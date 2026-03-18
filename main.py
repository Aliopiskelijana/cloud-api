"""
Cloud API Monitor — Vercel serverless entry point.
Storage: Upstash Redis (already configured via REDIS_URL env var).
Auth: JWT via python-jose + bcrypt.
"""
import logging
import os
import secrets as _sec
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────────────────────
REDIS_URL    = os.environ.get("REDIS_URL", "")
SECRET_KEY   = os.environ.get("SECRET_KEY", "changeme")
ALGORITHM    = os.environ.get("ALGORITHM", "HS256")
TOKEN_EXPIRE = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# ── Redis client (lazy) ───────────────────────────────────────────────────────
_redis = None


def get_redis():
    global _redis
    if _redis is None:
        import redis as _r
        _redis = _r.from_url(REDIS_URL, decode_responses=True)
    return _redis


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().isoformat()


def _user_by_email(email: str) -> Optional[dict]:
    r = get_redis()
    uid = r.get(f"user_email:{email}")
    if not uid:
        return None
    return r.hgetall(f"user:{uid}") or None


def _user_by_id(uid) -> Optional[dict]:
    r = get_redis()
    return r.hgetall(f"user:{uid}") or None


def _create_user(email: str, hashed_pw: str) -> dict:
    r = get_redis()
    uid = r.incr("counter:user")
    data = {
        "id": str(uid),
        "email": email,
        "hashed_password": hashed_pw,
        "is_active": "1",
        "created_at": _now(),
    }
    r.hset(f"user:{uid}", mapping=data)
    r.set(f"user_email:{email}", uid)
    return data


def _create_apikey(name: str, user_id: str) -> dict:
    r = get_redis()
    kid = r.incr("counter:apikey")
    key = f"sk_{_sec.token_urlsafe(32)}"
    data = {
        "id": str(kid),
        "key": key,
        "name": name,
        "user_id": user_id,
        "is_active": "1",
        "created_at": _now(),
    }
    r.hset(f"apikey:{kid}", mapping=data)
    r.set(f"apikey_key:{key}", kid)
    r.sadd(f"user_apikeys:{user_id}", kid)
    return data


def _get_apikeys(user_id: str) -> list[dict]:
    r = get_redis()
    ids = r.smembers(f"user_apikeys:{user_id}")
    keys = []
    for kid in ids:
        d = r.hgetall(f"apikey:{kid}")
        if d:
            keys.append(d)
    return sorted(keys, key=lambda x: x.get("created_at", ""))


def _get_apikey_by_value(key: str) -> Optional[dict]:
    r = get_redis()
    kid = r.get(f"apikey_key:{key}")
    if not kid:
        return None
    return r.hgetall(f"apikey:{kid}") or None


def _get_apikey_by_id(kid, user_id: str) -> Optional[dict]:
    r = get_redis()
    d = r.hgetall(f"apikey:{kid}")
    if d and d.get("user_id") == user_id:
        return d
    return None


def _revoke_apikey(kid: str, user_id: str) -> bool:
    r = get_redis()
    d = r.hgetall(f"apikey:{kid}")
    if not d or d.get("user_id") != user_id:
        return False
    r.hset(f"apikey:{kid}", "is_active", "0")
    return True


def _log_usage(user_id: str, endpoint: str, method: str,
               status_code: int, response_ms: int, ip: str):
    import json as _json
    r = get_redis()
    entry = _json.dumps({
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "response_time_ms": response_ms,
        "timestamp": _now(),
    })
    r.lpush(f"usage:{user_id}", entry)
    r.hincrby(f"usage_ep:{user_id}", endpoint, 1)


def _get_usage(user_id: str) -> dict:
    import json as _json
    r = get_redis()
    raw = r.lrange(f"usage:{user_id}", 0, -1)
    total = len(raw)
    eps = {k: int(v) for k, v in (r.hgetall(f"usage_ep:{user_id}") or {}).items()}
    return {"total_requests": total, "endpoints": eps}


# ── Auth helpers ─────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    import bcrypt
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    from jose import jwt
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=TOKEN_EXPIRE))
    to_encode["exp"] = expire
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    from jose import JWTError, jwt
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., min_length=6, example="secret123")


class UserOut(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class APIKeyCreate(BaseModel):
    name: str = Field(..., example="production")


class APIKeyOut(BaseModel):
    id: int
    key: str
    name: str
    is_active: bool
    created_at: datetime


class UsageOut(BaseModel):
    total_requests: int
    endpoints: dict


class DemoOut(BaseModel):
    message: str
    email: str
    password: str
    access_token: str
    api_key: str
    try_it: dict


# ── Helpers to convert Redis dicts to schema types ────────────────────────────

def _to_user_out(d: dict) -> UserOut:
    return UserOut(
        id=int(d["id"]),
        email=d["email"],
        is_active=d.get("is_active", "1") == "1",
        created_at=datetime.fromisoformat(d["created_at"]),
    )


def _to_apikey_out(d: dict) -> APIKeyOut:
    return APIKeyOut(
        id=int(d["id"]),
        key=d["key"],
        name=d["name"],
        is_active=d.get("is_active", "1") == "1",
        created_at=datetime.fromisoformat(d["created_at"]),
    )


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        r = get_redis()
        r.ping()
        logger.info("Redis connection OK")
    except Exception as e:
        logger.error("Redis connection failed: %s", e)
    yield


app = FastAPI(
    title="Cloud API Monitor",
    description="API key management with JWT authentication and usage tracking.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    user = _user_by_email(payload.get("sub", ""))
    if not user or user.get("is_active") != "1":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


# ── Demo ──────────────────────────────────────────────────────────────────────

@app.post("/demo", response_model=DemoOut, tags=["demo"],
          summary="Instant demo credentials — no signup needed")
def demo(request: Request):
    import uuid
    email    = f"demo-{uuid.uuid4().hex[:8]}@cloudapi.dev"
    password = "demo1234"
    if _user_by_email(email):
        raise HTTPException(400, "Try again")
    user = _create_user(email, hash_password(password))
    key  = _create_apikey("demo-key", user["id"])
    token = create_access_token({"sub": email})
    base  = str(request.base_url).rstrip("/")
    return DemoOut(
        message="Demo account ready.",
        email=email,
        password=password,
        access_token=token,
        api_key=key["key"],
        try_it={
            "list_keys":     f'curl {base}/api-keys -H "Authorization: Bearer {token}"',
            "hit_protected": f'curl {base}/protected -H "X-API-Key: {key["key"]}"',
            "usage_stats":   f'curl {base}/usage -H "Authorization: Bearer {token}"',
        },
    )


# ── Frontend UI ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui():
    return HTMLResponse(content=_HTML)


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/auth/signup", response_model=UserOut, status_code=201, tags=["auth"])
def signup(payload: UserCreate):
    if _user_by_email(payload.email):
        raise HTTPException(400, "Email already registered")
    user = _create_user(payload.email, hash_password(payload.password))
    return _to_user_out(user)


@app.post("/auth/login", response_model=Token, tags=["auth"])
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = _user_by_email(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return {"access_token": create_access_token({"sub": user["email"]}), "token_type": "bearer"}


# ── API Keys ──────────────────────────────────────────────────────────────────

@app.post("/api-keys", response_model=APIKeyOut, status_code=201, tags=["api-keys"])
def create_key(payload: APIKeyCreate, current_user: dict = Depends(get_current_user)):
    key = _create_apikey(payload.name, current_user["id"])
    return _to_apikey_out(key)


@app.get("/api-keys", response_model=list[APIKeyOut], tags=["api-keys"])
def list_keys(current_user: dict = Depends(get_current_user)):
    return [_to_apikey_out(k) for k in _get_apikeys(current_user["id"])]


@app.delete("/api-keys/{key_id}", status_code=204, tags=["api-keys"])
def revoke_key(key_id: int, current_user: dict = Depends(get_current_user)):
    if not _revoke_apikey(str(key_id), current_user["id"]):
        raise HTTPException(404, "Key not found")


# ── Usage ─────────────────────────────────────────────────────────────────────

@app.get("/usage", response_model=UsageOut, tags=["usage"])
def usage_summary(current_user: dict = Depends(get_current_user)):
    return _get_usage(current_user["id"])


# ── Protected ─────────────────────────────────────────────────────────────────

@app.get("/protected", tags=["protected"],
         summary="Protected endpoint — requires X-API-Key header")
def protected_route(request: Request):
    import time
    start = time.monotonic()
    hdr = request.headers.get("X-API-Key")
    if not hdr:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "X-API-Key header required")
    key_rec = _get_apikey_by_value(hdr)
    if not key_rec or key_rec.get("is_active") != "1":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or inactive API key")
    ms = int((time.monotonic() - start) * 1000)
    _log_usage(key_rec["user_id"], "/protected", "GET", 200, ms,
               request.client.host if request.client else "unknown")
    return {"message": "Access granted", "key_name": key_rec["name"]}


# ── HTML UI ───────────────────────────────────────────────────────────────────
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud API Monitor</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  a{color:#7c6aff;text-decoration:none}
  #auth-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
  #dashboard{display:none;max-width:900px;margin:0 auto;padding:2rem 1rem}
  .card{background:#1a1d27;border:1px solid #2a2d3e;border-radius:12px;padding:2rem}
  .tabs{display:flex;gap:.5rem;margin-bottom:1.5rem}
  .tab{flex:1;padding:.6rem;background:#12141e;border:1px solid #2a2d3e;border-radius:8px;cursor:pointer;font-size:.9rem;color:#94a3b8;transition:.15s}
  .tab.active{background:#7c6aff;border-color:#7c6aff;color:#fff}
  .form-group{margin-bottom:1rem}
  label{display:block;font-size:.8rem;color:#94a3b8;margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.05em}
  input{width:100%;padding:.65rem .9rem;background:#12141e;border:1px solid #2a2d3e;border-radius:8px;color:#e2e8f0;font-size:.95rem;outline:none;transition:.15s}
  input:focus{border-color:#7c6aff}
  .btn{width:100%;padding:.7rem;background:#7c6aff;border:none;border-radius:8px;color:#fff;font-size:.95rem;font-weight:600;cursor:pointer;transition:.15s}
  .btn:hover{background:#6b5cef}
  .btn-sm{width:auto;padding:.4rem .9rem;font-size:.8rem;border-radius:6px}
  .btn-danger{background:#ef4444}.btn-danger:hover{background:#dc2626}
  .btn-outline{background:transparent;border:1px solid #7c6aff;color:#7c6aff}.btn-outline:hover{background:#7c6aff;color:#fff}
  nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #2a2d3e}
  nav h1{font-size:1.2rem;font-weight:700;color:#7c6aff}
  .section-title{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#64748b;margin-bottom:1rem}
  .key-row{display:flex;align-items:center;gap:.75rem;padding:.85rem;background:#12141e;border:1px solid #2a2d3e;border-radius:8px;margin-bottom:.6rem}
  .key-name{font-weight:600;font-size:.9rem;flex:1}
  .key-val{font-family:monospace;font-size:.75rem;color:#64748b;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .badge{padding:.2rem .6rem;border-radius:99px;font-size:.7rem;font-weight:600;background:#16a34a22;color:#4ade80;border:1px solid #4ade8033}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:1.5rem}
  .stat-card{background:#12141e;border:1px solid #2a2d3e;border-radius:8px;padding:1.2rem;text-align:center}
  .stat-num{font-size:2rem;font-weight:700;color:#7c6aff}
  .stat-label{font-size:.75rem;color:#64748b;margin-top:.3rem}
  .alert{padding:.75rem 1rem;border-radius:8px;font-size:.85rem;margin-bottom:1rem}
  .alert-err{background:#ef444422;border:1px solid #ef444455;color:#fca5a5}
  .alert-ok{background:#16a34a22;border:1px solid #16a34a55;color:#86efac}
  .create-row{display:flex;gap:.6rem;margin-bottom:1.5rem}
  .create-row input{flex:1}
  .create-row .btn{width:auto;padding:.65rem 1.2rem}
  .copy-btn{background:none;border:none;color:#7c6aff;cursor:pointer;font-size:.75rem;padding:0 .3rem}
  .copy-btn:hover{color:#a08cff}
</style>
</head>
<body>

<div id="auth-screen">
  <div class="card" style="width:100%;max-width:420px">
    <h2 style="margin-bottom:.3rem;font-size:1.4rem">Cloud API Monitor</h2>
    <p style="font-size:.82rem;color:#64748b;margin-bottom:1.5rem">API key management · JWT auth · usage tracking</p>

    <div style="background:#7c6aff18;border:1px solid #7c6aff44;border-radius:10px;padding:1rem;margin-bottom:1.25rem">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:.75rem">
        <div>
          <div style="font-size:.85rem;font-weight:600;margin-bottom:.2rem">Try instantly</div>
          <div style="font-size:.78rem;color:#94a3b8">No signup — get a live key in one click</div>
        </div>
        <button id="demo-btn" class="btn btn-sm" style="white-space:nowrap;min-width:90px" onclick="tryDemo()">⚡ Demo</button>
      </div>
      <div id="demo-creds" style="display:none;margin-top:.9rem;padding-top:.9rem;border-top:1px solid #7c6aff33">
        <div style="font-size:.75rem;color:#94a3b8;margin-bottom:.5rem;text-transform:uppercase;letter-spacing:.05em">Your demo credentials</div>
        <div id="demo-info" style="font-size:.8rem;line-height:1.8"></div>
      </div>
    </div>

    <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1.25rem">
      <div style="flex:1;height:1px;background:#2a2d3e"></div>
      <span style="font-size:.75rem;color:#475569">or sign in</span>
      <div style="flex:1;height:1px;background:#2a2d3e"></div>
    </div>

    <div class="tabs">
      <button class="tab active" onclick="switchTab('login')">Login</button>
      <button class="tab" onclick="switchTab('signup')">Sign Up</button>
    </div>
    <div id="auth-msg"></div>
    <div class="form-group">
      <label>Email</label>
      <input id="auth-email" type="email" placeholder="you@example.com" autocomplete="email">
    </div>
    <div class="form-group">
      <label>Password</label>
      <input id="auth-pass" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')doAuth()">
    </div>
    <button class="btn" onclick="doAuth()">Continue</button>
    <p style="margin-top:1rem;font-size:.8rem;color:#64748b;text-align:center"><a href="/docs" target="_blank">API docs ↗</a></p>
  </div>
</div>

<div id="dashboard">
  <nav>
    <h1>⚡ Cloud API Monitor</h1>
    <div style="display:flex;align-items:center;gap:1rem">
      <span id="nav-email" style="font-size:.85rem;color:#64748b"></span>
      <button class="btn btn-outline btn-sm" onclick="logout()">Logout</button>
    </div>
  </nav>
  <div id="stats-wrap"></div>
  <div class="card" style="margin-bottom:1.5rem" id="try-card">
    <p class="section-title">Test a protected request</p>
    <p style="font-size:.82rem;color:#64748b;margin-bottom:1rem">Pick a key and send a real request to <code style="background:#12141e;padding:.1rem .4rem;border-radius:4px;font-size:.8rem">/protected</code></p>
    <div style="display:flex;gap:.6rem;align-items:center">
      <select id="test-key-select" style="flex:1;padding:.65rem .9rem;background:#12141e;border:1px solid #2a2d3e;border-radius:8px;color:#e2e8f0;font-size:.85rem;outline:none"></select>
      <button class="btn btn-sm btn-outline" onclick="testProtected()">Send →</button>
    </div>
    <div id="test-result" style="margin-top:.75rem;font-size:.82rem;font-family:monospace;color:#86efac;display:none"></div>
  </div>
  <div class="card">
    <p class="section-title">API Keys</p>
    <div class="create-row">
      <input id="new-key-name" placeholder="Key name (e.g. production)" onkeydown="if(event.key==='Enter')createKey()">
      <button class="btn btn-sm" onclick="createKey()">+ Create</button>
    </div>
    <div id="key-msg"></div>
    <div id="keys-list"><p style="color:#64748b;font-size:.9rem">Loading…</p></div>
  </div>
</div>

<script>
const BASE = '';
let TOKEN = localStorage.getItem('cam_token') || '';
let USER  = localStorage.getItem('cam_user')  || '';
let activeTab = 'login';

function switchTab(t) {
  activeTab = t;
  document.querySelectorAll('.tab').forEach((el,i)=>el.classList.toggle('active',(i===0&&t==='login')||(i===1&&t==='signup')));
  setMsg('auth-msg','','');
}
function setMsg(id,type,text){
  const el=document.getElementById(id);
  el.innerHTML=text?`<div class="alert alert-${type}">${text}</div>`:'';
}
async function doAuth(){
  const email=document.getElementById('auth-email').value.trim();
  const pass=document.getElementById('auth-pass').value;
  if(!email||!pass) return setMsg('auth-msg','err','Email and password required.');
  if(activeTab==='signup'){
    const r=await fetch(`${BASE}/auth/signup`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pass})});
    if(!r.ok){const d=await r.json();return setMsg('auth-msg','err',d.detail||'Signup failed');}
    setMsg('auth-msg','ok','Account created! Logging in…');
    activeTab='login';
  }
  const fd=new URLSearchParams({username:email,password:pass});
  const r2=await fetch(`${BASE}/auth/login`,{method:'POST',body:fd});
  if(!r2.ok){const d=await r2.json();return setMsg('auth-msg','err',d.detail||'Login failed');}
  const data=await r2.json();
  TOKEN=data.access_token; USER=email;
  localStorage.setItem('cam_token',TOKEN); localStorage.setItem('cam_user',USER);
  showDashboard();
}
function logout(){
  TOKEN=''; USER='';
  localStorage.removeItem('cam_token'); localStorage.removeItem('cam_user');
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('dashboard').style.display='none';
  document.getElementById('auth-email').value='';
  document.getElementById('auth-pass').value='';
}
function authHeaders(){return{Authorization:`Bearer ${TOKEN}`};}
async function showDashboard(){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('dashboard').style.display='block';
  document.getElementById('nav-email').textContent=USER;
  await Promise.all([loadKeys(),loadUsage()]);
}
async function loadUsage(){
  const r=await fetch(`${BASE}/usage`,{headers:authHeaders()});
  if(!r.ok) return;
  const d=await r.json();
  const eps=Object.entries(d.endpoints||{}).map(([k,v])=>`<div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid #2a2d3e"><span style="color:#94a3b8;font-size:.85rem">${k}</span><span style="font-weight:600">${v}</span></div>`).join('');
  document.getElementById('stats-wrap').innerHTML=`
    <div class="stats-grid" style="margin-bottom:1.5rem">
      <div class="stat-card"><div class="stat-num">${d.total_requests}</div><div class="stat-label">Total Requests</div></div>
      <div class="stat-card"><div class="stat-num">${Object.keys(d.endpoints||{}).length}</div><div class="stat-label">Endpoints Hit</div></div>
    </div>
    ${eps?'<div class="card" style="margin-bottom:1.5rem"><p class="section-title">Endpoint Breakdown</p>'+eps+'</div>':''}`;
}
async function loadKeys(){
  const r=await fetch(`${BASE}/api-keys`,{headers:authHeaders()});
  if(!r.ok){if(r.status===401)logout();return;}
  const keys=await r.json();
  const el=document.getElementById('keys-list');
  const sel=document.getElementById('test-key-select');
  sel.innerHTML=keys.filter(k=>k.is_active).map(k=>`<option value="${k.key}">${k.name} — ${k.key.slice(0,18)}…</option>`).join('');
  if(!keys.length){el.innerHTML='<p style="color:#64748b;font-size:.9rem">No keys yet. Create one above.</p>';return;}
  el.innerHTML=keys.map(k=>`
    <div class="key-row">
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:.5rem">
          <span class="key-name">${k.name}</span>
          <span class="badge">active</span>
        </div>
        <div style="display:flex;align-items:center;gap:.2rem;margin-top:.3rem">
          <span class="key-val" id="kv-${k.id}">${k.key}</span>
          <button class="copy-btn" onclick="copyKey('${k.key}','${k.id}')" title="Copy">⧉</button>
        </div>
      </div>
      <button class="btn btn-danger btn-sm" onclick="revokeKey(${k.id})">Revoke</button>
    </div>`).join('');
}
function copyKey(val,id){
  navigator.clipboard.writeText(val);
  const btn=event.target; btn.textContent='✓';
  setTimeout(()=>btn.textContent='⧉',1500);
}
async function createKey(){
  const name=document.getElementById('new-key-name').value.trim();
  if(!name) return;
  const r=await fetch(`${BASE}/api-keys`,{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(!r.ok){const d=await r.json();return setMsg('key-msg','err',d.detail||'Failed');}
  document.getElementById('new-key-name').value='';
  setMsg('key-msg','ok','Key created!');
  setTimeout(()=>setMsg('key-msg','',''),2500);
  await loadKeys();
}
async function revokeKey(id){
  if(!confirm('Revoke this key?')) return;
  await fetch(`${BASE}/api-keys/${id}`,{method:'DELETE',headers:authHeaders()});
  await loadKeys();
}
async function tryDemo(){
  const btn=document.getElementById('demo-btn');
  btn.textContent='…'; btn.disabled=true;
  const r=await fetch(`${BASE}/demo`,{method:'POST'});
  btn.disabled=false;
  if(!r.ok){btn.textContent='⚡ Demo';alert('Demo failed — please try again.');return;}
  const d=await r.json();
  TOKEN=d.access_token; USER=d.email;
  localStorage.setItem('cam_token',TOKEN); localStorage.setItem('cam_user',USER);
  const box=document.getElementById('demo-creds');
  const info=document.getElementById('demo-info');
  box.style.display='block';
  info.innerHTML=`
    <div style="display:flex;justify-content:space-between;margin-bottom:.25rem">
      <span style="color:#64748b">Email</span><span style="color:#e2e8f0">${d.email}</span>
    </div>
    <div style="display:flex;justify-content:space-between;margin-bottom:.25rem">
      <span style="color:#64748b">Password</span><span style="color:#e2e8f0">${d.password}</span>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:#64748b">API Key</span>
      <div style="display:flex;align-items:center;gap:.3rem">
        <span style="color:#a08cff;font-family:monospace;font-size:.75rem">${d.api_key.slice(0,20)}…</span>
        <button class="copy-btn" onclick="navigator.clipboard.writeText('${d.api_key}');this.textContent='✓';setTimeout(()=>this.textContent='⧉',1500)">⧉</button>
      </div>
    </div>`;
  btn.textContent='✓ Ready';
  setTimeout(()=>showDashboard(),600);
}
async function testProtected(){
  const sel=document.getElementById('test-key-select');
  const key=sel.value;
  if(!key) return;
  const r=await fetch(`${BASE}/protected`,{headers:{'X-API-Key':key}});
  const d=await r.json();
  const el=document.getElementById('test-result');
  el.style.display='block';
  el.style.color=r.ok?'#86efac':'#fca5a5';
  el.textContent=JSON.stringify(d);
  await loadUsage();
}
if(TOKEN) showDashboard();
</script>
</body>
</html>"""
