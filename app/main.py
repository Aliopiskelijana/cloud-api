import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.middleware.usage_tracker import UsageTrackerMiddleware
from app.routes import auth, api_keys, usage, protected

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise DB at startup — works in both serverless and long-running environments."""
    try:
        from app.database import init_db
        init_db()
        logger.info("Database ready")
    except Exception as e:
        logger.error("DB setup failed: %s", e)
    yield


app = FastAPI(
    title="Cloud API Monitor",
    description="API key management with usage tracking and rate limiting",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(UsageTrackerMiddleware)

app.include_router(auth.router)
app.include_router(api_keys.router)
app.include_router(usage.router)
app.include_router(protected.router)


@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "service": "Cloud API Monitor"}


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
