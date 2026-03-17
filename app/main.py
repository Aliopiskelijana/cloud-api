import logging
import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.middleware.usage_tracker import UsageTrackerMiddleware
from app.routes import auth, api_keys, usage, protected

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


def _setup_db():
    """Run in background thread — does not block app startup or health check."""
    try:
        from app.database import init_db, get_engine, Base
        init_db()
        Base.metadata.create_all(bind=get_engine())
        logger.info("Database tables ready")
    except Exception as e:
        logger.error("DB setup failed: %s", e)


# Start DB setup in background — app is ready to serve /health immediately
threading.Thread(target=_setup_db, daemon=True).start()

app = FastAPI(
    title="Cloud API Monitor",
    description="API key management with usage tracking and rate limiting",
    version="1.0.0",
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
