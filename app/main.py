import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.middleware.usage_tracker import UsageTrackerMiddleware
from app.routes import auth, api_keys, usage, protected

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Cloud API Monitor",
    description="API key management with usage tracking and rate limiting",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(UsageTrackerMiddleware)

app.include_router(auth.router)
app.include_router(api_keys.router)
app.include_router(usage.router)
app.include_router(protected.router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}
