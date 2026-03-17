import os
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"status": "ok", "service": "Cloud API Monitor", "db": os.environ.get("DATABASE_URL", "not set")[:20]}
