# Cloud API Monitor

A production-ready API key management system with usage tracking and rate limiting.

## Features

- JWT authentication (signup / login)
- API key generation and revocation
- Per-key and per-IP rate limiting (Redis)
- Automatic usage logging for every request
- Usage dashboard with stats and top endpoints
- Structured logging
- Docker support

## Tech Stack

| Layer    | Tech                        |
|----------|-----------------------------|
| Backend  | FastAPI (Python 3.12)       |
| Database | PostgreSQL (Neon free tier) |
| Cache    | Redis (Upstash free tier)   |
| Deploy   | Render / Railway            |

## Quick Start (local)

```bash
# 1. Clone and install
pip install -r requirements.txt

# 2. Set environment variables
cp .env.example .env
# Edit .env with your DB and Redis URLs

# 3. Run
uvicorn app.main:app --reload
```

Open [http://localhost:8000/docs](http://localhost:8000/docs)

## Quick Start (Docker)

```bash
docker-compose up --build
```

## Deploy to Render (free)

1. Push to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect your repo — `render.yaml` handles everything

Environment variables to set manually:
- `REDIS_URL` — get a free instance from [Upstash](https://upstash.com)

## Deploy to Railway (free)

```bash
railway login
railway init
railway up
```

Set `DATABASE_URL` and `REDIS_URL` in Railway dashboard.

## API Reference

### Auth
| Method | Endpoint       | Description  |
|--------|----------------|--------------|
| POST   | /auth/signup   | Register     |
| POST   | /auth/login    | Get JWT token|

### API Keys
| Method | Endpoint       | Auth  | Description     |
|--------|----------------|-------|-----------------|
| POST   | /keys/         | JWT   | Create key      |
| GET    | /keys/         | JWT   | List keys       |
| DELETE | /keys/{id}     | JWT   | Revoke key      |

### Protected Endpoints
| Method | Endpoint        | Auth      | Description  |
|--------|-----------------|-----------|--------------|
| GET    | /api/v1/data    | X-API-Key | Sample data  |
| GET    | /api/v1/status  | X-API-Key | Status check |

### Usage
| Method | Endpoint            | Auth | Description      |
|--------|---------------------|------|------------------|
| GET    | /usage/{key_id}     | JWT  | Usage summary    |
| GET    | /usage/{key_id}/logs| JWT  | Raw request logs |

## Rate Limiting

- 60 requests / 60 seconds per API key or IP
- Returns `429 Too Many Requests` with `Retry-After` header

## Run Tests

```bash
pytest tests/ -v
```

## Architecture

```
Request → UsageTrackerMiddleware → Router → Handler
                                       ↓
                                  RateLimit (Redis)
                                       ↓
                                  DB (PostgreSQL)
```
