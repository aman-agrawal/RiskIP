# IP Monitoring & Blocking System

A full-stack security monitoring platform that detects, warns, and blocks malicious IP activity — including rate-limit abuse, brute-force login attempts, and unusual endpoint access. Features real-time admin dashboard with risk scoring.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React (Vite) |
| Backend | Python + FastAPI |
| Database | SQLite (async) |
| Auth | JWT |
| Detection | Rule-based + Behavioral analysis |

## Quick Start

### 1. Setup

```bash
# Install all dependencies
./setup.sh

# Or manually:
cd backend && pip3 install -r requirements.txt
cd ../frontend && npm install
```

### 2. Start Backend (Terminal 1)

```bash
cd backend
python3 -m uvicorn main:app --reload --port 8000
```

### 3. Start Frontend (Terminal 2)

```bash
cd frontend
npm run dev
```

### 4. Run Test Script (Terminal 3)

```bash
python3 test_script.py
```

### 5. Open Dashboard

- **URL**: http://localhost:5173
- **Login**: `admin` / `admin123`

## Features

### Security Detection
- **Rate Limiting**: Warning at 50 req/min, block at 100 req/min
- **Failed Login Protection**: Warning at 3 failures, block at 5 failures
- **Endpoint Scanning Detection**: Detects 404 scanning & sensitive endpoint access
- **Risk Scoring**: Weighted 0-100 score per IP (auto-block at 80+)

### Admin Dashboard
- Real-time stats (auto-refresh every 5s)
- Blocked IPs with unblock capability
- Warning history
- Failed login tracking
- Threat event feed
- Per-IP risk scores

### Test Script
Simulates three attack vectors:
1. **Rate Limit Abuse**: 120 rapid requests
2. **Brute Force Login**: 8 failed login attempts
3. **Endpoint Scanning**: 25 non-existent/sensitive endpoint hits

## Configuration

All thresholds are configurable in `backend/config.py`:

| Setting | Default |
|---------|---------|
| Rate limit warning | 50 req / 60s |
| Rate limit block | 100 req / 60s |
| Failed login warning | 3 / 300s |
| Failed login block | 5 / 300s |
| Endpoint 404 warning | 10 unique / 60s |
| Risk score auto-block | ≥ 80 |

## Project Structure

```
├── backend/
│   ├── main.py              # FastAPI app + middleware
│   ├── config.py             # All configurable thresholds
│   ├── database/
│   │   ├── connection.py     # SQLite async connection
│   │   └── models.py         # Pydantic models
│   ├── security/
│   │   ├── rate_limiter.py   # Sliding window rate limiter
│   │   ├── threat_detector.py # Rule-based + behavioral detection
│   │   └── blocker.py        # IP block/unblock/logging
│   └── routes/
│       ├── auth.py           # JWT login/auth
│       ├── dashboard.py      # Admin dashboard API
│       └── public.py         # Public test endpoints
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Login.jsx     # Login page
│       │   └── Dashboard.jsx # Admin dashboard
│       ├── services/api.js   # Axios API client
│       └── context/AuthContext.jsx
├── test_script.py            # Attack simulation script
├── setup.sh                  # One-command setup
└── README.md
```
