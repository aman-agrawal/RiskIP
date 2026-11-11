"""
Central configuration for the IP Monitoring & Blocking System.
All thresholds are tunable here.
"""
import os

# ─── Database ───────────────────────────────────────────────
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "data", "monitor.db")

# ─── JWT ────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-in-prod-2024")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

# ─── Rate Limiting ──────────────────────────────────────────
RATE_LIMIT_WINDOW_SECONDS = 60          # Time window for counting requests
RATE_LIMIT_WARN_THRESHOLD = 50          # Requests in window → WARNING
RATE_LIMIT_BLOCK_THRESHOLD = 100        # Requests in window → BLOCK
RATE_LIMIT_BLOCK_DURATION_MINUTES = 15  # How long to block

# ─── Failed Login ───────────────────────────────────────────
LOGIN_WINDOW_SECONDS = 300              # Time window for counting failures
LOGIN_WARN_THRESHOLD = 3                # Failed logins → WARNING
LOGIN_BLOCK_THRESHOLD = 5               # Failed logins → BLOCK
LOGIN_BLOCK_DURATION_MINUTES = 30       # How long to block

# ─── Unusual Endpoint Access ────────────────────────────────
ENDPOINT_WINDOW_SECONDS = 60            # Time window
ENDPOINT_404_WARN_THRESHOLD = 10        # Unique 404s → WARNING
ENDPOINT_404_BLOCK_THRESHOLD = 20       # Unique 404s → BLOCK
ENDPOINT_BLOCK_DURATION_MINUTES = 15

# ─── Risk Scoring Weights (must sum to 1.0) ─────────────────
RISK_WEIGHT_REQUEST_RATE = 0.30
RISK_WEIGHT_FAILED_LOGINS = 0.30
RISK_WEIGHT_UNUSUAL_ENDPOINTS = 0.20
RISK_WEIGHT_404_RATE = 0.20

RISK_SCORE_BLOCK_THRESHOLD = 80         # Auto-block at this score

# ─── Sensitive Endpoints (accessing these raises risk) ──────
SENSITIVE_ENDPOINTS = [
    "/api/admin",
    "/api/dashboard",
    "/admin",
    "/debug",
    "/env",
    "/.env",
    "/config",
    "/api/users",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login",
    "/actuator",
]

# ─── CORS ───────────────────────────────────────────────────
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

# ─── Default Admin ──────────────────────────────────────────
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"
