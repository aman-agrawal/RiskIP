"""
IP Monitoring & Blocking System — FastAPI Application
Main entry point with middleware for request logging, rate limiting, and threat detection.
"""
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from passlib.context import CryptContext

from config import CORS_ORIGINS, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD
from database.connection import init_db, seed_admin
from security.rate_limiter import rate_limiter, RateLimitStatus
from security.threat_detector import threat_detector, EventType
from security.blocker import (
    is_ip_blocked,
    block_ip,
    add_warning,
    log_request,
    log_threat_event,
)
from config import RATE_LIMIT_BLOCK_DURATION_MINUTES, ENDPOINT_BLOCK_DURATION_MINUTES

from routes.auth import router as auth_router
from routes.dashboard import router as dashboard_router
from routes.public import router as public_router
from routes.test_control import router as test_router
from security.ip_utils import get_client_ip

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    print("=" * 60)
    print("  IP Monitoring & Blocking System")
    print("  Starting up...")
    print("=" * 60)

    # Initialize database
    await init_db()
    print("[STARTUP] Database initialized")

    # Seed default admin
    admin_hash = pwd_context.hash(DEFAULT_ADMIN_PASSWORD)
    await seed_admin(DEFAULT_ADMIN_USERNAME, admin_hash)
    print(f"[STARTUP] Admin user ready: {DEFAULT_ADMIN_USERNAME}/{DEFAULT_ADMIN_PASSWORD}")

    print("[STARTUP] Server ready!")
    print("=" * 60)

    yield

    print("[SHUTDOWN] Server shutting down...")


app = FastAPI(
    title="IP Monitor",
    description="IP-based monitoring and blocking system with threat detection",
    version="1.0.0",
    lifespan=lifespan,
)

# ─── CORS ───────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Middleware: Request Logging + Rate Limiting + Threat Detection ───
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Core security middleware pipeline:
    1. Check if IP is blocked
    2. Rate limit check
    3. Threat detection (sensitive endpoint, 404 scanning)
    4. Log the request
    """
    ip = get_client_ip(request)
    endpoint = request.url.path
    method = request.method
    user_agent = request.headers.get("user-agent", "unknown")

    # Skip middleware for docs, dashboard (JWT-protected), test-control, and health endpoints.
    # CRITICAL: Do NOT log these internal/monitoring queries into ip_requests table!
    # This prevents the request counter from continuously increasing due to frontend polling.
    EXEMPT_PREFIXES = (
        "/docs",
        "/openapi.json",
        "/redoc",
        "/favicon.ico",
        "/api/dashboard",
        "/api/test",
        "/health",
        "/api/auth/me",
    )
    if any(endpoint.startswith(prefix) for prefix in EXEMPT_PREFIXES):
        return await call_next(request)

    # ── Step 1: Check if IP is already blocked ──
    block = await is_ip_blocked(ip)
    if block:
        return JSONResponse(
            status_code=403,
            content={
                "detail": f"Your IP ({ip}) is blocked until {block['expires_at']}. Reason: {block['reason']}",
                "blocked": True,
                "expires_at": block["expires_at"],
            },
        )

    # ── Step 2: Rate limiting ──
    rl_status = rate_limiter.record_request(ip)

    if rl_status == RateLimitStatus.BLOCKED:
        risk = threat_detector.compute_risk_score(ip)
        await log_threat_event(
            ip=ip,
            event_type=EventType.RATE_LIMIT_BLOCK.value,
            severity="critical",
            details=f"IP {ip} exceeded rate limit ({rate_limiter.get_request_count(ip)} requests in window). Endpoint: {endpoint}",
            risk_score=risk,
        )
        await block_ip(
            ip=ip,
            reason=f"Rate limit exceeded ({rate_limiter.get_request_count(ip)} requests in window)",
            duration_minutes=RATE_LIMIT_BLOCK_DURATION_MINUTES,
            risk_score=risk,
        )
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Too many requests. Your IP ({ip}) has been blocked for {RATE_LIMIT_BLOCK_DURATION_MINUTES} minutes.",
                "blocked": True,
                "risk_score": risk,
            },
        )
    elif rl_status == RateLimitStatus.WARNING:
        risk = threat_detector.compute_risk_score(ip)
        await log_threat_event(
            ip=ip,
            event_type=EventType.RATE_LIMIT_WARNING.value,
            severity="high",
            details=f"IP {ip} approaching rate limit ({rate_limiter.get_request_count(ip)} requests in window). Endpoint: {endpoint}",
            risk_score=risk,
        )
        await add_warning(
            ip=ip,
            reason=f"Approaching rate limit ({rate_limiter.get_request_count(ip)} requests in window)",
            risk_score=risk,
        )

    # ── Step 3: Check for sensitive endpoint access ──
    endpoint_event = threat_detector.check_endpoint(ip, endpoint)
    if endpoint_event:
        await log_threat_event(
            ip=ip,
            event_type=endpoint_event.event_type.value,
            severity=endpoint_event.severity.value,
            details=endpoint_event.details,
            risk_score=endpoint_event.risk_score,
        )

    # ── Step 4: Process the request ──
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time

    # Add warning header if applicable
    if rl_status == RateLimitStatus.WARNING:
        response.headers["X-RateLimit-Warning"] = "true"
        response.headers["X-RateLimit-Count"] = str(rate_limiter.get_request_count(ip))
        response.headers["X-Risk-Score"] = str(threat_detector.get_risk_score(ip))

    # ── Step 5: Check for 404 scanning ──
    if response.status_code == 404:
        event_404 = threat_detector.record_404(ip, endpoint)
        if event_404:
            await log_threat_event(
                ip=ip,
                event_type=event_404.event_type.value,
                severity=event_404.severity.value,
                details=event_404.details,
                risk_score=event_404.risk_score,
            )
            if "block" in event_404.event_type.value:
                scan_count = threat_detector.get_404_count(ip)
                reason_msg = f"Unusual endpoint scanning ({scan_count} 404s in window)"
                await block_ip(
                    ip=ip,
                    reason=reason_msg,
                    duration_minutes=ENDPOINT_BLOCK_DURATION_MINUTES,
                    risk_score=event_404.risk_score,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": f"Your IP ({ip}) has been blocked for {ENDPOINT_BLOCK_DURATION_MINUTES} minutes. Reason: {reason_msg}",
                        "blocked": True,
                        "risk_score": event_404.risk_score,
                    },
                )
            elif "warning" in event_404.event_type.value:
                scan_count = threat_detector.get_404_count(ip)
                reason_msg = f"Unusual endpoint scanning ({scan_count} 404s in window)"
                await add_warning(
                    ip=ip,
                    reason=reason_msg,
                    risk_score=event_404.risk_score,
                )
                response.headers["X-Endpoint-Warning"] = "true"
                response.headers["X-Endpoint-Count"] = str(scan_count)
                response.headers["X-Risk-Score"] = str(event_404.risk_score)

    # ── Step 6: Auto-block on high risk score ──
    if threat_detector.should_auto_block(ip):
        existing_block = await is_ip_blocked(ip)
        if not existing_block:
            risk = threat_detector.get_risk_score(ip)
            await log_threat_event(
                ip=ip,
                event_type=EventType.HIGH_RISK_SCORE.value,
                severity="critical",
                details=f"IP {ip} auto-blocked due to high risk score: {risk}",
                risk_score=risk,
            )
            await block_ip(
                ip=ip,
                reason=f"High risk score: {risk}",
                duration_minutes=RATE_LIMIT_BLOCK_DURATION_MINUTES,
                risk_score=risk,
            )

    # ── Step 7: Log the request ──
    await log_request(ip, endpoint, method, response.status_code, user_agent)

    # Add processing time header
    response.headers["X-Process-Time"] = str(round(process_time, 4))

    return response


# ─── Include Routers ────────────────────────────────────────
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(public_router)
app.include_router(test_router)


@app.get("/")
async def root():
    return {
        "app": "IP Monitoring & Blocking System",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
