"""
Authentication routes — login, register, current user.
"""
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, Request
from passlib.context import CryptContext
from database.connection import get_db
from database.models import LoginRequest, LoginResponse, UserResponse
from security.threat_detector import threat_detector, EventType
from security.blocker import log_failed_login, log_threat_event, block_ip, add_warning, is_ip_blocked
from security.ip_utils import get_client_ip
from config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES,
    LOGIN_BLOCK_DURATION_MINUTES,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_token(data: dict) -> str:
    """Create a JWT token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(request: Request) -> dict:
    """Dependency: extract and verify the current user from JWT."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    return payload


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, body: LoginRequest):
    """Authenticate a user and return a JWT token."""
    ip = get_client_ip(request)

    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", (body.username,)
        )
        user = await cursor.fetchone()

        # Legitimate login check — admin can always log in to administer system
        if user and pwd_context.verify(body.password, user["password_hash"]):
            token = create_token({"sub": user["username"], "role": user["role"], "id": user["id"]})
            return LoginResponse(
                access_token=token,
                username=user["username"],
                role=user["role"],
            )

        # Credentials are invalid. Check if IP is already blocked
        block = await is_ip_blocked(ip)
        if block:
            raise HTTPException(
                status_code=403,
                detail=f"Your IP ({ip}) is blocked until {block['expires_at']}. Reason: {block['reason']}",
            )

        # Log failed login
        await log_failed_login(ip, body.username)

        # Check with threat detector
        event = threat_detector.record_failed_login(ip, body.username)

        if event:
            await log_threat_event(
                ip=ip,
                event_type=event.event_type.value,
                severity=event.severity.value,
                details=event.details,
                risk_score=event.risk_score,
            )

            if event.event_type == EventType.FAILED_LOGIN_BLOCK:
                await block_ip(
                    ip=ip,
                    reason=f"Too many failed login attempts ({threat_detector.get_failed_login_count(ip)} in window)",
                    duration_minutes=LOGIN_BLOCK_DURATION_MINUTES,
                    risk_score=event.risk_score,
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"IP blocked due to too many failed login attempts. Blocked for {LOGIN_BLOCK_DURATION_MINUTES} minutes.",
                )
            elif event.event_type == EventType.FAILED_LOGIN_WARNING:
                await add_warning(
                    ip=ip,
                    reason=event.details,
                    risk_score=event.risk_score,
                )
                raise HTTPException(
                    status_code=401,
                    detail=f"WARNING: Invalid credentials. You have {threat_detector.get_failed_login_count(ip)} failed attempts. Your IP will be blocked after {5} failed attempts.",
                )

        raise HTTPException(status_code=401, detail="Invalid username or password")
    finally:
        await db.close()


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get the current authenticated user."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", (current_user["sub"],)
        )
        user = await cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return UserResponse(
            id=user["id"],
            username=user["username"],
            role=user["role"],
            created_at=str(user["created_at"]),
        )
    finally:
        await db.close()
