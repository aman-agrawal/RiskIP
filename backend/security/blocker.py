"""
IP blocking / unblocking logic with database persistence.
"""
from datetime import datetime, timedelta, timezone
from database.connection import get_db
from config import (
    RATE_LIMIT_BLOCK_DURATION_MINUTES,
    LOGIN_BLOCK_DURATION_MINUTES,
    ENDPOINT_BLOCK_DURATION_MINUTES,
)


async def is_ip_blocked(ip: str) -> dict | None:
    """
    Check if an IP is currently blocked.
    Returns the block record if blocked, None otherwise.
    Auto-expires old blocks.
    """
    db = await get_db()
    try:
        now = datetime.now(timezone.utc).isoformat()
        # Expire old blocks
        await db.execute(
            "UPDATE ip_blocks SET is_active = 0 WHERE expires_at < ? AND is_active = 1",
            (now,),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT * FROM ip_blocks WHERE ip = ? AND is_active = 1 ORDER BY blocked_at DESC LIMIT 1",
            (ip,),
        )
        row = await cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        await db.close()


async def block_ip(ip: str, reason: str, duration_minutes: int = None, risk_score: float = 0):
    """Block an IP for a specified duration."""
    if duration_minutes is None:
        duration_minutes = RATE_LIMIT_BLOCK_DURATION_MINUTES

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=duration_minutes)

    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO ip_blocks (ip, reason, risk_score, blocked_at, expires_at, is_active)
               VALUES (?, ?, ?, ?, ?, 1)""",
            (ip, reason, risk_score, now.isoformat(), expires.isoformat()),
        )
        await db.commit()
        print(f"[BLOCKER] Blocked IP {ip} for {duration_minutes}m — reason: {reason}")
    finally:
        await db.close()


async def unblock_ip(ip: str) -> bool:
    """Manually unblock an IP."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE ip_blocks SET is_active = 0 WHERE ip = ? AND is_active = 1",
            (ip,),
        )
        await db.commit()
        unblocked = cursor.rowcount > 0
        if unblocked:
            print(f"[BLOCKER] Unblocked IP {ip}")
        return unblocked
    finally:
        await db.close()


async def add_warning(ip: str, reason: str, risk_score: float = 0):
    """Add a warning record for an IP."""
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO ip_warnings (ip, reason, risk_score) VALUES (?, ?, ?)",
            (ip, reason, risk_score),
        )
        await db.commit()
        print(f"[BLOCKER] Warning for IP {ip} — reason: {reason}")
    finally:
        await db.close()


async def log_request(ip: str, endpoint: str, method: str, status_code: int, user_agent: str = None):
    """Log a request to the database."""
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO ip_requests (ip, endpoint, method, status_code, user_agent) VALUES (?, ?, ?, ?, ?)",
            (ip, endpoint, method, status_code, user_agent),
        )
        await db.commit()
    finally:
        await db.close()


async def log_failed_login(ip: str, username: str):
    """Log a failed login attempt."""
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO failed_login_attempts (ip, username) VALUES (?, ?)",
            (ip, username),
        )
        await db.commit()
    finally:
        await db.close()


async def log_threat_event(ip: str, event_type: str, severity: str, details: str, risk_score: float = 0):
    """Log a threat event to the database."""
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO threat_events (ip, event_type, severity, details, risk_score) VALUES (?, ?, ?, ?, ?)",
            (ip, event_type, severity, details, risk_score),
        )
        await db.commit()
    finally:
        await db.close()


def get_block_duration(event_type: str) -> int:
    """Get the block duration in minutes based on event type."""
    if "login" in event_type:
        return LOGIN_BLOCK_DURATION_MINUTES
    elif "endpoint" in event_type:
        return ENDPOINT_BLOCK_DURATION_MINUTES
    else:
        return RATE_LIMIT_BLOCK_DURATION_MINUTES
