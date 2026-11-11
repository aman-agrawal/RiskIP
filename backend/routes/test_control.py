"""
Test control routes — provides endpoints for automated test scripts and presentation demos.
Exempt from IP blocks so tests and presenters can reset state cleanly at any time.
"""
from fastapi import APIRouter
from database.connection import get_db
from security.blocker import unblock_ip
from security.threat_detector import threat_detector
from security.rate_limiter import rate_limiter

router = APIRouter(prefix="/api/test", tags=["test-control"])


@router.post("/reset-ip/{ip}")
async def reset_ip_state(ip: str):
    """
    Reset all in-memory tracking and active DB blocks for a specific IP.
    Called between tests in the test suite to ensure clean, isolated results.
    """
    rate_limiter.reset_ip(ip)
    threat_detector.reset_ip(ip)
    await unblock_ip(ip)
    return {
        "status": "success",
        "message": f"State reset for IP {ip} (rate limiter, threat detector, and active blocks cleared)",
        "ip": ip,
    }


@router.post("/reset-all")
async def reset_all_state():
    """
    Reset all in-memory tracking and active DB blocks across all IPs.
    """
    rate_limiter.reset_all()
    threat_detector.reset_all()
    db = await get_db()
    try:
        await db.execute("UPDATE ip_blocks SET is_active = 0 WHERE is_active = 1")
        await db.commit()
    finally:
        await db.close()

    return {
        "status": "success",
        "message": "All active blocks and in-memory tracking cleared for all IPs",
    }


@router.post("/clear-data")
async def clear_all_test_data():
    """
    Completely wipe historical test logs (requests, warnings, blocks, failed logins, threat events)
    and reset in-memory state. Ideal for starting a fresh presentation or demo.
    """
    rate_limiter.reset_all()
    threat_detector.reset_all()
    db = await get_db()
    try:
        await db.execute("DELETE FROM ip_requests")
        await db.execute("DELETE FROM ip_warnings")
        await db.execute("DELETE FROM ip_blocks")
        await db.execute("DELETE FROM failed_login_attempts")
        await db.execute("DELETE FROM threat_events")
        await db.commit()
    finally:
        await db.close()

    return {
        "status": "success",
        "message": "All historical test logs and tracking state wiped clean",
    }


@router.get("/status")
async def test_status():
    """Check test system readiness."""
    return {"status": "ready", "module": "test-control"}
