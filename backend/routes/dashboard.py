"""
Admin dashboard API routes — protected by JWT.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from routes.auth import verify_token
from security.ip_utils import get_client_ip
from database.connection import get_db
from database.models import DashboardStats, IPBlockRecord, IPWarningRecord, ThreatEventRecord
from security.blocker import unblock_ip
from security.threat_detector import threat_detector
from security.rate_limiter import rate_limiter

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


async def verify_admin_or_localhost(request: Request) -> dict:
    """Allow valid JWT token, or automatically authorize requests from localhost."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            return verify_token(token)
        except Exception:
            pass

    # Localhost exception for admin presenter convenience
    client_ip = get_client_ip(request)
    if client_ip in ("127.0.0.1", "localhost", "::1") or (
        request.client and request.client.host in ("127.0.0.1", "localhost", "::1")
    ):
        return {"sub": "admin", "role": "admin"}

    raise HTTPException(status_code=401, detail="Authentication required")


@router.get("/stats")
async def get_stats(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get dashboard summary statistics."""
    db = await get_db()
    try:
        # Total requests
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM ip_requests")
        total_requests = (await cursor.fetchone())["cnt"]

        # Active blocks
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM ip_blocks WHERE is_active = 1"
        )
        active_blocks = (await cursor.fetchone())["cnt"]

        # Total warnings
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM ip_warnings")
        total_warnings = (await cursor.fetchone())["cnt"]

        # Total threat events
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM threat_events")
        total_threats = (await cursor.fetchone())["cnt"]

        # Failed logins
        cursor = await db.execute("SELECT COUNT(*) as cnt FROM failed_login_attempts")
        failed_logins = (await cursor.fetchone())["cnt"]

        # Unique IPs
        cursor = await db.execute("SELECT COUNT(DISTINCT ip) as cnt FROM ip_requests")
        unique_ips = (await cursor.fetchone())["cnt"]

        return {
            "total_requests": total_requests,
            "active_blocks": active_blocks,
            "total_warnings": total_warnings,
            "total_threat_events": total_threats,
            "failed_logins": failed_logins,
            "unique_ips": unique_ips,
        }
    finally:
        await db.close()


@router.get("/blocked-ips")
async def get_blocked_ips(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get all blocked IPs (active and expired)."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ip_blocks ORDER BY blocked_at DESC LIMIT 100"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/warned-ips")
async def get_warned_ips(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get all warned IPs."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM ip_warnings ORDER BY warned_at DESC LIMIT 100"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/failed-logins")
async def get_failed_logins(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get failed login attempts, grouped by IP."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT ip, username, COUNT(*) as attempt_count, 
                      MIN(attempted_at) as first_attempt, 
                      MAX(attempted_at) as last_attempt
               FROM failed_login_attempts 
               GROUP BY ip, username 
               ORDER BY attempt_count DESC 
               LIMIT 100"""
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/threat-events")
async def get_threat_events(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get all threat events."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM threat_events ORDER BY created_at DESC LIMIT 200"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/risk-scores")
async def get_risk_scores(current_user: dict = Depends(verify_admin_or_localhost)):
    """Get per-IP risk scores based on recent activity."""
    db = await get_db()
    try:
        # Get all unique IPs with activity
        cursor = await db.execute(
            """SELECT DISTINCT ip FROM (
                   SELECT ip FROM ip_requests
                   UNION
                   SELECT ip FROM failed_login_attempts
                   UNION
                   SELECT ip FROM ip_warnings
                   UNION
                   SELECT ip FROM ip_blocks
               ) ORDER BY ip"""
        )
        ips = [row["ip"] for row in await cursor.fetchall()]

        results = []
        for ip in ips:
            # Request count
            cursor = await db.execute(
                "SELECT COUNT(*) as cnt FROM ip_requests WHERE ip = ?", (ip,)
            )
            req_count = (await cursor.fetchone())["cnt"]

            # Failed logins
            cursor = await db.execute(
                "SELECT COUNT(*) as cnt FROM failed_login_attempts WHERE ip = ?", (ip,)
            )
            login_count = (await cursor.fetchone())["cnt"]

            # Warnings
            cursor = await db.execute(
                "SELECT COUNT(*) as cnt FROM ip_warnings WHERE ip = ?", (ip,)
            )
            warn_count = (await cursor.fetchone())["cnt"]

            # Is blocked
            cursor = await db.execute(
                "SELECT COUNT(*) as cnt FROM ip_blocks WHERE ip = ? AND is_active = 1", (ip,)
            )
            is_blocked = (await cursor.fetchone())["cnt"] > 0

            # Compute risk score
            risk = threat_detector.compute_risk_score(ip)

            results.append({
                "ip": ip,
                "risk_score": risk,
                "request_count": req_count,
                "failed_logins": login_count,
                "warnings": warn_count,
                "is_blocked": is_blocked,
            })

        # Sort by risk score descending
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results
    finally:
        await db.close()


@router.post("/unblock/{ip}")
async def unblock_ip_route(ip: str, current_user: dict = Depends(verify_admin_or_localhost)):
    """Manually unblock an IP address and clear in-memory tracking."""
    rate_limiter.reset_ip(ip)
    threat_detector.reset_ip(ip)
    success = await unblock_ip(ip)
    if success:
        return {"message": f"IP {ip} has been unblocked and tracking reset", "ip": ip}
    return {"message": f"IP {ip} tracking state reset", "ip": ip}


@router.get("/ip-details/{ip}")
async def get_ip_details(ip: str, current_user: dict = Depends(verify_admin_or_localhost)):
    """Get detailed information about a specific IP."""
    db = await get_db()
    try:
        # Total requests
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM ip_requests WHERE ip = ?", (ip,)
        )
        total_requests = (await cursor.fetchone())["cnt"]

        # Failed logins
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM failed_login_attempts WHERE ip = ?", (ip,)
        )
        failed_logins = (await cursor.fetchone())["cnt"]

        # Warnings
        cursor = await db.execute(
            "SELECT * FROM ip_warnings WHERE ip = ? ORDER BY warned_at DESC LIMIT 50", (ip,)
        )
        warnings = [dict(r) for r in await cursor.fetchall()]

        # Blocks
        cursor = await db.execute(
            "SELECT * FROM ip_blocks WHERE ip = ? ORDER BY blocked_at DESC LIMIT 50", (ip,)
        )
        blocks = [dict(r) for r in await cursor.fetchall()]

        # Threat events
        cursor = await db.execute(
            "SELECT * FROM threat_events WHERE ip = ? ORDER BY created_at DESC LIMIT 50", (ip,)
        )
        threats = [dict(r) for r in await cursor.fetchall()]

        # Recent requests
        cursor = await db.execute(
            "SELECT * FROM ip_requests WHERE ip = ? ORDER BY timestamp DESC LIMIT 20", (ip,)
        )
        recent = [dict(r) for r in await cursor.fetchall()]

        risk = threat_detector.compute_risk_score(ip)

        return {
            "ip": ip,
            "total_requests": total_requests,
            "failed_logins": failed_logins,
            "warnings": warnings,
            "blocks": blocks,
            "threat_events": threats,
            "recent_requests": recent,
            "risk_score": risk,
        }
    finally:
        await db.close()


@router.post("/reset-ip/{ip}")
async def reset_ip_state(ip: str, current_user: dict = Depends(verify_admin_or_localhost)):
    """Reset all in-memory tracking and DB block for an IP."""
    rate_limiter.reset_ip(ip)
    threat_detector.reset_ip(ip)
    await unblock_ip(ip)
    return {"message": f"All state reset for IP {ip}", "ip": ip}


@router.post("/reset-all")
async def reset_all_state(current_user: dict = Depends(verify_admin_or_localhost)):
    """Reset all in-memory tracking and unblock all IPs in DB."""
    rate_limiter.reset_all()
    threat_detector.reset_all()
    db = await get_db()
    try:
        await db.execute("UPDATE ip_blocks SET is_active = 0 WHERE is_active = 1")
        await db.commit()
    finally:
        await db.close()
    return {"message": "All active blocks and in-memory tracking have been reset"}


@router.post("/clear-data")
async def clear_data_state(current_user: dict = Depends(verify_admin_or_localhost)):
    """Wipe historical request and threat logs for a fresh presentation."""
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
    return {"message": "All monitoring data has been wiped clean"}
