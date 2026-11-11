"""
IP extraction utility — extracts client IP with support for reverse proxies and simulated IPs.
"""
from fastapi import Request


def get_client_ip(request: Request) -> str:
    """
    Extract the client IP from the request.
    Supports X-Forwarded-For and X-Real-IP headers (e.g. from reverse proxy or test script).
    Falls back to request.client.host, and defaults to 127.0.0.1.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can be a comma-separated list of IPs; first is the original client
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        client_ip = real_ip.strip()
        if client_ip:
            return client_ip

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"
