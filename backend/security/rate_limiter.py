"""
Sliding-window rate limiter using in-memory counters.
Each IP gets a deque of timestamps; we count how many fall within the window.
"""
import time
from collections import defaultdict, deque
from enum import Enum
from config import (
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_WARN_THRESHOLD,
    RATE_LIMIT_BLOCK_THRESHOLD,
)


class RateLimitStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"
    BLOCKED = "blocked"


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self):
        # ip -> deque of timestamps
        self._requests: dict[str, deque] = defaultdict(deque)

    def record_request(self, ip: str) -> RateLimitStatus:
        """Record a request and return the current status for this IP."""
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        q = self._requests[ip]

        # Add current request
        q.append(now)

        # Evict old entries outside the window
        while q and q[0] < window_start:
            q.popleft()

        count = len(q)

        if count >= RATE_LIMIT_BLOCK_THRESHOLD:
            return RateLimitStatus.BLOCKED
        elif count >= RATE_LIMIT_WARN_THRESHOLD:
            return RateLimitStatus.WARNING
        return RateLimitStatus.OK

    def get_request_count(self, ip: str) -> int:
        """Get the number of requests in the current window for an IP."""
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        q = self._requests[ip]

        while q and q[0] < window_start:
            q.popleft()

        return len(q)

    def get_request_rate(self, ip: str) -> float:
        """Get requests per second for an IP in the current window."""
        count = self.get_request_count(ip)
        if count == 0:
            return 0.0
        return count / RATE_LIMIT_WINDOW_SECONDS

    def reset_ip(self, ip: str):
        """Clear all recorded requests for an IP."""
        if ip in self._requests:
            del self._requests[ip]

    def reset_all(self):
        """Clear all recorded requests."""
        self._requests.clear()

    def cleanup(self):
        """Remove IPs with no recent activity."""
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        empty_ips = []
        for ip, q in self._requests.items():
            while q and q[0] < window_start:
                q.popleft()
            if not q:
                empty_ips.append(ip)
        for ip in empty_ips:
            del self._requests[ip]


# Global singleton
rate_limiter = RateLimiter()
