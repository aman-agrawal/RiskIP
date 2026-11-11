"""
Threat detection engine — rule-based + behavioural analysis.
Computes per-IP risk scores and detects anomalies.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from config import (
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_WARN_THRESHOLD,
    RATE_LIMIT_BLOCK_THRESHOLD,
    LOGIN_WINDOW_SECONDS,
    LOGIN_WARN_THRESHOLD,
    LOGIN_BLOCK_THRESHOLD,
    ENDPOINT_WINDOW_SECONDS,
    ENDPOINT_404_WARN_THRESHOLD,
    ENDPOINT_404_BLOCK_THRESHOLD,
    RISK_WEIGHT_REQUEST_RATE,
    RISK_WEIGHT_FAILED_LOGINS,
    RISK_WEIGHT_UNUSUAL_ENDPOINTS,
    RISK_WEIGHT_404_RATE,
    RISK_SCORE_BLOCK_THRESHOLD,
    SENSITIVE_ENDPOINTS,
)


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    RATE_LIMIT_WARNING = "rate_limit_warning"
    RATE_LIMIT_BLOCK = "rate_limit_block"
    FAILED_LOGIN_WARNING = "failed_login_warning"
    FAILED_LOGIN_BLOCK = "failed_login_block"
    UNUSUAL_ENDPOINT_WARNING = "unusual_endpoint_warning"
    UNUSUAL_ENDPOINT_BLOCK = "unusual_endpoint_block"
    SENSITIVE_ENDPOINT_ACCESS = "sensitive_endpoint_access"
    HIGH_RISK_SCORE = "high_risk_score"


@dataclass
class ThreatEvent:
    ip: str
    event_type: EventType
    severity: ThreatLevel
    details: str
    risk_score: float
    timestamp: float = field(default_factory=time.time)


class ThreatDetector:
    """Rule-based + behavioral threat detection engine."""

    def __init__(self):
        # ip -> deque of failed login timestamps
        self._failed_logins: dict[str, deque] = defaultdict(deque)
        # ip -> deque of (timestamp, endpoint) for 404s
        self._404_requests: dict[str, deque] = defaultdict(deque)
        # ip -> set of unique endpoints accessed
        self._unique_endpoints: dict[str, deque] = defaultdict(deque)
        # ip -> deque of sensitive endpoint access timestamps
        self._sensitive_access: dict[str, deque] = defaultdict(deque)
        # ip -> last computed risk score
        self._risk_scores: dict[str, float] = defaultdict(float)

    def record_failed_login(self, ip: str, username: str) -> Optional[ThreatEvent]:
        """Record a failed login attempt and check thresholds."""
        now = time.time()
        window_start = now - LOGIN_WINDOW_SECONDS
        q = self._failed_logins[ip]
        q.append(now)

        # Evict old entries
        while q and q[0] < window_start:
            q.popleft()

        count = len(q)

        if count >= LOGIN_BLOCK_THRESHOLD:
            risk = self._compute_risk_score(ip)
            return ThreatEvent(
                ip=ip,
                event_type=EventType.FAILED_LOGIN_BLOCK,
                severity=ThreatLevel.CRITICAL,
                details=f"IP {ip} has {count} failed login attempts in {LOGIN_WINDOW_SECONDS}s (threshold: {LOGIN_BLOCK_THRESHOLD}). Username tried: {username}",
                risk_score=risk,
            )
        elif count >= LOGIN_WARN_THRESHOLD:
            risk = self._compute_risk_score(ip)
            return ThreatEvent(
                ip=ip,
                event_type=EventType.FAILED_LOGIN_WARNING,
                severity=ThreatLevel.HIGH,
                details=f"IP {ip} has {count} failed login attempts in {LOGIN_WINDOW_SECONDS}s (threshold: {LOGIN_WARN_THRESHOLD}). Username tried: {username}",
                risk_score=risk,
            )
        return None

    def record_404(self, ip: str, endpoint: str) -> Optional[ThreatEvent]:
        """Record a 404 response and check for scanning behavior."""
        now = time.time()
        window_start = now - ENDPOINT_WINDOW_SECONDS
        q = self._404_requests[ip]
        q.append((now, endpoint))

        # Evict old entries
        while q and q[0][0] < window_start:
            q.popleft()

        # Count unique endpoints that returned 404
        unique_404s = len(set(ep for _, ep in q))

        if unique_404s >= ENDPOINT_404_BLOCK_THRESHOLD:
            risk = self._compute_risk_score(ip)
            return ThreatEvent(
                ip=ip,
                event_type=EventType.UNUSUAL_ENDPOINT_BLOCK,
                severity=ThreatLevel.CRITICAL,
                details=f"IP {ip} hit {unique_404s} unique non-existent endpoints in {ENDPOINT_WINDOW_SECONDS}s — likely scanning. Latest: {endpoint}",
                risk_score=risk,
            )
        elif unique_404s >= ENDPOINT_404_WARN_THRESHOLD:
            risk = self._compute_risk_score(ip)
            return ThreatEvent(
                ip=ip,
                event_type=EventType.UNUSUAL_ENDPOINT_WARNING,
                severity=ThreatLevel.HIGH,
                details=f"IP {ip} hit {unique_404s} unique non-existent endpoints in {ENDPOINT_WINDOW_SECONDS}s. Latest: {endpoint}",
                risk_score=risk,
            )
        return None

    def record_sensitive_access(self, ip: str, endpoint: str) -> Optional[ThreatEvent]:
        """Record access to a sensitive endpoint."""
        now = time.time()
        window_start = now - ENDPOINT_WINDOW_SECONDS
        q = self._sensitive_access[ip]
        q.append(now)

        while q and q[0] < window_start:
            q.popleft()

        count = len(q)
        if count >= 3:
            risk = self._compute_risk_score(ip)
            return ThreatEvent(
                ip=ip,
                event_type=EventType.SENSITIVE_ENDPOINT_ACCESS,
                severity=ThreatLevel.HIGH,
                details=f"IP {ip} accessed sensitive endpoint '{endpoint}' {count} times in {ENDPOINT_WINDOW_SECONDS}s",
                risk_score=risk,
            )
        return None

    def check_endpoint(self, ip: str, endpoint: str) -> Optional[ThreatEvent]:
        """Check if the endpoint is sensitive."""
        endpoint_lower = endpoint.lower()
        for sensitive in SENSITIVE_ENDPOINTS:
            if sensitive in endpoint_lower:
                return self.record_sensitive_access(ip, endpoint)
        return None

    def get_failed_login_count(self, ip: str) -> int:
        """Get failed login count in current window."""
        now = time.time()
        window_start = now - LOGIN_WINDOW_SECONDS
        q = self._failed_logins[ip]
        while q and q[0] < window_start:
            q.popleft()
        return len(q)

    def get_404_count(self, ip: str) -> int:
        """Get 404 count in current window."""
        now = time.time()
        window_start = now - ENDPOINT_WINDOW_SECONDS
        q = self._404_requests[ip]
        while q and q[0][0] < window_start:
            q.popleft()
        return len(q)

    def _compute_risk_score(self, ip: str) -> float:
        """
        Compute a 0-100 risk score for an IP based on weighted factors.
        """
        from security.rate_limiter import rate_limiter

        # Factor 1: Request rate (normalized to threshold)
        request_count = rate_limiter.get_request_count(ip)
        rate_score = min(100, (request_count / RATE_LIMIT_BLOCK_THRESHOLD) * 100)

        # Factor 2: Failed logins (normalized to threshold)
        login_count = self.get_failed_login_count(ip)
        login_score = min(100, (login_count / LOGIN_BLOCK_THRESHOLD) * 100)

        # Factor 3: Unusual endpoint access
        now = time.time()
        window_start = now - ENDPOINT_WINDOW_SECONDS
        q_404 = self._404_requests[ip]
        while q_404 and q_404[0][0] < window_start:
            q_404.popleft()
        unique_404s = len(set(ep for _, ep in q_404))
        endpoint_score = min(100, (unique_404s / max(ENDPOINT_404_BLOCK_THRESHOLD, 1)) * 100)

        # Factor 4: 404 rate
        total_404s = len(q_404)
        rate_404_score = min(100, (total_404s / max(ENDPOINT_404_BLOCK_THRESHOLD, 1)) * 100)

        # Weighted sum
        risk_score = (
            rate_score * RISK_WEIGHT_REQUEST_RATE
            + login_score * RISK_WEIGHT_FAILED_LOGINS
            + endpoint_score * RISK_WEIGHT_UNUSUAL_ENDPOINTS
            + rate_404_score * RISK_WEIGHT_404_RATE
        )

        self._risk_scores[ip] = round(risk_score, 2)
        return self._risk_scores[ip]

    def get_risk_score(self, ip: str) -> float:
        """Get the last computed risk score for an IP."""
        return self._risk_scores.get(ip, 0.0)

    def compute_risk_score(self, ip: str) -> float:
        """Force recompute of risk score."""
        return self._compute_risk_score(ip)

    def should_auto_block(self, ip: str) -> bool:
        """Check if the IP risk score warrants an auto-block."""
        score = self._compute_risk_score(ip)
        return score >= RISK_SCORE_BLOCK_THRESHOLD

    def reset_ip(self, ip: str):
        """Clear all threat tracking state for a specific IP."""
        self._failed_logins.pop(ip, None)
        self._404_requests.pop(ip, None)
        self._unique_endpoints.pop(ip, None)
        self._sensitive_access.pop(ip, None)
        self._risk_scores.pop(ip, None)

    def reset_all(self):
        """Clear all threat tracking state across all IPs."""
        self._failed_logins.clear()
        self._404_requests.clear()
        self._unique_endpoints.clear()
        self._sensitive_access.clear()
        self._risk_scores.clear()


# Global singleton
threat_detector = ThreatDetector()
