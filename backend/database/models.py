"""
Pydantic models for request/response schemas.
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


# ─── Auth ───────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: str


# ─── IP Records ─────────────────────────────────────────────

class IPBlockRecord(BaseModel):
    id: int
    ip: str
    reason: str
    risk_score: float
    blocked_at: str
    expires_at: str
    is_active: int


class IPWarningRecord(BaseModel):
    id: int
    ip: str
    reason: str
    risk_score: float
    warned_at: str


class FailedLoginRecord(BaseModel):
    id: int
    ip: str
    username: str
    attempted_at: str


class ThreatEventRecord(BaseModel):
    id: int
    ip: str
    event_type: str
    severity: str
    details: Optional[str]
    risk_score: float
    created_at: str


class IPRequestRecord(BaseModel):
    id: int
    ip: str
    endpoint: str
    method: str
    status_code: int
    timestamp: str


# ─── Dashboard ──────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_requests: int
    active_blocks: int
    total_warnings: int
    total_threat_events: int
    failed_logins: int
    unique_ips: int


class RiskScoreEntry(BaseModel):
    ip: str
    risk_score: float
    request_count: int
    failed_logins: int
    warnings: int
    is_blocked: bool


class IPDetail(BaseModel):
    ip: str
    total_requests: int
    failed_logins: int
    warnings: list
    blocks: list
    threat_events: list
    recent_requests: list
    risk_score: float
