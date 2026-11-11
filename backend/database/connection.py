"""
SQLite async database connection and initialization.
"""
import aiosqlite
import os
from config import DATABASE_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER DEFAULT 200,
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ip_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score REAL DEFAULT 0,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ip_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    risk_score REAL DEFAULT 0,
    warned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    details TEXT,
    risk_score REAL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_requests_ip ON ip_requests(ip);
CREATE INDEX IF NOT EXISTS idx_ip_requests_timestamp ON ip_requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_blocks_ip ON ip_blocks(ip);
CREATE INDEX IF NOT EXISTS idx_ip_blocks_active ON ip_blocks(is_active);
CREATE INDEX IF NOT EXISTS idx_failed_login_ip ON failed_login_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_threat_events_ip ON threat_events(ip);
CREATE INDEX IF NOT EXISTS idx_threat_events_created ON threat_events(created_at);
"""


async def get_db() -> aiosqlite.Connection:
    """Get a database connection."""
    db = await aiosqlite.connect(DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Initialize the database schema."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    db = await get_db()
    try:
        await db.executescript(SCHEMA)
        await db.commit()
    finally:
        await db.close()


async def seed_admin(username: str, password_hash: str):
    """Seed the default admin user if not exists."""
    db = await get_db()
    try:
        existing = await db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        )
        if not await existing.fetchone():
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, "admin"),
            )
            await db.commit()
            print(f"[DB] Seeded admin user: {username}")
        else:
            print(f"[DB] Admin user '{username}' already exists")
    finally:
        await db.close()
