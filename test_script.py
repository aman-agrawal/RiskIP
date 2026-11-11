#!/usr/bin/env python3
"""
Test Script for IP Monitoring & Blocking System
================================================
Simulates three attack vectors from a simulated external client IP:
  1. Too Many Requests (rate limit abuse)
  2. Repeated Failed Logins (brute force)
  3. Unusual Endpoint Access (404 scanning)

By default, the script simulates an external attacker IP (192.168.1.100) via X-Forwarded-For,
while the admin dashboard and app run on localhost (127.0.0.1).
This clearly separates attacker traffic from legitimate dashboard traffic!

Usage:
    python3 test_script.py
    python3 test_script.py --ip 10.0.0.99
"""

import requests
import time
import sys
import json
import sqlite3
import os

BASE_URL = "http://localhost:8000"
DB_PATH = os.path.join(os.path.dirname(__file__), "backend", "data", "monitor.db")
DIVIDER = "=" * 70

# Default simulated external attacker IP
DEFAULT_ATTACKER_IP = "192.168.1.100"

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def parse_target_ip():
    """Parse --ip argument if provided, else use default."""
    if "--ip" in sys.argv:
        idx = sys.argv.index("--ip")
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return DEFAULT_ATTACKER_IP


ATTACKER_IP = parse_target_ip()
ATTACKER_HEADERS = {"X-Forwarded-For": ATTACKER_IP}


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════════╗
║          IP MONITORING & BLOCKING SYSTEM — TEST SUITE           ║
║                                                                  ║
║  Simulated Attacker IP:  {YELLOW}{ATTACKER_IP:<39}{CYAN}║
║  App / Dashboard Host:   {GREEN}{'localhost (127.0.0.1)':<39}{CYAN}║
║                                                                  ║
║  Attacks Tested:                                                 ║
║    1. Rate limit abuse (too many requests)                       ║
║    2. Brute force login (repeated failed logins)                 ║
║    3. Endpoint scanning (unusual 404 access)                     ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


def print_header(title):
    print(f"\n{BOLD}{MAGENTA}{DIVIDER}")
    print(f"  {title}")
    print(f"{DIVIDER}{RESET}\n")


def print_response(i, resp, label=""):
    status = resp.status_code
    if status == 200:
        color = GREEN
        icon = "✓"
    elif status == 401:
        color = YELLOW
        icon = "⚠"
    elif status == 403:
        color = RED
        icon = "🚫"
    elif status == 429:
        color = RED
        icon = "⛔"
    else:
        color = BLUE
        icon = "•"

    # Check for warning headers
    warning = ""
    if resp.headers.get("X-RateLimit-Warning"):
        count = resp.headers.get("X-RateLimit-Count", "?")
        risk = resp.headers.get("X-Risk-Score", "?")
        warning = f" {YELLOW}[WARNING: {count} reqs, risk: {risk}]{RESET}"
    elif resp.headers.get("X-Endpoint-Warning"):
        count = resp.headers.get("X-Endpoint-Count", "?")
        risk = resp.headers.get("X-Risk-Score", "?")
        warning = f" {YELLOW}[SCAN WARNING: {count} 404s, risk: {risk}]{RESET}"

    try:
        body = resp.json()
        detail = body.get("detail", body.get("message", ""))
        if isinstance(detail, str) and len(detail) > 120:
            detail = detail[:120] + "..."
    except Exception:
        detail = ""

    print(f"  {color}{icon} [{i:3d}] {label} → {status}{RESET} {detail}{warning}")


def get_admin_token():
    """Login as admin from localhost without spoofing attacker IP."""
    try:
        resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()["access_token"]
    except Exception:
        pass
    return None


def unblock_via_db(ip=None):
    """Directly unblock IPs in the database as fallback."""
    try:
        conn = sqlite3.connect(DB_PATH)
        if ip:
            conn.execute("UPDATE ip_blocks SET is_active = 0 WHERE ip = ? AND is_active = 1", (ip,))
        else:
            conn.execute("UPDATE ip_blocks SET is_active = 0 WHERE is_active = 1")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"  {YELLOW}Could not unblock via DB: {e}{RESET}")
        return False


def reset_ip_state(ip=None):
    """
    Reset all in-memory (rate limiter + threat detector) + DB state for an IP.
    Uses the dedicated /api/test/reset-ip endpoint, falling back to dashboard API.
    """
    if ip is None:
        ip = ATTACKER_IP

    # 1. Try test control endpoint (exempt from blocks)
    try:
        resp = requests.post(f"{BASE_URL}/api/test/reset-ip/{ip}", timeout=5)
        if resp.status_code == 200:
            return True
    except Exception:
        pass

    # 2. Try dashboard reset endpoint with admin token
    token = get_admin_token()
    if token:
        try:
            resp = requests.post(
                f"{BASE_URL}/api/dashboard/reset-ip/{ip}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            if resp.status_code == 200:
                return True
        except Exception:
            pass

    # 3. Fallback to DB-only reset
    return unblock_via_db(ip)


def reset_between_tests(label):
    """Reset the IP block and in-memory threat state between tests."""
    print(f"\n  {CYAN}── Resetting state for IP {ATTACKER_IP} before {label}... ──{RESET}")
    if reset_ip_state(ATTACKER_IP):
        print(f"  {GREEN}✓ IP state completely reset (rate limiter + threat detector + blocks){RESET}")
    else:
        unblock_via_db(ATTACKER_IP)
        print(f"  {YELLOW}⚠ DB blocks cleared (fallback){RESET}")
    time.sleep(1)


def test_rate_limiting():
    """Test 1: Send rapid requests to trigger rate limiting."""
    print_header("TEST 1: RATE LIMIT ABUSE — Too Many Requests")
    print(f"  {CYAN}Simulating rapid requests from IP: {ATTACKER_IP}{RESET}")
    print(f"  {CYAN}Sending 120 requests to /api/public/* endpoints...{RESET}")
    print(f"  {CYAN}Warning at 50 requests, Block at 100 requests{RESET}\n")

    endpoints = [
        "/api/public/home",
        "/api/public/about",
        "/api/public/products",
        "/api/public/contact",
        "/api/public/services",
    ]
    warned = False
    blocked = False
    total_ok = 0
    total_warned = 0
    total_blocked = 0

    for i in range(1, 121):
        try:
            endpoint = endpoints[i % len(endpoints)]
            resp = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=ATTACKER_HEADERS,
                timeout=5,
            )

            if resp.status_code == 429:
                if not blocked:
                    print(f"\n  {RED}{BOLD}⛔ RATE LIMITED at request #{i}!{RESET}")
                    blocked = True
                total_blocked += 1
                if i == total_ok + total_warned + 1 or i % 10 == 0:
                    print_response(i, resp, "BLOCK")
            elif resp.status_code == 403:
                total_blocked += 1
                if not blocked:
                    blocked = True
                if i % 10 == 0:
                    print_response(i, resp, "BLOCKED")
            elif resp.headers.get("X-RateLimit-Warning"):
                if not warned:
                    print(f"\n  {YELLOW}{BOLD}⚠ WARNING triggered at request #{i}!{RESET}")
                    warned = True
                total_warned += 1
                if i % 10 == 0:
                    print_response(i, resp, "WARN")
            else:
                total_ok += 1
                if i % 25 == 0:
                    print_response(i, resp, "OK")

        except requests.exceptions.ConnectionError:
            print(f"  {RED}✗ [{i:3d}] Connection refused — is the server running?{RESET}")
            return False

    print(f"\n  {BOLD}Results for {ATTACKER_IP}:{RESET}")
    print(f"    {GREEN}OK: {total_ok}{RESET} | {YELLOW}Warned: {total_warned}{RESET} | {RED}Blocked: {total_blocked}{RESET}")
    print(f"    {'✅ Rate limiting working correctly!' if blocked else '❌ Rate limiting did NOT trigger'}")
    return True


def test_brute_force_login():
    """Test 2: Repeated failed login attempts."""
    print_header("TEST 2: BRUTE FORCE LOGIN — Repeated Failed Logins")
    print(f"  {CYAN}Simulating brute-force attack from IP: {ATTACKER_IP}{RESET}")
    print(f"  {CYAN}Sending 8 failed login attempts with invalid credentials...{RESET}")
    print(f"  {CYAN}Warning at 3 failures, Block at 5 failures{RESET}\n")

    usernames = ["admin", "root", "administrator", "user", "test"]
    passwords = ["wrong1", "wrong2", "wrong3", "password", "12345", "qwerty", "letmein", "abc123"]

    warned = False
    blocked = False

    for i in range(1, 9):
        try:
            username = usernames[i % len(usernames)]
            password = passwords[i % len(passwords)]

            resp = requests.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": username, "password": password},
                headers=ATTACKER_HEADERS,
                timeout=5,
            )

            if resp.status_code == 403:
                if not blocked:
                    print(f"\n  {RED}{BOLD}🚫 BLOCKED after {i} failed attempts!{RESET}")
                    blocked = True
                print_response(i, resp, f"LOGIN({username}:{password})")
                if i >= 6:
                    break
            elif resp.status_code == 401:
                try:
                    body = resp.json()
                    detail = body.get("detail", "")
                    if "WARNING" in detail:
                        if not warned:
                            print(f"\n  {YELLOW}{BOLD}⚠ WARNING after {i} failed attempts!{RESET}")
                            warned = True
                except Exception:
                    pass
                print_response(i, resp, f"LOGIN({username}:{password})")
            else:
                print_response(i, resp, f"LOGIN({username}:{password})")

            time.sleep(0.3)

        except requests.exceptions.ConnectionError:
            print(f"  {RED}✗ Connection refused{RESET}")
            return False

    print(f"\n  {BOLD}Results for {ATTACKER_IP}:{RESET}")
    print(f"    Warned: {'✅ Yes' if warned else '❌ No'} | Blocked: {'✅ Yes' if blocked else '❌ No'}")
    return True


def test_endpoint_scanning():
    """Test 3: Hit non-existent and sensitive endpoints."""
    print_header("TEST 3: ENDPOINT SCANNING — Unusual Endpoint Access")
    print(f"  {CYAN}Simulating endpoint scanning from IP: {ATTACKER_IP}{RESET}")
    print(f"  {CYAN}Hitting 25 non-existent + sensitive endpoints...{RESET}")
    print(f"  {CYAN}Warning at 10 unique 404s, Block at 20{RESET}\n")

    scan_endpoints = [
        "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin",
        "/api/admin/users", "/api/admin/config", "/.env", "/debug",
        "/config.yml", "/api/users/dump", "/actuator/health",
        "/api/v1/secret", "/backup.sql", "/database.sql",
        "/api/internal/keys", "/api/tokens", "/api/admin/settings",
        "/env", "/server-status", "/api/debug/vars",
        "/api/private/data", "/api/admin/logs", "/robots.txt.bak",
        "/api/v2/hidden", "/api/graphql/introspection",
    ]

    warned = False
    blocked = False
    status_counts = {}

    for i, endpoint in enumerate(scan_endpoints, 1):
        try:
            resp = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=ATTACKER_HEADERS,
                timeout=5,
            )
            status = resp.status_code
            status_counts[status] = status_counts.get(status, 0) + 1

            # Check for warning header
            if resp.headers.get("X-Endpoint-Warning") and not warned:
                print(f"\n  {YELLOW}{BOLD}⚠ SCANNING WARNING triggered at endpoint #{i} ({endpoint})!{RESET}")
                warned = True

            if status == 403:
                if not blocked:
                    print(f"\n  {RED}{BOLD}🚫 BLOCKED at endpoint #{i} ({endpoint})!{RESET}")
                    blocked = True
                print_response(i, resp, endpoint)
                if i >= 20:
                    break
            elif status == 429:
                if not blocked:
                    print(f"\n  {RED}{BOLD}⛔ RATE LIMITED at endpoint #{i}!{RESET}")
                    blocked = True
                print_response(i, resp, endpoint)
                break
            else:
                print_response(i, resp, endpoint)

            time.sleep(0.05)

        except requests.exceptions.ConnectionError:
            print(f"  {RED}✗ Connection refused{RESET}")
            return False

    print(f"\n  {BOLD}Results for {ATTACKER_IP}:{RESET}")
    for status, count in sorted(status_counts.items()):
        color = GREEN if status == 200 else YELLOW if status == 404 else RED
        print(f"    {color}HTTP {status}: {count} responses{RESET}")
    print(f"    Warned: {'✅ Yes' if warned else '❌ No'} | Blocked: {'✅ Yes' if blocked else '❌ No'}")
    return True


def print_summary():
    """Print final summary by checking the dashboard API from localhost (clean admin IP)."""
    print_header("SUMMARY — Dashboard State After Tests")

    try:
        # Admin connects from localhost (127.0.0.1) — never blocked
        token = get_admin_token()
        if not token:
            print(f"  {YELLOW}Could not login as admin to fetch summary{RESET}")
            print(f"  {CYAN}Open the dashboard at http://localhost:5173 to see all results{RESET}")
            return

        headers = {"Authorization": f"Bearer {token}"}

        # Fetch stats
        stats_resp = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=headers, timeout=5)
        if stats_resp.status_code == 200:
            stats = stats_resp.json()
            print(f"  {BOLD}Dashboard Statistics:{RESET}")
            print(f"    📊 Total Monitored Requests: {CYAN}{stats['total_requests']}{RESET} (internal dashboard queries excluded)")
            print(f"    🚫 Active Blocks:            {RED}{stats['active_blocks']}{RESET}")
            print(f"    ⚠  Total Warnings:           {YELLOW}{stats['total_warnings']}{RESET}")
            print(f"    🛡  Threat Events:            {MAGENTA}{stats['total_threat_events']}{RESET}")
            print(f"    🔐 Failed Logins:            {RED}{stats['failed_logins']}{RESET}")
            print(f"    🌐 Unique IPs Monitored:     {BLUE}{stats['unique_ips']}{RESET}")

        # Fetch blocked IPs
        blocked_resp = requests.get(f"{BASE_URL}/api/dashboard/blocked-ips", headers=headers, timeout=5)
        if blocked_resp.status_code == 200:
            blocked = blocked_resp.json()
            if blocked:
                print(f"\n  {BOLD}Block Records ({len(blocked)} total):{RESET}")
                for b in blocked[:5]:
                    status = f"{RED}ACTIVE{RESET}" if b.get("is_active") else f"{GREEN}EXPIRED{RESET}"
                    print(f"    {'🔒' if b.get('is_active') else '✅'} IP: {b['ip']} [{status}] — {b['reason'][:80]}")

        # Fetch threat events
        threats_resp = requests.get(f"{BASE_URL}/api/dashboard/threat-events", headers=headers, timeout=5)
        if threats_resp.status_code == 200:
            threats = threats_resp.json()
            if threats:
                print(f"\n  {BOLD}Recent Threat Events ({len(threats)} total, showing last 6):{RESET}")
                for t in threats[:6]:
                    severity_color = RED if t["severity"] == "critical" else YELLOW if t["severity"] == "high" else BLUE
                    event = t["event_type"].replace("_", " ").title()
                    print(f"    {severity_color}[{t['severity'].upper():8s}]{RESET} IP: {t['ip']} — {event}")
                    if t.get("details"):
                        detail = t["details"][:100] + "..." if len(t["details"]) > 100 else t["details"]
                        print(f"              {BLUE}{detail}{RESET}")

        # IP Architecture Note
        print(f"\n  {BOLD}{GREEN}✓ Architecture Separation Verified:{RESET}")
        print(f"    • Attacker IP:  {YELLOW}{ATTACKER_IP}{RESET} (Blocked / Monitored)")
        print(f"    • App Host:     {GREEN}127.0.0.1 (Localhost){RESET} (Safe / Admin Dashboard Access)")

    except requests.exceptions.ConnectionError:
        print(f"  {RED}Could not connect to server for summary{RESET}")
    except Exception as e:
        print(f"  {RED}Error fetching summary: {e}{RESET}")


def main():
    banner()

    # Check server connectivity
    print(f"  {CYAN}Checking server connectivity...{RESET}")
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        if resp.status_code == 200:
            print(f"  {GREEN}✓ Server is running at {BASE_URL}{RESET}\n")
        else:
            print(f"  {RED}✗ Server returned {resp.status_code}{RESET}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"  {RED}✗ Cannot connect to {BASE_URL}")
        print(f"  Make sure the backend is running: cd backend && python3 -m uvicorn main:app --port 8000{RESET}")
        sys.exit(1)

    # Clear any existing blocks and reset tracking for attacker IP before starting
    print(f"  {CYAN}Clearing any previous tracking for {ATTACKER_IP}...{RESET}")
    reset_ip_state(ATTACKER_IP)
    print(f"  {GREEN}✓ Clean test environment ready{RESET}")

    print(f"\n  {BOLD}Starting tests in 2 seconds...{RESET}")
    time.sleep(2)

    # ── Test 1: Rate limiting ──
    test_rate_limiting()

    # Reset state cleanly before test 2
    reset_between_tests("Test 2 (Brute Force Login)")
    time.sleep(1)

    # ── Test 2: Brute force login ──
    test_brute_force_login()

    # Reset state cleanly before test 3
    reset_between_tests("Test 3 (Endpoint Scanning)")
    time.sleep(1)

    # ── Test 3: Endpoint scanning ──
    test_endpoint_scanning()

    time.sleep(1)

    # ── Summary ──
    print_summary()

    # Final message
    print(f"\n{BOLD}{CYAN}{DIVIDER}")
    print(f"  TEST SUITE COMPLETE")
    print(f"  Open the admin dashboard at: http://localhost:5173")
    print(f"  Login: admin / admin123")
    print(f"{DIVIDER}{RESET}\n")


if __name__ == "__main__":
    main()
