# AmIDataBroke — SOC-lite Security Log Analysis Platform

A real, working AI-assisted security log triage tool. Nothing here is mocked —
every button calls a live backend endpoint that does exactly what it claims.

## What's new in this build

| # | Feature | How it's real |
|---|---------|----------------|
| 1 | **Live Threat Intelligence Lookup** | Backend calls the real **AbuseIPDB** API (`/threat-intel/{ip}`) and returns the actual abuse score, country, ISP, and report count for any IP. Requires your own free API key (see setup below) — this is a genuine live external call, not a hardcoded response. |
| 2 | **Raw Log Parser** | `/parse-raw-log` uses real regex/JSON parsing to break down messy Apache/Nginx access logs, JSON blobs (CloudWatch/Windows-Event style), or generic syslog text into clean fields (IP, timestamp, user, method, path, payload). |
| 3 | **PDF Forensic Report Generator** | `/logs/{id}/report` uses **ReportLab** to render a real PDF on the fly from the log's actual stored data — no template screenshots, an actual generated PDF document downloads to your machine. |
| 4 | **CSV / JSON Bulk Export** | `/logs/export/csv` and `/logs/export/json` stream your actual current database contents as a downloadable file. |
| 5 | **Compliance Audit Trail** | Every status change, single-log purge, and "Clear All" writes a real row to a new `audit_logs` SQLite table, including the acting user's email (sent via the `X-User-Email` header) and timestamp. Displayed live at the bottom of the dashboard. |
| 6 | **Cross-Module Threat Correlation** | `/correlation` groups stored logs by source IP, escalating priority when one address shows repeated attempts or multiple attack categories — enriched live with AbuseIPDB, flagging risky sources (Tor/proxy/VPN). Real computed pattern detection, not a static label. |
| 7 | **MITRE ATT&CK Tagging** | Every detected category maps to a real MITRE ATT&CK technique ID (e.g. `T1190 — Exploit Public-Facing Application`) — the same taxonomy real SIEM platforms use. |
| 8 | **Landing Page + Enforced Sign-Up Flow** | New public landing page with feature overview; signing in with an unregistered email shows a clear "create an account first" prompt instead of a silent failure. |
| 9 | **Sidebar SOC Workspace Layout** | Dashboard reorganized into a sidebar-navigated workspace (Overview, Analyze & Parse, Correlation, Log History, Audit Trail) instead of one long stacked page. |
| 10 | **Auto-Refreshing Alert Queue** | The queue, KPIs, correlation panel, and audit trail now poll the backend every 15s automatically — not just after an action you personally took. |
| 11 | **Real MTTA / MTTR Metrics** | New `investigating_at` / `resolved_at` timestamps are captured the moment a human changes status, and `/metrics` computes genuine Mean-Time-To-Acknowledge / Mean-Time-To-Resolve from them — no fabricated numbers. MTTD is intentionally not reported as a duration, since detection is synchronous in this architecture. |
| 12 | **Interactive Response Playbooks** | Every log's detail view now shows an ordered, per-category checklist of concrete remediation steps. Checkbox progress is persisted per log (`/logs/{id}/playbook`), not just a UI toggle. |
| 13 | **Demo Seed Script** (`seed_demo_data.py`) | Pushes realistic sample log lines through the real `/analyze-log` pipeline — genuine ML scoring, correlation, and MITRE tagging run on this data, exactly as they would on anything typed in live. Useful for a reliable, reproducible live demo. |

Everything above runs against your own SQLite database and your own backend —
there is no fake data injected anywhere.

---

## Tech Stack

**Frontend**
- Plain HTML + vanilla JavaScript (no framework/build step)
- Tailwind CSS (via CDN) for styling
- Chart.js for the threat-distribution donut chart
- Font Awesome for icons

**Backend**
- Python 3 + FastAPI (REST API, auto-generates docs at `/docs`)
- scikit-learn (TF-IDF vectorizer + Logistic Regression) — the actual ML model that scores payload risk
- ReportLab — real PDF generation
- `requests` — live outbound HTTP calls to AbuseIPDB
- `python-dotenv` — loads your API key from a local `.env` file

**Database**
- SQLite (`database.db`), two tables:
  - `security_logs` — every analyzed payload + AI verdict
  - `users` — signup/login credentials (SHA-256 salted hashes)
  - `audit_logs` — new compliance trail table

**Workflow**
1. User pastes a raw log or a clean payload string.
2. `/parse-raw-log` (optional) extracts structured fields from messy input.
3. `/analyze-log` runs it through the ML model → risk score → severity → category (via signature rules) → plain-English summary → recommended remediation. Result is stored in SQLite.
4. If an IP was found, `/threat-intel/{ip}` enriches it with live AbuseIPDB reputation data.
5. Dashboard KPIs, the chart, and the log table all read live from `/metrics` and `/logs`.
6. Analyst can change status, delete a log, purge everything, export CSV/JSON, or generate a PDF report — every action that changes data writes to the audit trail.

---

## How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
(If you hit an "externally managed environment" error on Linux, use `pip install -r requirements.txt --break-system-packages`, or better, use a virtualenv:)
```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. (Optional but recommended) Enable live Threat Intelligence
1. Sign up for a **free** AbuseIPDB account: https://www.abuseipdb.com/register (no credit card, 1,000 lookups/day free)
2. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
3. Paste your API key into `.env`:
   ```
   ABUSEIPDB_API_KEY=your_real_key_here
   ```
If you skip this step, every other feature still works — the Threat Intel panel will just show a clear message telling you it needs a key.

### 3. Start the backend
```bash
uvicorn main:app --reload --port 8000
```
The API is now live at `http://127.0.0.1:8000` (interactive docs at `http://127.0.0.1:8000/docs`).

### 4. Open the frontend
Just open `index.html` directly in your browser (double-click it, or use the VS Code "Live Server" extension — `settings.json` is already configured for port 5501). It talks to the backend at `http://127.0.0.1:8000` via `API_BASE` at the top of the `<script>` block in `index.html` — change that if you deploy the backend elsewhere.

### 5. (Optional) Populate it with realistic demo data
Instead of typing attack payloads one at a time, run:
```bash
python seed_demo_data.py
```
This pushes ~11 realistic log lines (brute-force attempts, SQL injection, XSS, path traversal, a repeat-offender IP, and normal traffic) through your **real** `/analyze-log` endpoint — genuine ML scoring and correlation run on this data, nothing is faked. Great for a fast, reliable live demo.

### 6. Use it
- Sign up, then sign in — you'll land on the sidebar-navigated dashboard (Overview, Analyze & Parse, Correlation, Log History, Audit Trail).
- Paste a payload (e.g. `' OR 1=1 --`) into "Analyze Log Payload" and run it.
- Or paste a real raw log line into "Raw Log Parser & Live Threat Intel" to see it broken down and IP-checked live.
- Click the magnifying glass on any row to drill in — you'll see the full detail, an interactive response playbook checklist (progress is saved), an Export PDF button, and a Delete button.
- Use "Export Active Logs (CSV)" for a spreadsheet-ready dump.
- Check the Overview tab for MTTA/MTTR — these only populate once you change a log's status to Investigating/Resolved, since they're computed from real timestamps, not simulated.
- Check the Audit Trail tab to see every status change, playbook update, and purge logged with a real timestamp and identity.

---

## Files
```
main.py              FastAPI backend — all endpoints, ML model, PDF/CSV/audit logic
index.html           Frontend — single file, Tailwind + vanilla JS
requirements.txt     Python dependencies
.env.example          Copy to .env and add your free AbuseIPDB key
database.db           SQLite database (auto-created on first run if missing)
check_db.py           Small utility script to inspect the DB from a terminal
settings.json         VS Code Live Server port config
```
