# SENTINEL AI

**Detect. Prioritise. Protect.**

**Team:** Tech Buggy · **Category:** AI in Cybersecurity and Fintech · **Problem Statement:** Web Application Security Misconfiguration Scanner

**SENTINEL AI** is an evidence-driven web application security assessment, risk intelligence, AI-assisted remediation, and verification platform built with Python, Streamlit, Flask, Google Gemini (`google-genai`), SQLite/SQLAlchemy, Plotly, and ReportLab.

> **Core Workflow:** `DETECT → PRIORITISE → PROPOSE → APPROVE → VERIFY → REPORT`

---

## Key Features

- **Landing Page & Authentication Portal** (`components/landing_auth.py`):
  - Top navigation bar with **Features**, **How It Works**, **Sign In**, **Create Account**, and an icon-only **Dark / Light Mode** (`☀️` / `🌙`) toggle.
  - PBKDF2-HMAC-SHA256 salted password authentication backed by SQLite (`UserAccount`), with real-time login telemetry (`created_at`, `last_login_at`, `login_count`) and immutable `AuditLog` tracking.
- **Liquid Glassmorphism UI & System-Wide Dark/Light Mode** (`assets/style.css`, `app.py`):
  - Animated liquid ambient orbs, frosted glass panels, liquid button hover/shimmer animations, and crisp **Dark Mode** + **Light Mode** themes across all pages, tables, and Plotly charts.
- **Per-User Data Isolation & Persistence** (`database/database.py`, `database/models.py`):
  - Each registered user has an isolated workspace where their scans, findings, remediation proposals, audit logs, and PDF reports persist across sessions, with a **Reset User Data** control in **Settings**.
- **Defensive Multi-Layer Security Scanner** (`scanner/`):
  - Supports **public `https://` websites**, **`http://localhost` / `https://localhost`** (with automatic IPv4/IPv6 loopback fallback and self-signed local cert inspection), and **local network LAN IPs** (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`), while enforcing SSRF protection against cloud metadata endpoints (`169.254.0.0/16`) and embedded URL credentials.
  - Supports direct URL input or **`.txt` / `.csv` URL file upload** on **New Security Scan**.
  - Built-in **glassmorphic findings table** with **Critical → High → Medium → Low** filtering & sorting, interactive **Risk Score** & **Severity Distribution** Plotly graphs, and **AI Suggestions & Required Changes** directly on the scan page.
  - Automatic embedded Flask demo target on `http://127.0.0.1:8000` (so local and Streamlit Cloud demos work out of the box), plus framework-managed header skipping on SENTINEL AI's own Streamlit port `8501`.
- **Explainable AI Risk & Confidence Engines** (`intelligence/`):
  - **AI Risk Intelligence (`risk_engine.py`)**: 5-factor weighted risk model (`severity` 30%, `exposure` 25%, `data_sensitivity` 20%, `exploitability` 15%, `confidence` 10%).
  - **Google Gemini AI Copilot (`gemini_client.py`, `ai_remediation.py`)**: Uses `gemini-2.5-flash` (with `gemini-2.5-flash-lite`, `gemini-3-flash-preview`, `gemini-3.1-flash-lite` fallbacks) via `google-genai`, reading `GEMINI_API_KEY` from `.env` or `st.secrets`, with deterministic remediation playbook fallback when offline.
  - **Security Proof & Regression Guard**: Before-and-after verification scans, 7-factor remediation confidence scoring, human-in-the-loop approval, configuration backup/rollback, and 16-section branded PDF reports (`reporting/pdf_generator.py`).

---

## Architecture

- **`app.py` / `config.py`** — Streamlit entrypoint, global Dark/Light theme CSS injection, embedded `127.0.0.1:8000` demo target launcher, 14-section workspace router, and OWASP Top 10:2025 metadata.
- **`components/`** — `landing_auth.py` (landing + login/register), `sidebar.py` (scrollable navigation + theme toggle), `dashboard.py` (Overview + Settings telemetry), `charts.py` (theme-aware Plotly charts), `phase2_views.py`, `phase3_views.py`, `enterprise_views.py`, `twin_confidence_views.py`.
- **`scanner/`** — `target_validator.py` (SSRF, DNS rebinding, IPv4/IPv6 loopback fallback), `header_scanner.py`, `cookie_scanner.py`, `tls_scanner.py` (with `certifi` CA bundle), `exposed_file_scanner.py` (with SPA soft-404 filtering), `orchestrator.py`.
- **`intelligence/`** — `owasp_mapper.py`, `risk_engine.py`, `benchmark.py`, `security_proof.py`, `regression_guard.py`, `remediation_confidence.py`, `gemini_client.py`, `ai_remediation.py`.
- **`remediation/`** — `fix_generator.py`, `fix_validator.py`, `regression_analyzer.py`, `approval_manager.py`, `fix_applier.py`, `rollback_manager.py`, `verification_engine.py`.
- **`reporting/`** — `pdf_generator.py` generating 16-section branded PDF reports from SQLite.
- **`database/`** — SQLite + SQLAlchemy ORM (`data/sentinel_ai.db`) with additive schema migrations (`UserAccount`, `Scan`, `Finding`, `Report`, `RemediationProposal`, `ApprovalRecord`, `ConfigBackup`, `RollbackRecord`, `BenchmarkRun`, `RegressionAlert`, `AuditLog`, and confidence/simulation models).

---

## Tech Stack & Packages (`requirements.txt`)

- `streamlit>=1.38.0` — Web UI & multi-page dashboard
- `plotly>=5.22.0` — Interactive security posture & risk charts
- `sqlalchemy>=2.0.30` — SQLite ORM & session management
- `flask>=3.0.3` — Embedded demo target server
- `requests>=2.31.0` — SSRF-safe HTTP scanner client
- `reportlab>=4.2.0` — 16-section PDF report generation
- `pyarrow>=20.0.0` — Columnar data support for Streamlit/pandas
- `google-genai>=1.0.0` — Google Gemini AI SDK
- `python-dotenv>=1.0.0` — `.env` environment variable loader

---

## Local Installation & Running

```powershell
git clone https://github.com/shrex88/TeckBuggy.git
cd TeckBuggy
pip install -r requirements.txt
copy .env.example .env
```

Set `GEMINI_API_KEY` and `GEMINI_MODEL=gemini-2.5-flash` in `.env` (optional; deterministic remediation playbooks are used automatically if omitted).

Start the application:

```powershell
python -m streamlit run app.py --server.port 8501
```

Or via Docker Compose:

```powershell
docker compose up --build
```

Default analyst login: `admin@sentinel.ai` / `Sentinel@2026` (or create a new account from the landing page).

---

## Streamlit Community Cloud Deployment

1. Push the repository to GitHub (`main` branch).
2. In [share.streamlit.io](https://share.streamlit.io), create a new app pointing to `app.py`.
3. In **App Settings → Secrets**, add:
   ```toml
   GEMINI_API_KEY = "your-google-gemini-api-key"
   GEMINI_MODEL = "gemini-2.5-flash"
   ```
4. The embedded demo target (`http://127.0.0.1:8000`) starts automatically inside the cloud container, and live public `https://` targets can also be scanned directly.

---

## Inspecting the Database in DBeaver

Connect DBeaver to **SQLite** using the file path:

```text
data/sentinel_ai.db
```

Key tables: `user_accounts` (includes `created_at`, `last_login_at`, `login_count`), `scans` (`user_id`, `target_url`, `security_score`, `total_findings`, `scan_date`), `findings`, `reports`, and `audit_logs`.

---

## Running Tests

```powershell
python -m pytest -v
```

All **27 unit and integration tests** across `tests/test_auth_landing.py`, `tests/test_phase1.py`, `tests/test_phase2.py`, `tests/test_phase3.py`, `tests/test_enterprise.py`, and `tests/test_master_features.py` pass cleanly.
