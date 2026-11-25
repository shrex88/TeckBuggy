# SENTINEL AI

**Detect. Prioritise. Protect.**

SENTINEL AI is an AI-powered Web Application Security Intelligence Platform built with Python, Streamlit, Plotly, SQLite/SQLAlchemy, and Flask.

> **Implemented Phases:**
> - **Phase 1:** Foundation, Premium Cybersecurity UI, Persistent SQLite/SQLAlchemy Database, and Isolated Local Flask Demonstration Lab.
> - **Phase 2:** Defensive Local Security Scanners, OWASP Top 10:2025 Mapping, Explainable AI Risk Intelligence, and Dashboard Integration.
> - **Phase 3:** Smart Remediation Engine, Security Proof (Before/After Verification), Branded PDF Reporting, Enhanced Scan History, and Docker Compose Setup.

---

## Project Architecture

```text
sentinel-ai/
├── app.py                  # Main Streamlit application entrypoint & navigation router
├── config.py               # Central configuration, constants, profiles & OWASP 2025 metadata
├── requirements.txt        # Python dependencies
├── README.md               # Documentation & exact run commands
├── database/
│   ├── __init__.py
│   ├── database.py         # SQLAlchemy engine, session lifecycle, snapshot & scan queries
│   └── models.py           # ORM models: Scan, Finding, Report
├── components/
│   ├── __init__.py
│   ├── sidebar.py          # Enterprise sidebar navigation
│   ├── dashboard.py        # Overview dashboard, empty state, Coming Soon & Settings views
│   ├── phase2_views.py     # New Security Scan, Vulnerabilities, AI Intelligence & Scan History
│   └── charts.py           # Dark-themed Plotly gauges & distribution charts
├── demo_lab/
│   ├── __init__.py
│   └── app.py              # Isolated Flask local demonstration lab (synthetic data only)
├── assets/
│   └── style.css           # Deep navy / electric cyan / violet cybersecurity SaaS theme
├── scanner/                # Authorised local-only security scanners (Phase 2)
│   ├── target_validator.py # SSRF prevention, DNS rebinding & redirect validation
│   ├── header_scanner.py   # HTTP security header inspection
│   ├── cookie_scanner.py   # Cookie flag analysis (values never stored)
│   ├── tls_scanner.py      # Strict TLS & certificate inspection
│   ├── exposed_file_scanner.py # Predefined sensitive path metadata checks
│   ├── models.py           # StandardFinding dataclass
│   └── orchestrator.py     # End-to-end scan & persistence coordinator
├── intelligence/           # OWASP 2025 & AI Risk Intelligence (Phase 2)
│   ├── owasp_mapper.py     # OWASP Top 10:2025 mapping (A02:2025, A04:2025, contextual A07:2025)
│   └── risk_engine.py      # Multi-factor weighted risk scoring & application profiles
├── remediation/            # Smart Remediation Engine (Phase 3)
│   └── fix_generator.py    # Flask, Django, Apache, Nginx & Express playbooks
├── reporting/              # PDF Report Generation (Phase 3)
│   └── pdf_generator.py    # Branded ReportLab PDF exporter
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Isolated Sentinel AI + Demo Lab stack
└── tests/
    ├── __init__.py
    ├── test_phase1.py      # Phase 1 verification tests
    ├── test_phase2.py      # Phase 2 scanner, OWASP, risk engine & DB integration tests
    └── test_phase3.py      # Phase 3 remediation, Security Proof, PDF & E2E tests
```

---

## Setup & Installation

Navigate to the `sentinel-ai` directory and install dependencies:

```powershell
cd sentinel-ai
pip install -r requirements.txt
```

---

## Running the Application

### 1. Start the SENTINEL AI Dashboard (Streamlit)

```powershell
cd sentinel-ai
python -m streamlit run app.py
```

By default, Streamlit launches at `http://localhost:8501`.

### 2. Start the Local Demonstration Lab (Flask)

In a separate terminal:

```powershell
cd sentinel-ai
python -m demo_lab.app
```

By default, the isolated local demonstration lab binds strictly to `http://127.0.0.1:5050` and exposes configurable synthetic endpoints:
- `GET /` — Service metadata & active lab configuration
- `GET /health` — Health check endpoint
- `GET /session-test` — Issues a synthetic cookie (`sentinel_demo_session`) with configurable `HttpOnly`/`Secure`/`SameSite` flags
- `GET /config.json` — Synthetic exposed configuration endpoint (clearly marked synthetic test data)
- `GET/POST /lab/settings` — Toggle `missing_security_headers`, `insecure_cookie_flags`, and `expose_config_endpoint`

---

## Running Tests

```powershell
cd sentinel-ai
python -m pytest -v
```

---

## Phase-by-Phase Capabilities

### Phase 1 — Foundation, Premium UI & Local Demonstration Lab
- **Enterprise Cybersecurity UI:** Deep navy, charcoal, electric cyan, and violet Streamlit dashboard with custom CSS and Plotly visualizations.
- **Persistent SQLite Storage:** SQLAlchemy ORM models (`Scan`, `Finding`, `Report`) with transactional session management and empty-state handling.
- **Isolated Local Flask Lab:** `demo_lab/app.py` bound strictly to `127.0.0.1:5050` with configurable missing security headers, insecure `sentinel_demo_session` cookie flags, and synthetic exposed `/config.json`.

### Phase 2 — Defensive Security Scanners & AI Risk Intelligence
- **Authorised Target Validation:** `scanner/target_validator.py` restricts scans to `localhost`, `127.0.0.1`, `::1`, and explicitly allowlisted local Docker services, with DNS rebinding protection, redirect validation, timeouts, and SSRF guards.
- **Scanning Modules:** HTTP Security Header Scanner, Cookie Security Scanner (cookie values never stored), Strict TLS/Certificate Scanner, and Predefined Exposed File Scanner.
- **OWASP Top 10:2025 & Risk Engine:** Deterministic mapping (`A02:2025`, `A04:2025`, contextual `A07:2025`) and weighted 0–100 risk scoring across `Fintech / Payment Application`, `Customer Portal`, and `General Web Application` profiles.

### Phase 3 — Smart Remediation, Security Proof & PDF Reporting
- **Smart Remediation Engine:** `remediation/fix_generator.py` provides technical explanations, security impact, corrected configurations, verification steps, and reference code for Flask, Django, Apache, Nginx, and Express without modifying targets automatically.
- **Security Proof Engine:** `intelligence/security_proof.py` compares baseline and follow-up scans by `(rule_id, target_path)`, calculates risk reduction and percentage improvement, and marks findings `resolved` only after a subsequent completed scan verifies the fix.
- **Branded PDF Reports & Scan History:** `reporting/pdf_generator.py` exports 10-section PDF assessment reports via ReportLab, and `Scan History` provides full historical scan and finding inspection.

---

## Live Hackathon Demonstration Flow

`AUTHORISE → SCAN → DETECT → PRIORITISE → FIX → RESCAN → VERIFY → REPORT`

1. Start the local Flask demonstration lab (`python -m demo_lab.app`) and Streamlit dashboard (`python -m streamlit run app.py`).
2. Run an initial scan against `http://127.0.0.1:5050` in **New Security Scan**.
3. Inspect detected misconfigurations, OWASP 2025 mappings, and AI risk scores in **Vulnerabilities** and **AI Risk Intelligence**.
4. Review framework-specific patches in **Remediation Centre** and apply fixes to the local lab (e.g., via `POST /lab/settings`).
5. Run a second scan and open **Security Proof** to verify fixed vulnerabilities, score improvement, and risk reduction.
6. Export and download the branded PDF report in **Reports**.

### Docker Compose (Optional)

```powershell
cd sentinel-ai
docker compose up --build
```
