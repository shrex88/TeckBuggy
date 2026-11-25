# SENTINEL AI

**Detect. Prioritise. Protect.**

SENTINEL AI is an AI-powered Web Application Security Intelligence Platform built with Python, Streamlit, Plotly, SQLite/SQLAlchemy, and Flask.

> **Current Release:** Phase 2 — Defensive Local Security Scanners, OWASP Top 10:2025 Mapping, Explainable AI Risk Intelligence, and Dashboard Integration.

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
├── remediation/            # Reserved for Phase 3 remediation playbooks
├── reporting/              # Reserved for Phase 3 report generation
└── tests/
    ├── __init__.py
    ├── test_phase1.py      # Phase 1 verification tests
    └── test_phase2.py      # Phase 2 scanner, OWASP, risk engine & DB integration tests
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
