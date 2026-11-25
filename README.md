# SENTINEL AI

**Detect. Prioritise. Protect.**

SENTINEL AI is an AI-powered Web Application Security Intelligence Platform built with Python, Streamlit, Plotly, SQLite/SQLAlchemy, and Flask.

> **Current Release:** Phase 1 — Foundation, Premium UI, Persistent Database, and Isolated Local Demonstration Lab.

---

## Project Architecture

```text
sentinel-ai/
├── app.py                  # Main Streamlit application entrypoint & navigation router
├── config.py               # Central configuration, constants, navigation & OWASP metadata
├── requirements.txt        # Python dependencies
├── README.md               # Documentation & exact run commands
├── database/
│   ├── __init__.py
│   ├── database.py         # SQLAlchemy engine, session lifecycle, snapshot queries
│   └── models.py           # ORM models: Scan, Finding, Report
├── components/
│   ├── __init__.py
│   ├── sidebar.py          # Enterprise sidebar navigation
│   ├── dashboard.py        # Overview dashboard, empty state, Coming Soon & Settings views
│   └── charts.py           # Dark-themed Plotly gauges & distribution charts
├── demo_lab/
│   ├── __init__.py
│   └── app.py              # Isolated Flask local demonstration lab (synthetic data only)
├── assets/
│   └── style.css           # Deep navy / electric cyan / violet cybersecurity SaaS theme
├── scanner/                # Reserved for Phase 2 scanning engine
├── intelligence/           # Reserved for Phase 3 AI risk intelligence
├── remediation/            # Reserved for Phase 3 remediation playbooks
├── reporting/              # Reserved for Phase 3 report generation
└── tests/
    ├── __init__.py
    └── test_phase1.py      # Phase 1 verification tests
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
