# SENTINEL AI

**Detect. Prioritise. Protect.**

**Team:** Tech Buggy · **Category:** AI in Cybersecurity and Fintech · **Problem Statement:** Web Application Security Misconfiguration Scanner

SENTINEL AI is an evidence-driven web application security assessment, benchmarking, AI-assisted remediation, and verification platform built with Python, Streamlit, Flask, Google Gemini (`google-genai`), SQLite/SQLAlchemy, Plotly, and ReportLab.

> **Core Workflow:** `DETECT → LEARN → SIMULATE → EVALUATE → APPROVE → REMEDIATE → RESCAN → VERIFY → REPORT`

---

## Architecture

- **`app.py` / `config.py`** — Streamlit entrypoint, 14-section router, allowlisted action catalogue, and OWASP Top 10:2025 metadata.
- **`scanner/`** — Strict local-only `target_validator.py` (SSRF, DNS rebinding, redirect protection), `header_scanner.py`, `cookie_scanner.py`, `tls_scanner.py`, `exposed_file_scanner.py` (with SPA soft-404 filtering), and `orchestrator.py`.
- **`intelligence/`** — `owasp_mapper.py`, `risk_engine.py`, `benchmark.py`, `security_proof.py`, `regression_guard.py`, `remediation_confidence.py`, `gemini_client.py`, and `ai_remediation.py`.
- **`remediation/`** — `fix_generator.py`, `fix_validator.py`, `regression_analyzer.py`, `approval_manager.py`, `fix_applier.py`, `rollback_manager.py`, and `verification_engine.py`.
- **`reporting/`** — `pdf_generator.py` generating 16-section branded PDF reports from SQLite.
- **`database/`** — Additive SQLite + SQLAlchemy models (`Scan`, `Finding`, `Report`, `RemediationProposal`, `ApprovalRecord`, `ConfigBackup`, `RollbackRecord`, `BenchmarkRun`, `RegressionAlert`, `AuditLog`).

---

## Installation & Environment Setup

```powershell
cd "c:\Users\anass\.gemini\antigravity-ide\scratch\tech buggy\sentinel-ai"
pip install -r requirements.txt
copy .env.example .env
```

### Optional Gemini API Configuration
Set `GEMINI_API_KEY` in `.env` (never commit real secrets). If `GEMINI_API_KEY` is omitted or unreachable, SENTINEL AI automatically uses deterministic rule-based remediation.

---

## Starting SENTINEL AI

### 1. Figma React + Vite Frontend (Recommended)
Start the Flask REST API bridge and the React frontend in two terminals:

```powershell
# Terminal 1: REST API bridge on http://127.0.0.1:5055
python -m api_server

# Terminal 2: React + Vite UI on http://127.0.0.1:5173
cd frontend
npm install
npm run dev
```

### 2. Streamlit Dashboard
```powershell
python -m streamlit run app.py
```

Or via Docker Compose:
```powershell
docker compose up --build
```

---

## Key Workflows

- **Security Benchmark:** Open **Security Benchmark** → click **Run Security Benchmark** to compare Application A vs. Application B using genuine scanner results.
- **AI Remediation & Approval:** Open **AI Remediation Copilot** → select a finding → **Generate AI Fix** → open **Developer Approval Centre** → **Approve Fix** → **Apply Approved Fix** (only Application B is permitted; Application A is strictly read-only).
- **Verification & Security Proof:** Click **Verify Fix via Fresh Scan** or open **Security Proof** to verify resolved findings, risk reduction, and percentage improvement.
- **Smart Rollback:** Open **Remediation History** → select a `backup_uid` → **Rollback Configuration** to restore and verify the original setting.
- **Security Regression Guard:** Open **Security Regression Guard** to detect returning fixed issues or score deterioration.
- **AI Remediation Confidence Engine:** Open **Remediation Confidence** (or click **Evaluate Confidence** in **Developer Approval Centre**) to view deterministic validation, application safety, regression warnings, and 7-factor confidence scoring.
- **Security Learning Mode:** Open **Security Learning Mode** for Beginner/Intermediate/Advanced lessons, the Gemini AI Security Tutor, interactive quizzes, hands-on local lab challenges, and verified badges.
- **PDF Reports:** Open **Reports** → **Generate PDF Report** → **Download PDF Report**.

---

## Running Tests

```powershell
python -m pytest -v
```

## Troubleshooting

- **PyArrow / NumPy 1.x conflict:** `requirements.txt` pins `pyarrow>=12.0.0,<19.0.0` for compatibility with `numpy 1.26.x`.
- **Port already in use:** Override `SENTINEL_DEMO_PORT` or `SENTINEL_HIGH_SEC_PORT` in `.env`.
