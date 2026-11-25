# SENTINEL AI

**Detect. Prioritise. Protect.**

**Team:** Tech Buggy · **Category:** AI in Cybersecurity and Fintech · **Problem Statement:** Web Application Security Misconfiguration Scanner

SENTINEL AI is an evidence-driven web application security assessment, benchmarking, AI-assisted remediation, and verification platform built with Python, Streamlit, Flask, Google Gemini (`google-genai`), SQLite/SQLAlchemy, Plotly, and ReportLab.

> **Core Workflow:** `AUTHORISE → BENCHMARK → SCAN → DETECT → ANALYSE → PRIORITISE → GEMINI AI → APPROVE → APPLY → VERIFY → PROVE → REPORT`

---

## Architecture

- **`app.py` / `config.py`** — Streamlit entrypoint, 13-section router, target registry, allowlisted action catalogue, and OWASP Top 10:2025 metadata.
- **`scanner/`** — Strict local-only `target_validator.py` (SSRF, DNS rebinding, redirect protection), `header_scanner.py`, `cookie_scanner.py`, `tls_scanner.py`, `exposed_file_scanner.py` (with SPA soft-404 filtering), and `orchestrator.py`.
- **`intelligence/`** — `owasp_mapper.py` (OWASP Top 10:2025), `risk_engine.py` (5-factor Fintech-aware scoring + contextual impact), `benchmark.py` (App A vs App B), `security_proof.py`, `regression_guard.py`, `gemini_client.py`, and `ai_remediation.py`.
- **`remediation/`** — `fix_generator.py`, `fix_validator.py`, `approval_manager.py`, `fix_applier.py`, `rollback_manager.py`, and `verification_engine.py`.
- **`reporting/`** — `pdf_generator.py` generating 16-section branded PDF reports from SQLite.
- **`demo_lab/`** — Isolated local Flask targets:
  - `high_security_app.py` (Application A — read-only hardened reference on `127.0.0.1:5051`).
  - `app.py` (Application B — configurable low-security target on `127.0.0.1:5050` with token-protected `/api/remediation/*`).
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

## Starting the Services

Run each service in a separate terminal:

1. **Application A (High-Security Reference, Read-Only — `127.0.0.1:5051`):**
   ```powershell
   python -m demo_lab.high_security_app
   ```
2. **Application B (Low-Security Demo Lab — `127.0.0.1:5050`):**
   ```powershell
   python -m demo_lab.app
   ```
3. **SENTINEL AI Dashboard (`http://localhost:8501`):**
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
- **PDF Reports:** Open **Reports** → **Generate PDF Report** → **Download PDF Report**.

---

## Running Tests

```powershell
python -m pytest -v
```

## Troubleshooting

- **PyArrow / NumPy 1.x conflict:** `requirements.txt` pins `pyarrow>=12.0.0,<19.0.0` for compatibility with `numpy 1.26.x`.
- **Port already in use:** Override `SENTINEL_DEMO_PORT` or `SENTINEL_HIGH_SEC_PORT` in `.env`.
