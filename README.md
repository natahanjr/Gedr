# Gədr

AI-Enhanced Multi-Language Security Analyzer (SAST).

An AI-assisted static application security testing platform that detects vulnerabilities in
**Python, Java, C, C++, PHP, HTML, CSS, JavaScript, Go, Ruby, Rust, C#, Kotlin, Swift, Shell, and SQL**,
explains them with **Gədr AI security reasoning**, and generates professional security assessment reports (PDF).

Optimized for modest hardware (Windows 11, Core i5, 12GB RAM, no dedicated GPU).

---

## Architecture

```
User → Upload Source Code → Language Detection → Static Analysis Engine
   (heuristic scanners + optional Bandit / Semgrep / SpotBugs / PMD / Clang)
        → Dependency Scanner (pip-audit, npm-audit, composer-audit)
        → Vulnerability Database (SQLite) → Gədr AI Analysis
        → Security Report Generator (PDF) → Dashboard (custom SPA)
```

| Component | Tech | Role |
|---|---|---|
| Backend | FastAPI + Uvicorn | API, file processing, scanner orchestration, SPA hosting |
| Frontend | Custom SPA (HTML/CSS/vanilla JS, no build step) | Upload, dashboard, results, report download |
| Database | SQLite | Projects, scans, findings, AI recommendations |
| Scanners | Built-in heuristic engine + optional external tools | Detection |
| Dependencies | pip-audit, npm-audit, composer-audit | Vulnerable dependency detection |
| AI | Gədr AI (OpenAI-compatible API) | Security reasoning & remediation |
| Reports | fpdf2 | PDF security assessment reports |
| Auth | JWT + bcrypt | User authentication & authorization |

### Detection layers

The heuristic engine is **always available with zero external dependencies**. External tools
are probed on PATH and used automatically when installed:

- Python → `bandit`, `semgrep`, `pip-audit`
- Java → `spotbugs`, `pmd`
- C/C++ → `clang --analyze` (Clang Static Analyzer)
- Web (PHP/JS/HTML/CSS) → `semgrep`
- Node.js → `npm-audit`
- PHP → `composer-audit`

### Dependency scanning

Automatically detects vulnerable dependencies across multiple ecosystems:
- Python: `pip-audit` for requirements.txt, Pipfile, pyproject.toml
- JavaScript/Node: `npm-audit` for package.json
- PHP: `composer-audit` for composer.lock
- Java: dependency-check for pom.xml, build.gradle

### Risk engine

- Findings are mapped to **CWE IDs** and **OWASP Top 10 (2021)** categories.
- Severity: Critical 9–10, High 7–8, Medium 4–6, Low 1–3.
- Security score: starts at 100, deducts weighted penalties (Critical=30, High=15,
  Medium=6, Low=2), scaled by project size.
- Grades: A+ (≥90), A (≥80), B (≥70), C (≥50), D (≥30), F (<30).

### Gədr AI — 3-tier fallback chain

AI analysis never fails silently. Requests cascade through providers automatically:

```
Request → Tier 1: Gədr Fast (primary)
              │ quota / rate-limit / failure
              ▼
          Tier 2: Gədr Cloud (fallback)
              │ failure
              ▼
          Tier 3: Gədr Deep Reasoning (extended timeout)
              │ failure
              ▼
          Offline rule-based explanations (always available)
```

Each finding receives a deep explanation: what the vulnerability is, potential impact,
root cause, step-by-step attack scenario, recommended fix, and a secure code example.

### PDF reports (Gedr Reporting Engine 3.0)

Reports are produced by a dedicated reporting pipeline, not a simple export:

```
DATA -> REPORT MODEL -> SECTION GENERATION -> VISUALISATION
     -> PDF LAYOUT -> VALIDATION -> DELIVERY
```

- `reports/report_model.py` - normalises/aggregates platform records; nothing
  is invented (sections without data are omitted, empty scans produce a
  meaningful "No Significant Findings" report)
- `reports/sanitizer.py` - credential redaction before any evidence is embedded
- `reports/charts.py` - native vector charts (severity ring, score meter,
  category bars) - crisp in print, greyscale-safe
- `reports/layout.py` - design system: cover, running headers/footers,
  numbered sections, finding cards, repeating table headers, page X of Y
- `reports/validator.py` - automated QC (structure, blank pages, content
  presence, metadata) before delivery; critical failures abort the export

Output: `GDR_Security_Analysis_Report_<REPORT-ID>_<DATE>.pdf` with report ID,
classification, analysis window, integrity digest and full methodology
appendix.

---

## Setup

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
cd Gedr
pip install -r requirements.txt
```

### Environment configuration

```bash
cp .env.example .env
# Edit .env with your values
```

Required variables:
- `SECRET_KEY` — Generate with: `python -c "import secrets; print(secrets.token_hex(64))"`

Optional variables:
- `CCI_AI_API_KEY` — AI provider API key (platform works without it using offline fallback)
- `DATABASE_URL` — SQLite (default) or PostgreSQL connection string
- `CCI_ALLOWED_SCAN_ROOTS` — Restrict scan paths (comma-separated)

### Optional: install external scanners

```bash
pip install bandit semgrep pip-audit
# Java: download SpotBugs/PMD and add to PATH
# C/C++: install LLVM/Clang and add to PATH
```

---

## Run

```bash
python main.py                 # backend + SPA dashboard at http://127.0.0.1:8000
python run.py                  # alternative entry point
python main.py --legacy-dashboard  # also launch the old Streamlit UI on :8501
```

Open **http://127.0.0.1:8000** — the SPA (Scan / Dashboard / Findings pages) is served
directly by FastAPI. API docs: `http://127.0.0.1:8000/docs`

---

## Authentication

Register a new user:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/register \
  -d "username=myuser" -d "password=mypassword"
```

Login to get a JWT token:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login \
  -d "username=myuser" -d "password=mypassword"
```

Use the token for protected endpoints:
```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/projects
```

---

## API Endpoints

### Public endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login and get JWT token |
| GET | `/api/health` | Status + detected external tools |
| GET | `/api/connectors` | List available scanner connectors |

### Protected endpoints (require JWT)

| Method | Path | Description |
|---|---|---|
| POST | `/api/scan/upload` | Upload a single file and scan it |
| POST | `/api/scan/project` | Scan a local path (`path`, `use_ai` form fields) |
| GET | `/api/projects` | List projects |
| GET | `/api/projects/{id}` | Project + scans |
| GET | `/api/scans/{id}` | Scan with findings + AI recommendations |
| POST | `/api/scans/{id}/ai` | Run Gədr analysis over findings |
| POST | `/api/scans/{id}/summary` | Generate AI summary of scan results |
| GET | `/api/scans/{id}/report` | Download PDF report |
| POST | `/api/scans/{id}/autofix` | Auto-fix vulnerabilities (creates Git branch) |
| DELETE | `/api/projects/{id}` | Delete a project |
| DELETE | `/api/history` | Clear all scan history |

---

## Docker Deployment

```bash
# Start all services
docker-compose up -d

# Services:
# - Backend API: http://localhost:8000
# - AI Service: http://localhost:8002
# - PostgreSQL: localhost:5432
# - OpenVAS (optional): docker-compose --profile scanners up -d
```

---

## Evaluation

`sample_code/` contains deliberately vulnerable files for all scanner families.
Run:

```bash
python tests/smoke_test.py          # pipeline smoke test
pytest -q                           # full unit + integration suite
```

For the evaluation matrix (OWASP Benchmark, Juliet, DVWA, WebGoat), point the
`/api/scan/project` endpoint at a test suite directory and collect per-scan metrics
(findings vs. known labels → precision / recall / false positives / negatives).

---

## Project Structure

```
Gedr/
├── main.py                      # entry point (serves SPA + API)
├── run.py                       # alternative runner
├── start_ai.py                  # AI microservice starter
├── backend/
│   ├── api.py                   # FastAPI endpoints + SPA hosting
│   ├── auth.py                  # JWT authentication
│   ├── scanner_manager.py       # orchestration, language detection, risk engine
│   ├── autofix_engine.py        # auto-fix with Git integration
│   ├── custom_rule_engine.py    # user-defined security rules
│   ├── taint_analyzer.py        # taint flow analysis
│   ├── benchmark_validator.py   # OWASP Benchmark evaluation
│   ├── docker_orchestrator.py   # Docker scanner management
│   ├── rate_limit.py            # rate limiting
│   ├── path_security.py         # path traversal prevention
│   ├── error_handling.py        # error handlers
│   └── upload_validator.py      # file upload validation
├── frontend/
│   ├── index.html               # SPA markup
│   ├── style.css                # dark security theme
│   └── app.js                   # SPA logic (vanilla JS)
├── scanners/
│   ├── python_scanner.py        # Python heuristic + Bandit/Semgrep
│   ├── java_scanner.py          # Java heuristic + SpotBugs/PMD
│   ├── cpp_scanner.py           # C/C++ heuristic + Clang
│   ├── web_scanner.py           # PHP/HTML/CSS/JS + Semgrep
│   ├── generic_scanner.py       # Go, Ruby, Rust, C#, Kotlin, Swift, Shell, SQL
│   └── dependency_scanner.py    # pip-audit, npm-audit, composer-audit
├── scanner_connectors/
│   ├── base.py                  # connector base class
│   ├── openvas.py               # OpenVAS/GVM connector
│   ├── nmap.py                  # Nmap connector
│   ├── nessus.py                # Nessus connector
│   └── custom.py                # custom scanner connector
├── ai/
└── ai_agent.py                 # Gədr AI reasoning engine + offline fallback
├── ai_service/
│   └── main.py                  # AI microservice (FastAPI)
├── database/
│   └── sqlite_manager.py        # SQLite persistence
├── reports/
│   └── pdf_generator.py         # compat shim -> reports/ reporting engine
├── reports/                     # Gedr Reporting Engine (see "PDF reports")
│   ├── generator.py             #   pipeline orchestrator + section builders
│   ├── report_model.py          #   data layer: normalise, aggregate, digest
│   ├── sanitizer.py             #   credential redaction for evidence
│   ├── theme.py                 #   design system (palette, type, severity)
│   ├── charts.py                #   native vector visualisations
│   ├── layout.py                #   GedrPDF layout engine + components
│   └── validator.py             #   automated report QC before delivery
├── docker/
│   └── Dockerfile.scanners      # Scanner environment container
├── sample_code/                 # vulnerable test files
├── tests/
│   ├── smoke_test.py            # pipeline smoke test
│   ├── test_scanners.py         # scanner unit tests
│   ├── test_integration_pipeline.py
│   └── test_ai_retry.py         # AI retry logic tests
├── .env.example                 # environment variables template
├── docker-compose.yml           # Docker Compose config
├── Dockerfile.backend           # Backend container
├── requirements.txt             # Python dependencies
└── README.md
```

---

## Security Features

- **JWT Authentication** — Secure token-based auth with bcrypt password hashing
- **Rate Limiting** — Configurable per-endpoint rate limits
- **Path Traversal Prevention** — Whitelist-based filesystem access control
- **Input Validation** — File type, size, and content validation
- **CORS Configuration** — Configurable allowed origins
- **Secret Management** — Environment variables, no hardcoded secrets

---

## Design decisions

1. **Heuristic engine as the default layer** — no heavy toolchains required, the platform
   is functional out of the box and scans fast on 12GB RAM systems; external tools are
   additive and auto-detected.
2. **AI as reasoning assistant, not detection engine** — scanner findings are strictly
   formatted and sent to Gədr for explanation/remediation, keeping the detection
   deterministic and reproducible.
3. **Transparent risk model** — score and severity formulas are documented in code and in
   the generated PDF so results are fully auditable.
4. **Graceful degradation** — missing API key, missing external tools, or a failed AI call
   never blocks the scan pipeline.
5. **Zero-build-step SPA** — the dashboard is plain HTML/CSS/vanilla JS served by FastAPI:
   a professional product look without a Node toolchain, keeping RAM/disk usage minimal.
6. **Defense in depth** — authentication, authorization, rate limiting, path validation, and
   input sanitization work together to prevent common attack vectors.

---

*Last updated: August 2026*
