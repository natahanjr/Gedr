# Gedr

AI-enhanced Static Application Security Testing (SAST) platform. Scans source code for vulnerabilities, generates professional PDF security reports, and integrates with external network scanners.

<!-- Achievement: YOLO -->
<!-- Achievement: Pull Shark -->

## Features

### Code Scanning
- Multi-language heuristic analysis (Python, Java, C/C++, PHP, JavaScript, Go, Ruby, Rust, C#, Kotlin, Swift, Shell, SQL)
- External tool integration (Bandit, Semgrep, SpotBugs, PMD, Clang)
- Taint analysis tracking user input to dangerous sinks
- Custom vulnerability rules via YAML
- Dependency vulnerability scanning (pip, npm, composer, Maven)

### Network Scanning
- Nmap port/service detection
- OpenVAS vulnerability assessment
- Nessus integration
- Custom scanner support

### AI Analysis
- Per-finding remediation guidance
- Executive security summaries
- Multi-tier failover with offline fallback
- Auto-fix engine with Git branch creation

### Reporting
- Premium PDF reports with charts and visualizations
- Credential redaction and content sanitization
- Finding tracking with stable IDs (GDR-F-001)
- CWE/OWASP Top 10 mapping

### Security
- JWT authentication with refresh tokens
- Rate limiting per endpoint type
- Path traversal and symlink protection
- Upload validation with zip bomb detection

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | FastAPI, Uvicorn, SQLite |
| AI | Multi-provider with offline fallback |
| Reports | WeasyPrint, FPDF2 |
| Frontend | Vanilla JavaScript SPA |
| Auth | JWT, bcrypt, OAuth2 |
| Infra | Docker, Docker Compose |

## Architecture

```
Frontend (SPA)  →  FastAPI Backend  →  Scanners (Python/Java/C++/Web/...)
                      ↓                      ↓
                  Database              External Tools
                      ↓               (Bandit/Semgrep/Nmap)
                  AI Service  →  Multi-provider / Offline Fallback
                      ↓
                  PDF Reports
```

## Project Structure

```
gedr/
├── backend/          # API, auth, scanning pipeline, security
├── scanners/         # Language-specific vulnerability scanners
├── scanner_connectors/  # Nmap, OpenVAS, Nessus integrations
├── reports/          # PDF generation, charts, templates
├── ai/               # AI agent with multi-backend support
├── ai_service/       # Standalone AI microservice
├── frontend/         # SPA dashboard
├── database/         # SQLite persistence layer
├── tests/            # Test suite
└── sample_code/      # Vulnerable test files
```

## Getting Started

### Prerequisites
- Python 3.11+
- pip

### Clone & Run

```bash
# Clone the repository
git clone https://github.com/natahanjr/Gedr.git
cd Gedr

# Install dependencies
pip install -r requirements.txt

# Set your AI API key (optional - runs offline without it)
export AI_PRIMARY_KEY="your-api-key"

# Start the server
python main.py
```

Open http://127.0.0.1:8000 in your browser.

### Docker

```bash
docker compose up
```

## License

MIT
