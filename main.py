"""
Gədr - entry point.

The FastAPI backend serves the modern SPA dashboard at http://127.0.0.1:8000
(frontend/ folder). The Streamlit dashboard remains available as a legacy
optional UI.

Usage:
    python main.py                 # backend + SPA dashboard
    python main.py --legacy-dashboard  # launch the old Streamlit UI too
"""
import argparse
import os
import sys
import logging
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# The brand contains "ə" (U+0259); when stdout/stderr are redirected to a
# file or pipe, Python falls back to the legacy cp1252 codec on Windows and
# logging the brand would crash the process. Force UTF-8 with replacement.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError, OSError):
        pass

# Set up logging early
from backend.error_handling import setup_logging

BACKEND_PORT = int(os.getenv("CCI_BACKEND_PORT", "8000"))
LOG_FILE = Path(ROOT) / "logs" / "cybercode.log"
LOG_LEVEL = os.getenv("CCI_LOG_LEVEL", "INFO")

# Create logs directory
LOG_FILE.parent.mkdir(exist_ok=True)

# Configure logging
log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
setup_logging(log_file=LOG_FILE, level=log_level)

logger = logging.getLogger(__name__)


def run_backend():
    import uvicorn

    logger.info(f"Starting Gədr on http://127.0.0.1:{BACKEND_PORT}")
    logger.info(f"API documentation: http://127.0.0.1:{BACKEND_PORT}/docs")
    logger.info(f"Log file: {LOG_FILE}")
    
    print(f"[Gədr] Running at http://127.0.0.1:{BACKEND_PORT}")
    print(f"[Gədr] API docs at http://127.0.0.1:{BACKEND_PORT}/docs")
    print(f"[Gədr] Logs: {LOG_FILE}")
    
    uvicorn.run("backend.api:app", host="0.0.0.0", port=BACKEND_PORT, log_level="warning")


def run_legacy_dashboard():
    import threading
    import webbrowser
    import streamlit.web.cli as stcli

    def _run():
        sys.argv = ["streamlit", "run", str(ROOT / "dashboard" / "app.py")]
        stcli.main()

    threading.Timer(2.0, lambda: webbrowser.open("http://127.0.0.1:8501")).start()
    _run()


def main():
    parser = argparse.ArgumentParser(description="Gədr")
    parser.add_argument("--legacy-dashboard", action="store_true",
                        help="also launch the legacy Streamlit UI on :8501")
    args = parser.parse_args()

    logger.info("=" * 70)
    logger.info("Gədr Starting")
    logger.info("=" * 70)

    # Check API key (CCI_AI_API_KEY is the canonical name; legacy
    # AI_PRIMARY_KEY is still accepted by ai.ai_agent.)
    if not (os.getenv("CCI_AI_API_KEY") or os.getenv("AI_PRIMARY_KEY")):
        logger.info("CCI_AI_API_KEY not set - AI analysis will use offline fallback")
        print("[i] CCI_AI_API_KEY not set - AI analysis will be offline (local fallback).")
        print('    Set it with:  $env:CCI_AI_API_KEY="AIza..."')
    else:
        logger.info("AI API key detected - AI analysis enabled")

    logger.debug(f"Log level: {LOG_LEVEL}")
    logger.debug(f"Backend port: {BACKEND_PORT}")
    logger.debug(f"Root directory: {ROOT}")

    if args.legacy_dashboard:
        logger.info("Starting with legacy Streamlit dashboard")
        import threading
        threading.Thread(target=run_backend, daemon=True).start()
        run_legacy_dashboard()
    else:
        logger.info("Starting backend only (modern SPA dashboard)")
        run_backend()


if __name__ == "__main__":
    main()
