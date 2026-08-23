"""
Gədr — One-Click Launcher (Cross-Platform)

Starts both the backend API and the AI microservice with one command.

Usage:
    python run.py                  # start both services
    python run.py --backend-only   # start only the backend
    python run.py --ai-only        # start only the AI microservice
    python run.py --port 8001      # custom backend port
"""
import os
import sys
import subprocess
import time
import webbrowser
import signal
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# --- Config ---
BACKEND_PORT = os.getenv("CCI_BACKEND_PORT", "8000")
AI_PORT = "8002"
AI_URL = f"http://127.0.0.1:{AI_PORT}"

# Find Python executable (prefer project venv, fall back to system)
def find_python() -> str | None:
    if platform.system() == "Windows":
        candidates = [
            ROOT / ".venv" / "Scripts" / "python.exe",
            ROOT / ".venv" / "Scripts" / "python",
        ]
    else:
        candidates = [
            ROOT / ".venv" / "bin" / "python3",
            ROOT / ".venv" / "bin" / "python",
            Path("/tmp/cci-venv") / "bin" / "python3",
        ]
    for c in candidates:
        if c.exists():
            return str(c)
    return sys.executable

PYTHON = find_python()

# --- Colors ---
class C:
    OK = "\033[92m" if sys.stdout.isatty() else ""
    WARN = "\033[93m" if sys.stdout.isatty() else ""
    ERR = "\033[91m" if sys.stdout.isatty() else ""
    BOLD = "\033[1m" if sys.stdout.isatty() else ""
    END = "\033[0m" if sys.stdout.isatty() else ""


def print_banner():
    print(f"""
{C.BOLD}{'=' * 60}
  Gədr — One-Click Launcher
{'=' * 60}{C.END}
  Backend : http://127.0.0.1:{BACKEND_PORT}
  AI svc  : http://127.0.0.1:{AI_PORT}
  Python  : {PYTHON}
""")


def wait_for_url(url: str, timeout: float = 30.0) -> bool:
    import urllib.request
    start = time.time()
    while time.time() - start < timeout:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def start_ai_service() -> subprocess.Popen | None:
    env = os.environ.copy()
    env.setdefault("AI_PRIMARY_KEY", "")
    env.setdefault("AI_PRIMARY_MODEL", "")

    cmd = [PYTHON, str(ROOT / "start_ai.py")]
    print(f"{C.OK}[AI]{C.END} Starting AI microservice on port {AI_PORT}...")

    try:
        kw = dict(cwd=str(ROOT), env=env,
                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if platform.system() == "Windows":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(cmd, **kw)
    except Exception as e:
        print(f"{C.ERR}[AI]{C.END} Failed to start: {e}")
        return None

    if wait_for_url(f"http://127.0.0.1:{AI_PORT}/ai/health", timeout=30):
        print(f"{C.OK}[AI]{C.END} Microservice ready at {AI_URL}")
        return proc
    else:
        print(f"{C.WARN}[AI]{C.END} Microservice started but health check timed out — continuing without AI")
        return proc


def start_backend() -> subprocess.Popen | None:
    env = os.environ.copy()
    env.setdefault("AI_PRIMARY_KEY", "")
    env.setdefault("SECRET_KEY", "")
    env["CCI_BACKEND_PORT"] = BACKEND_PORT
    env["CCI_AI_URL"] = AI_URL

    cmd = [PYTHON, str(ROOT / "main.py")]
    print(f"{C.OK}[BE]{C.END} Starting backend on port {BACKEND_PORT}...")

    try:
        kw = dict(cwd=str(ROOT), env=env,
                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if platform.system() == "Windows":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(cmd, **kw)
    except Exception as e:
        print(f"{C.ERR}[BE]{C.END} Failed to start: {e}")
        return None

    if wait_for_url(f"http://127.0.0.1:{BACKEND_PORT}/api/health", timeout=30):
        print(f"{C.OK}[BE]{C.END} Backend ready at http://127.0.0.1:{BACKEND_PORT}")
        return proc
    else:
        print(f"{C.ERR}[BE]{C.END} Backend did not start within 30s")
        return proc


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Gədr Launcher")
    parser.add_argument("--backend-only", action="store_true")
    parser.add_argument("--ai-only", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    global BACKEND_PORT
    BACKEND_PORT = str(args.port)
    print_banner()

    procs = []

    if not args.backend_only:
        ai = start_ai_service()
        if ai:
            procs.append(ai)

    if not args.ai_only:
        be = start_backend()
        if be:
            procs.append(be)
        else:
            print(f"{C.ERR}[!]{C.END} Backend failed. Check errors above.")
            sys.exit(1)

    if not procs:
        print(f"{C.ERR}[!]{C.END} No services started.")
        sys.exit(1)

    print(f"\n{C.BOLD}{'=' * 60}{C.END}")
    print(f"  {C.OK}All services running!{C.END}")
    print(f"  Dashboard: {C.BOLD}http://127.0.0.1:{BACKEND_PORT}{C.END}")
    print(f"  Press {C.BOLD}Ctrl+C{C.END} to stop all services.")
    print(f"{'=' * 60}\n")

    if not args.no_browser:
        time.sleep(1)
        webbrowser.open(f"http://127.0.0.1:{BACKEND_PORT}")

    def shutdown(*_):
        print(f"\n\n{C.WARN}[!]{C.END} Shutting down...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                pass
        print(f"{C.OK}[done]{C.END}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, shutdown)

    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
