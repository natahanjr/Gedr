#!/bin/bash
# CyberCode Inspector — One-Click Start (Linux / macOS)
# Reads credentials from .env in the project root.

set -e

cd "$(dirname "$0")/.."

# Load .env if present
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# Check for API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "[!] GEMINI_API_KEY not set in .env — AI analysis will use offline fallback"
fi

# Check Python
PYTHON=""
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
elif [ -f ".venv/bin/python3" ]; then
    PYTHON=".venv/bin/python3"
elif [ -f "/tmp/cci-venv/bin/python3" ]; then
    PYTHON="/tmp/cci-venv/bin/python3"
else
    PYTHON="python3"
fi

echo "[*] CyberCode Inspector starting..."
echo "    Backend: http://127.0.0.1:8000"
echo "    AI svc:  http://127.0.0.1:8002"

# Start AI microservice
echo "[AI] Starting AI microservice..."
cd "$(dirname "$0")/.."
GEMINI_API_KEY="$GEMINI_API_KEY" GEMINI_MODEL="$GEMINI_MODEL" \
    "$PYTHON" start_ai.py &
AI_PID=$!

# Wait for AI service
sleep 3
curl -sf http://127.0.0.1:8002/ai/health > /dev/null 2>&1 && echo "[AI] Ready" || echo "[AI] Starting (may take a few seconds...)"

# Start backend
echo "[BE] Starting backend..."
cd "$(dirname "$0")/.."
GEMINI_API_KEY="$GEMINI_API_KEY" \
SECRET_KEY="$SECRET_KEY" \
CCI_BACKEND_PORT=8000 \
CCI_AI_URL="http://127.0.0.1:8002" \
    "$PYTHON" main.py &
BE_PID=$!

# Wait for backend
sleep 3
curl -sf http://127.0.0.1:8000/api/health > /dev/null 2>&1 && echo "[BE] Ready" || echo "[BE] Starting..."

echo ""
echo "============================================================"
echo "  CyberCode Inspector is running!"
echo "  Dashboard: http://127.0.0.1:8000"
echo "  Press Ctrl+C to stop all services"
echo "============================================================"

# Open browser (if available)
if command -v xdg-open > /dev/null 2>&1; then
    xdg-open http://127.0.0.1:8000 2>/dev/null &
elif command -v open > /dev/null 2>&1; then
    open http://127.0.0.1:8000 2>/dev/null &
fi

# Wait for both processes
wait
