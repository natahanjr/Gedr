"""Launcher for the AI microservice."""
import sys
import os

# Ensure project root is on the path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# Set default env if needed
os.environ.setdefault("AI_PRIMARY_MODEL", "")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "ai_service.main:app",
        host="0.0.0.0",
        port=8002,
        log_level="warning",
    )
