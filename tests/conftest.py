"""Pytest configuration for the Gədr test suite.

Ensures the repository root is importable no matter how pytest is
invoked (pytest -q, pytest tests/test_auth.py, IDE runners, CI), so
`from backend... / from ai...` imports always resolve.

Also isolates tests from the real database: CCI_DB_PATH is pointed at
a per-run temp file BEFORE backend.api is imported, so API-level tests
never read or write the developer's cybercode.db.
"""
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# Isolate the database before any test module imports backend.api
# (database/sqlite_manager.py reads CCI_DB_PATH at import time).
_TEST_DB_DIR = tempfile.mkdtemp(prefix="gedr_test_db_")
os.environ["CCI_DB_PATH"] = os.path.join(_TEST_DB_DIR, "test.db")
# Keep SECRET_KEY deterministic for JWT tests
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only-32chars!")
