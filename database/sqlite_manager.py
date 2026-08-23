"""
SQLite persistence layer for Gədr.

Stores projects, scans, findings, and AI recommendations.
Thread-safe: one connection per thread via a lock-protected helper.

This file was previously named postgres_manager.py but always used
SQLite. The class is SQLiteManager; a PostgresManager alias is kept
for backward compatibility only.
"""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "cybercode.db"
_lock = threading.RLock()


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SQLiteManager:
    """Thin wrapper around SQLite providing a simple, safe CRUD API."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self):
        with _lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        hashed_password TEXT NOT NULL,
                        role TEXT DEFAULT 'user',
                        created_at TEXT DEFAULT (datetime('now'))
                    );

                    CREATE TABLE IF NOT EXISTS projects (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        language TEXT,
                        source_path TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        finished_at TEXT,
                        files_scanned INTEGER DEFAULT 0,
                        findings_count INTEGER DEFAULT 0,
                        security_score INTEGER DEFAULT 100,
                        ai_enabled INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'running',
                        summary TEXT,
                        FOREIGN KEY (project_id) REFERENCES projects(id)
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        file TEXT NOT NULL,
                        line INTEGER DEFAULT 0,
                        code TEXT DEFAULT '',
                        scanner TEXT NOT NULL,
                        rule_id TEXT,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        severity_score INTEGER NOT NULL,
                        cwe TEXT,
                        owasp TEXT,
                        description TEXT,
                        raw TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans(id)
                    );

                    CREATE TABLE IF NOT EXISTS ai_recommendations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        finding_id INTEGER NOT NULL,
                        explanation TEXT,
                        impact TEXT,
                        attack_scenario TEXT,
                        root_cause TEXT,
                        recommended_fix TEXT,
                        secure_code TEXT,
                        owasp TEXT,
                        cwe TEXT,
                        model TEXT,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (finding_id) REFERENCES findings(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                    CREATE INDEX IF NOT EXISTS idx_ai_finding ON ai_recommendations(finding_id);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------- Users -------------------------
    def create_user(self, username: str, password_hash: str, role: str = "user") -> int:
        with _lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)",
                    (username, password_hash, role),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_user(self, username: str):
        with _lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM users WHERE username=?", (username,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    # ------------------------- Projects -------------------------
    def create_project(self, name: str, language: str, source_path: str) -> str:
        pid = uuid.uuid4().hex[:12]
        with _lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO projects (id, name, language, source_path, created_at) VALUES (?,?,?,?,?)",
                    (pid, name, language, str(source_path), utcnow()),
                )
                conn.commit()
            finally:
                conn.close()
        return pid

    def get_project(self, project_id: str):
        with _lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM projects WHERE id=?", (project_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_projects(self):
        with _lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM projects ORDER BY created_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------- Scans -------------------------
    def create_scan(self, project_id: str) -> str:
        scan_id = uuid.uuid4().hex[:12]
        with _lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO scans (id, project_id, started_at, status) VALUES (?,?,?,?)",
                    (scan_id, project_id, utcnow(), "running"),
                )
                conn.commit()
            finally:
                conn.close()
        return scan_id

    def finish_scan(self, scan_id: str, files_scanned: int, score: int, ai_enabled: bool, summary: str):
        with _lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE scans SET finished_at=?, files_scanned=?, security_score=?, "
                    "ai_enabled=?, status='completed', summary=? WHERE id=?",
                    (utcnow(), files_scanned, score, int(ai_enabled), summary, scan_id),
                )
                conn.commit()
            finally:
                conn.close()

    def get_scan(self, scan_id: str):
        with _lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_scans(self, project_id: str | None = None):
        with _lock:
            conn = self._connect()
            try:
                if project_id:
                    rows = conn.execute(
                        "SELECT * FROM scans WHERE project_id=? ORDER BY started_at DESC",
                        (project_id,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM scans ORDER BY started_at DESC"
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------- Findings -------------------------
    def insert_findings(self, scan_id: str, findings: list[dict]) -> list[int]:
        ids = []
        with _lock:
            conn = self._connect()
            try:
                for f in findings:
                    cur = conn.execute(
                        "INSERT INTO findings (scan_id, file, line, code, scanner, rule_id, "
                        "title, severity, severity_score, cwe, owasp, description, raw) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            scan_id,
                            f.get("file", ""),
                            int(f.get("line", 0)),
                            f.get("code", "")[:500],
                            f.get("scanner", ""),
                            f.get("rule_id"),
                            f.get("title", ""),
                            f.get("severity", "Low"),
                            int(f.get("severity_score", 1)),
                            f.get("cwe"),
                            f.get("owasp"),
                            f.get("description"),
                            json.dumps(f.get("raw", {})),
                        ),
                    )
                    ids.append(cur.lastrowid)
                conn.execute(
                    "UPDATE scans SET findings_count=? WHERE id=?",
                    (len(findings), scan_id),
                )
                conn.commit()
            finally:
                conn.close()
        return ids

    def get_findings(self, scan_id: str, severity: str | None = None) -> list[dict]:
        with _lock:
            conn = self._connect()
            try:
                if severity:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE scan_id=? AND severity=? ORDER BY severity_score DESC",
                        (scan_id, severity),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE scan_id=? ORDER BY severity_score DESC, file, line",
                        (scan_id,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------- AI Recommendations -------------------------
    def save_ai_recommendation(self, finding_id: int, rec: dict) -> int:
        with _lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO ai_recommendations (finding_id, explanation, impact, attack_scenario, "
                    "root_cause, recommended_fix, secure_code, owasp, cwe, model, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        finding_id,
                        rec.get("explanation"),
                        rec.get("impact"),
                        rec.get("attack_scenario"),
                        rec.get("root_cause"),
                        rec.get("recommended_fix"),
                        rec.get("secure_code"),
                        rec.get("owasp"),
                        rec.get("cwe"),
                        rec.get("model"),
                        utcnow(),
                    ),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_recommendation(self, finding_id: int) -> dict | None:
        with _lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM ai_recommendations WHERE finding_id=?",
                    (finding_id,),
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    # ------------------------- Report / Stats -------------------------
    def severity_breakdown(self, scan_id: str) -> dict:
        with _lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id=? GROUP BY severity",
                    (scan_id,),
                ).fetchall()
                out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                for r in rows:
                    out[r["severity"]] = r["n"]
                return out
            finally:
                conn.close()

    def delete_project(self, project_id: str):
        with _lock:
            conn = self._connect()
            try:
                scan_ids = [
                    r["id"] for r in conn.execute(
                        "SELECT id FROM scans WHERE project_id=?", (project_id,)
                    ).fetchall()
                ]
                for sid in scan_ids:
                    conn.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
                conn.execute("DELETE FROM scans WHERE project_id=?", (project_id,))
                conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
                conn.commit()
            finally:
                conn.close()

    def clear_history(self):
        """Delete every project, scan, finding and AI recommendation."""
        with _lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM ai_recommendations")
                conn.execute("DELETE FROM findings")
                conn.execute("DELETE FROM scans")
                conn.execute("DELETE FROM projects")
                conn.commit()
            finally:
                conn.close()


# Backwards-compat alias: the file is named postgres_manager.py and many
# modules import PostgresManager, but the underlying store is SQLite.
PostgresManager = SQLiteManager
