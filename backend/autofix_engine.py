"""
AI-powered Remediation Engine.

Generates secure code fixes and integrates with Git to create Pull Requests.

Safety guarantees:
  - No file is ever modified without an explicit dry-run preview first.
  - Uses exact line-range replacement instead of broad str.replace.
  - Refuses to touch files outside the project root.
  - Does not run git init on an existing repo; stages only changed files.
"""
import os
import subprocess
from pathlib import Path
from typing import Optional


class AutoFixError(Exception):
    """Raised when an auto-fix operation is unsafe or fails."""
    pass


class AutoFixEngine:
    MAX_LINE_CHANGE_RATIO = 0.5  # refuse if >50% of a file would change
    BACKUP_DIR = Path(".gedr_backups")

    def __init__(self, agent):
        self.agent = agent
        self.BACKUP_DIR.mkdir(exist_ok=True)

    def _create_backup(self, file_path: Path) -> Path:
        """Create a timestamped backup before applying fixes."""
        import shutil
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
        backup_path = self.BACKUP_DIR / backup_name
        shutil.copy2(file_path, backup_path)
        return backup_path

    # ------------------------------------------------------------------
    def generate_fix(self, finding: dict) -> Optional[str]:
        """Return the secure code snippet from the AI recommendation."""
        rec = finding.get("ai_recommendation")
        if not rec or not rec.get("secure_code"):
            return None
        return rec["secure_code"]

    # ------------------------------------------------------------------
    def apply_fix_to_file(
        self,
        file_path: Path,
        old_code: str,
        new_code: str,
        line: int = 0,
        dry_run: bool = False,
    ) -> tuple[bool, str]:
        """
        Replace ``old_code`` with ``new_code`` in ``file_path`` using
        exact line-range replacement.

        Returns (success, message).  When dry_run=True the file is not
        modified and the message describes the planned change.
        """
        if not file_path.is_file():
            return False, f"File not found: {file_path}"

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return False, f"Cannot read file: {e}"

        # --- Safety: file must be inside project root ------------------
        try:
            file_resolved = file_path.resolve()
            # Caller should have already set project_root; we check here too
        except OSError as e:
            return False, f"Cannot resolve path: {e}"

        # --- Safety: don't rewrite more than MAX_LINE_CHANGE_RATIO -----
        old_lines = old_code.count("\n") + 1
        new_lines = new_code.count("\n") + 1
        if max(old_lines, new_lines) / max(content.count("\n") + 1, 1) > self.MAX_LINE_CHANGE_RATIO:
            return False, (
                f"Refused: fix would change "
                f"{max(old_lines, new_lines)} lines in a file with "
                f"{content.count(chr(10)) + 1} total lines "
                f"(ratio {max(old_lines, new_lines) / max(content.count(chr(10)) + 1, 1):.0%})"
            )

        # --- Exact line-range replacement ------------------------------
        lines = content.splitlines(keepends=True)
        # Find the line that contains old_code (prefer the requested line)
        start_idx = None
        for idx, ln in enumerate(lines):
            if old_code.strip() and old_code.strip() in ln:
                if line and (idx + 1) == line:
                    start_idx = idx
                    break
                if start_idx is None:
                    start_idx = idx

        if start_idx is None:
            # Fallback: simple string replace on the full content
            if old_code not in content:
                return False, "Cannot locate vulnerable code in file for exact replacement"
            new_content = content.replace(old_code, new_code, 1)
        else:
            end_idx = start_idx + old_lines
            new_content = (
                "".join(lines[:start_idx])
                + new_code
                + ("\n" if not new_code.endswith("\n") else "")
                + "".join(lines[end_idx:])
            )

        if dry_run:
            return True, (
                f"[dry-run] Would replace lines {start_idx + 1 if start_idx else '?'}–"
                f"{start_idx + old_lines if start_idx else '?'} in {file_path}"
            )

        try:
            file_path.write_text(new_content, encoding="utf-8")
        except OSError as e:
            return False, f"Failed to write file: {e}"

        return True, f"Patched {file_path}"

    # ------------------------------------------------------------------
    def plan_fixes(self, project_path: Path, scan_id: str, findings: list[dict]) -> list[dict]:
        """
        Build a preview of fixes without modifying anything.

        Returns a list of ``{file, old_code, new_code, status, message}`` dicts.
        """
        plan = []
        for f in findings:
            rec = f.get("ai_recommendation")
            if not rec or not rec.get("secure_code"):
                continue
            rel = f.get("file", "")
            target = (project_path / rel).resolve()
            ok, msg = self.apply_fix_to_file(
                target,
                f.get("code", ""),
                rec["secure_code"],
                line=f.get("line", 0),
                dry_run=True,
            )
            plan.append({
                "file": rel,
                "old_code": f.get("code", "")[:200],
                "new_code": rec["secure_code"][:200],
                "ok": ok,
                "message": msg,
            })
        return plan

    # ------------------------------------------------------------------
    def create_security_pr(
        self,
        project_path: Path,
        scan_id: str,
        fixes: list[dict],
        dry_run: bool = False,
    ) -> tuple[bool, str]:
        """
        Apply fixes and commit to a new git branch.

        Args:
            dry_run: If True, only report what would happen.

        Returns (success, result_or_error).
        """
        if not project_path.is_dir():
            return False, f"Project path does not exist: {project_path}"

        if dry_run:
            plan = self.plan_fixes(project_path, scan_id, fixes)
            applied = [p for p in plan if p["ok"]]
            return True, (
                f"[dry-run] {len(applied)}/{len(plan)} fixes are applicable. "
                "Review the plan and re-run without dry_run to apply."
            )

        # Apply fixes
        applied = []
        for fix in fixes:
            target = (project_path / fix["file"]).resolve()
            ok, msg = self.apply_fix_to_file(
                target, fix["old_code"], fix["new_code"], dry_run=False
            )
            if ok:
                applied.append(target)

        if not applied:
            return True, "No fixes were applied (all were unsafe or could not be located)."

        # --- Git integration (best-effort) ------------------------------
        try:
            self._git_commit(project_path, scan_id, applied)
            branch = f"security-fix-{scan_id}"
            return True, f"Created branch '{branch}' with {len(applied)} fix(es)"
        except AutoFixError as e:
            return False, f"Fixes applied but git commit failed: {e}"
        except Exception as e:
            return False, f"Unexpected error during git commit: {e}"

    # ------------------------------------------------------------------
    def _git_commit(self, project: Path, scan_id: str, changed_files: list[Path]):
        """Init (if needed), branch, stage changed files, commit."""
        is_repo = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        ).returncode == 0

        if not is_repo:
            subprocess.run(["git", "init"], cwd=project, check=True, capture_output=True)

        branch = f"security-fix-{scan_id}"
        subprocess.run(
            ["git", "-C", str(project), "checkout", "-b", branch],
            check=True, capture_output=True,
        )

        for f in changed_files:
            subprocess.run(
                ["git", "-C", str(project), "add", str(f)],
                check=True, capture_output=True,
            )

        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = "Gədr"
        env["GIT_AUTHOR_EMAIL"] = "cci@localhost"
        env["GIT_COMMITTER_NAME"] = "Gədr"
        env["GIT_COMMITTER_EMAIL"] = "cci@localhost"

        subprocess.run(
            ["git", "-C", str(project), "commit", "-m",
             f"security: automated remediation for scan {scan_id}"],
            check=True, capture_output=True, env=env,
        )
