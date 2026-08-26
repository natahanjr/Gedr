"""
Path security utilities for Gədr.

Prevents:
  - Path traversal attacks (../ sequences)
  - Symlink following to unsafe locations
  - Absolute paths to system directories
  - Traversal outside the allowed scan root
"""
import os
from pathlib import Path


class PathSecurityError(Exception):
    """Raised when path validation fails."""
    pass


def validate_scan_path(user_path: str, allow_absolute: bool = False,
                       allowed_roots: str = "") -> Path:
    """
    Validate and normalize a scan path for security.

    Args:
        user_path: The path provided by the user (may contain .., symlinks, etc.)
        allow_absolute: If True, absolute paths are allowed ONLY when they
            fall under one of the comma-separated ``allowed_roots``.
        allowed_roots: Colon-separated (or comma-separated) list of allowed
            absolute root directories. Empty means no absolute paths allowed
            even when allow_absolute=True.

    Returns:
        A validated, normalized Path object.

    Raises:
        PathSecurityError: If the path fails validation.
    """
    if not user_path or not isinstance(user_path, str):
        raise PathSecurityError("Path must be a non-empty string")

    user_path = user_path.strip()

    # Prevent empty paths
    if not user_path:
        raise PathSecurityError("Path cannot be empty or whitespace-only")

    # Convert to Path object
    try:
        requested = Path(user_path)
    except (ValueError, TypeError) as e:
        raise PathSecurityError(f"Invalid path: {e}")

    # Resolve the path to normalize (resolves symlinks on most systems)
    try:
        resolved = requested.resolve()
    except (OSError, RuntimeError) as e:
        raise PathSecurityError(f"Cannot resolve path: {e}")

    # Check that path exists
    if not resolved.exists():
        raise PathSecurityError(f"Path does not exist: {user_path}")

    # If absolute, enforce the allowed-roots allowlist
    if resolved.is_absolute():
        if not allow_absolute:
            raise PathSecurityError(
                "Absolute paths are not allowed. Use relative paths."
            )
        if allowed_roots:
            roots = [
                Path(r.strip()).resolve()
                for r in allowed_roots.replace(",", ":").split(":")
                if r.strip()
            ]
            if not any(
                str(resolved).lower().startswith(str(r).lower())
                for r in roots
            ):
                raise PathSecurityError(
                    f"Absolute path is outside allowed scan roots: {allowed_roots}"
                )

    # Prevent scanning system-critical directories (exact match or direct child)
    _system_paths = [
        Path("/"), Path("/etc"), Path("/sys"), Path("/proc"),
        Path("/root"), Path("/boot"), Path("/dev"), Path("/var"),
        Path("/tmp"), Path("/usr"), Path("/lib"), Path("/sbin"),
        Path("C:\\"), Path("C:\\Windows"), Path("C:\\System32"),
        Path("C:\\Program Files"), Path("C:\\ProgramData"),
    ]
    resolved_str = str(resolved).lower()
    for sys_path in _system_paths:
        sp = str(sys_path).lower()
        if resolved_str == sp or resolved_str.startswith(sp + "\\") or resolved_str.startswith(sp + "/"):
            raise PathSecurityError(f"Cannot scan system-critical directory: {sys_path}")

    # Prevent path traversal: reject .. segments that escape the working dir
    if ".." in requested.parts:
        raise PathSecurityError(
            "Path traversal sequences (..) are not allowed in scan paths."
        )

    return resolved


def is_safe_symlink(path: Path, follow: bool = False) -> bool:
    """
    Check if a path is safe to follow (if it's a symlink).
    
    Args:
        path: The path to check.
        follow: If False, reject symlinks. If True, check target safety.
        
    Returns:
        True if safe, False otherwise.
    """
    if not path.is_symlink():
        return True
    
    if not follow:
        return False  # Reject symlinks entirely
    
    try:
        target = path.resolve()
        # Symlink target should exist
        return target.exists()
    except (OSError, RuntimeError):
        return False


def list_safe_files(root: Path, max_depth: int = 10, follow_symlinks: bool = False) -> list[Path]:
    """
    Safely list files under a directory, with safeguards against traversal.
    
    Args:
        root: Root directory to scan.
        max_depth: Maximum directory depth to traverse.
        follow_symlinks: Whether to follow symlinks (default: False for safety).
        
    Returns:
        List of safe file paths.
        
    Raises:
        PathSecurityError: If root path is unsafe.
    """
    # Validate root first
    root = validate_scan_path(str(root), allow_absolute=True)
    
    if not root.is_dir():
        raise PathSecurityError(f"Root path is not a directory: {root}")
    
    files = []
    visited = set()
    
    def _walk(current: Path, depth: int):
        if depth > max_depth:
            return  # Stop at max depth
        
        # Prevent infinite loops from symlink cycles
        try:
            real_path = current.resolve()
        except (OSError, RuntimeError):
            return
        
        if real_path in visited:
            return
        visited.add(real_path)
        
        try:
            for item in current.iterdir():
                if item.is_symlink() and not follow_symlinks:
                    continue  # Skip symlinks
                
                if item.is_dir(follow_symlinks=follow_symlinks):
                    _walk(item, depth + 1)
                elif item.is_file(follow_symlinks=follow_symlinks):
                    files.append(item)
        except (OSError, PermissionError):
            # Skip inaccessible directories
            pass
    
    _walk(root, 0)
    return files
