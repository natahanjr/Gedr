"""
Upload validation and security utilities for Gədr.

Prevents:
  - Oversized uploads (DoS via huge files)
  - Zip bombs and nested archives
  - Unsafe archive extraction
  - Invalid file types
  - Path traversal in archive contents
"""
import mimetypes
import tarfile
import tempfile
import zipfile
from pathlib import Path


class UploadValidationError(Exception):
    """Raised when upload validation fails."""
    pass


# Safe file types for scanning (programming languages + common formats)
SAFE_EXTENSIONS = {
    # Python
    ".py", ".pyw", ".pyi",
    # Java
    ".java",
    # C/C++
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
    # Web
    ".php", ".phtml", ".js", ".jsx", ".ts", ".tsx", ".mjs",
    ".html", ".htm", ".xhtml", ".css", ".scss", ".sass",
    # Go
    ".go",
    # Ruby
    ".rb", ".erb", ".rake", ".gemspec",
    # Rust
    ".rs",
    # C#
    ".cs",
    # Kotlin
    ".kt", ".kts",
    # Swift
    ".swift",
    # Shell
    ".sh", ".bash", ".zsh",
    # SQL
    ".sql",
    # Common configs/docs (informational)
    ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".conf",
    ".md", ".txt", ".properties",
}

# Reject these MIME types (executables, archives that bypass scanning)
BLOCKED_MIME_TYPES = {
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-msdownload",
    "application/x-dvi",
    "application/x-object",
}

# Size limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file
MAX_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50 MB total extracted
MAX_ARCHIVE_FILES = 1000  # Don't extract more than 1000 files from a zip


def validate_filename(filename: str) -> None:
    """
    Validate uploaded filename for safety.
    
    Checks:
      - Not empty
      - No path traversal sequences
      - Safe extension
      - Reasonable length
    
    Raises:
        UploadValidationError: If validation fails.
    """
    if not filename or not isinstance(filename, str):
        raise UploadValidationError("Filename must be a non-empty string")
    
    filename = filename.strip()
    if not filename:
        raise UploadValidationError("Filename cannot be empty or whitespace-only")
    
    # Prevent path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise UploadValidationError("Filename contains path traversal sequences")
    
    # Check length
    if len(filename) > 255:
        raise UploadValidationError("Filename too long (>255 characters)")
    
    # Check extension
    suffix = Path(filename).suffix.lower()
    if suffix and suffix not in SAFE_EXTENSIONS:
        raise UploadValidationError(
            f"File type '{suffix}' not allowed. "
            f"Supported: {', '.join(sorted(SAFE_EXTENSIONS))}"
        )


def validate_file_content(data: bytes, filename: str, max_size: int = MAX_FILE_SIZE) -> None:
    """
    Validate file content for safety.
    
    Checks:
      - Size limits
      - MIME type
      - Magic bytes (file signature)
    
    Raises:
        UploadValidationError: If validation fails.
    """
    if not data:
        raise UploadValidationError("File is empty")
    
    if len(data) > max_size:
        raise UploadValidationError(
            f"File too large ({len(data)} bytes > {max_size} limit)"
        )
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type and mime_type in BLOCKED_MIME_TYPES:
        raise UploadValidationError(f"MIME type '{mime_type}' not allowed")
    
    # Check magic bytes for common binary formats we want to reject
    if _is_binary_executable(data):
        raise UploadValidationError("Uploaded file appears to be a binary executable")
    
    if _is_zip_bomb(data):
        raise UploadValidationError("Uploaded file looks like a zip bomb (suspicious compression)")
    
    if _is_tar_bomb(data):
        raise UploadValidationError("Uploaded file looks like a tar bomb (suspicious compression)")


def _is_binary_executable(data: bytes) -> bool:
    """Detect common binary executable signatures."""
    if len(data) < 4:
        return False
    
    # ELF (Linux)
    if data[:4] == b"\x7fELF":
        return True
    
    # Mach-O (macOS)
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return True
    
    # PE (Windows .exe, .dll)
    if data[:2] == b"MZ":
        return True
    
    # Java class file
    if data[:4] == b"\xca\xfe\xba\xbe":
        return True
    
    # .NET assembly
    if data[:4] == b"\x00\x01\x00\x00":
        return True
    
    # Script with shebang (but allow Python/Shell scripts we want to scan)
    if data[:2] == b"#!":
        first_line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace")
        # Block dangerous interpreters but allow Python/Shell
        dangerous = ["bash", "sh", "zsh", "csh", "ksh"]
        for interp in dangerous:
            if f"/{interp}" in first_line:
                return True
    
    return False


def _is_zip_bomb(data: bytes) -> bool:
    """Detect suspicious compression ratios (zip bomb indicator)."""
    if len(data) < 4 or data[:2] != b"PK":  # Not a zip
        return False
    
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(data)
            tmp_path = f.name
        
        try:
            with zipfile.ZipFile(tmp_path, "r") as zf:
                # Check compression ratio
                total_compressed = len(data)
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                
                if total_uncompressed > 0:
                    ratio = total_uncompressed / total_compressed
                    # Suspicious if ratio > 100x (legitimate archives rarely exceed 50x)
                    if ratio > 100:
                        return True
                
                # Check file count
                if len(zf.infolist()) > MAX_ARCHIVE_FILES:
                    return True
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    except (zipfile.BadZipFile, Exception):
        # Not a valid zip or other error - not a bomb
        pass
    
    return False


def _is_tar_bomb(data: bytes) -> bool:
    """Detect suspicious tar archives (tar bomb indicator)."""
    # Check for tar magic bytes (ustar at offset 257)
    if len(data) < 263:
        return False
    
    # Check tar magic: "ustar" at offset 257
    tar_magic = data[257:262]
    if tar_magic != b"ustar":
        return False
    
    try:
        import io
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            total_compressed = len(data)
            total_uncompressed = sum(member.size for member in tf.getmembers())
            
            if total_uncompressed > 0:
                ratio = total_uncompressed / total_compressed
                # Suspicious if ratio > 100x
                if ratio > 100:
                    return True
            
            # Check file count
            if len(tf.getmembers()) > MAX_ARCHIVE_FILES:
                return True
            
            # Check for suspicious entries (absolute paths, /dev/zero, etc.)
            for member in tf.getmembers():
                if member.name.startswith("/") or member.name.startswith(".."):
                    return True
                if member.size > 100 * 1024 * 1024:  # Single file > 100MB
                    return True
    except (tarfile.TarError, Exception):
        pass
    
    return False


def safe_extract_archive(archive_path: Path, extract_to: Path | None = None) -> Path:
    """
    Safely extract a zip/tar archive, preventing traversal attacks.
    
    Args:
        archive_path: Path to the archive file.
        extract_to: Destination directory (created if doesn't exist).
        
    Returns:
        Path to extraction directory.
        
    Raises:
        UploadValidationError: If extraction is unsafe.
    """
    if not archive_path.exists():
        raise UploadValidationError(f"Archive not found: {archive_path}")
    
    extract_to = extract_to or Path(tempfile.mkdtemp(prefix="cci_extract_"))
    extract_to.mkdir(parents=True, exist_ok=True)
    
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            # Validate all member paths before extraction
            for member in zf.infolist():
                # Prevent path traversal
                member_path = (extract_to / member.filename).resolve()
                if not str(member_path).startswith(str(extract_to.resolve())):
                    raise UploadValidationError(
                        f"Archive contains path traversal: {member.filename}"
                    )
                
                # Prevent symlinks to unsafe locations (check external_attr for symlink flag)
                # Unix symlink: external_attr >> 16 & 0o170000 == 0o120000
                if member.external_attr and (member.external_attr >> 16 & 0o170000) == 0o120000:
                    raise UploadValidationError(
                        f"Archive contains symlink (not supported): {member.filename}"
                    )
            
            # Extract safely
            zf.extractall(path=extract_to)
    except zipfile.BadZipFile:
        raise UploadValidationError("Invalid or corrupted zip file")
    
    return extract_to


def validate_upload(
    filename: str,
    file_data: bytes,
    max_file_size: int = MAX_FILE_SIZE,
) -> None:
    """
    Complete upload validation pipeline.
    
    Runs all checks in sequence:
      1. Filename validation
      2. File content validation
      3. Size checks
    
    Raises:
        UploadValidationError: If any check fails.
    """
    validate_filename(filename)
    validate_file_content(file_data, filename, max_file_size)
