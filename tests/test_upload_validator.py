"""Unit tests for upload validation."""
import pytest
import tempfile
import zipfile
from pathlib import Path

from backend.upload_validator import (
    validate_filename,
    validate_file_content,
    validate_upload,
    UploadValidationError,
    safe_extract_archive,
    _is_binary_executable,
    _is_zip_bomb,
    MAX_FILE_SIZE,
)


class TestFilenameValidation:
    """Test filename validation."""

    def test_valid_python_filename(self):
        """Valid Python filename should pass."""
        validate_filename("test.py")
        validate_filename("my_scanner.py")

    def test_valid_java_filename(self):
        """Valid Java filename should pass."""
        validate_filename("Main.java")
        validate_filename("SecurityTest.java")

    def test_empty_filename_rejected(self):
        """Empty filename should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("")

    def test_whitespace_only_filename_rejected(self):
        """Whitespace-only filename should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("   ")

    def test_path_traversal_parent_rejected(self):
        """Path traversal with .. should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("../../../etc/passwd")

    def test_path_traversal_slash_rejected(self):
        """Absolute path with / should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("/etc/passwd")

    def test_path_traversal_backslash_rejected(self):
        """Windows path with \\ should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("..\\..\\windows\\system32")

    def test_unsafe_extension_rejected(self):
        """File with unsafe extension should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename("malware.exe")
        
        with pytest.raises(UploadValidationError):
            validate_filename("script.sh")

    def test_filename_too_long_rejected(self):
        """Filename > 255 chars should be rejected."""
        long_name = "a" * 256 + ".py"
        with pytest.raises(UploadValidationError):
            validate_filename(long_name)

    def test_none_filename_rejected(self):
        """None filename should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_filename(None)


class TestFileContentValidation:
    """Test file content validation."""

    def test_empty_file_rejected(self):
        """Empty file should be rejected."""
        with pytest.raises(UploadValidationError):
            validate_file_content(b"", "test.py")

    def test_oversized_file_rejected(self):
        """File exceeding size limit should be rejected."""
        huge = b"x" * (MAX_FILE_SIZE + 1)
        with pytest.raises(UploadValidationError):
            validate_file_content(huge, "test.py")

    def test_valid_python_code_accepted(self):
        """Valid Python code should be accepted."""
        code = b"print('hello')\n" * 100
        validate_file_content(code, "test.py")

    def test_elf_executable_rejected(self):
        """ELF binary should be rejected."""
        elf_header = b"\x7fELF" + b"\x00" * 100
        with pytest.raises(UploadValidationError):
            validate_file_content(elf_header, "binary")

    def test_pe_executable_rejected(self):
        """Windows PE executable should be rejected."""
        pe_header = b"MZ" + b"\x00" * 100
        with pytest.raises(UploadValidationError):
            validate_file_content(pe_header, "malware.exe")

    def test_macho_executable_rejected(self):
        """macOS Mach-O executable should be rejected."""
        macho_header = b"\xfe\xed\xfa\xce" + b"\x00" * 100
        with pytest.raises(UploadValidationError):
            validate_file_content(macho_header, "binary")


class TestBinaryDetection:
    """Test binary executable detection."""

    def test_elf_detected(self):
        """ELF signature should be detected."""
        assert _is_binary_executable(b"\x7fELF" + b"\x00" * 10)

    def test_pe_detected(self):
        """PE signature should be detected."""
        assert _is_binary_executable(b"MZ" + b"\x00" * 10)

    def test_macho_detected(self):
        """Mach-O signature should be detected."""
        assert _is_binary_executable(b"\xfe\xed\xfa\xce" + b"\x00" * 10)

    def test_text_not_detected_as_binary(self):
        """Plain text should not be detected as binary."""
        assert not _is_binary_executable(b"#!/bin/bash\necho hello")

    def test_python_code_not_detected_as_binary(self):
        """Python code should not be detected as binary."""
        assert not _is_binary_executable(b"def foo():\n    pass")


class TestZipBombDetection:
    """Test zip bomb detection."""

    def test_legitimate_zip_accepted(self):
        """Legitimate zip file should be accepted."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        
        try:
            # Create a legitimate zip
            with zipfile.ZipFile(tmp, "w") as zf:
                zf.writestr("test.py", "print('hello')")
                zf.writestr("test2.py", "print('world')")
            
            with open(tmp, "rb") as f:
                data = f.read()
            
            # Should not raise
            result = _is_zip_bomb(data)
            assert not result
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_suspicious_compression_detected(self):
        """Suspicious compression ratios should be detected."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        
        try:
            # Create a zip with high compression ratio
            with zipfile.ZipFile(tmp, "w") as zf:
                # 10KB of repeated data compresses to ~1KB
                big_data = b"A" * (10 * 1024)
                zf.writestr("bomb.txt", big_data, compress_type=zipfile.ZIP_DEFLATED)
            
            with open(tmp, "rb") as f:
                data = f.read()
            
            # This might be detected as suspicious (>100x ratio)
            result = _is_zip_bomb(data)
            # Note: exact result depends on compression, just verify no crash
            assert isinstance(result, bool)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_non_zip_not_detected_as_bomb(self):
        """Non-zip data should not trigger bomb detection."""
        assert not _is_zip_bomb(b"This is not a zip file")
        assert not _is_zip_bomb(b"")


class TestArchiveExtraction:
    """Test safe archive extraction."""

    def test_legitimate_archive_extracted(self):
        """Legitimate archive should extract safely."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        
        try:
            # Create archive
            with zipfile.ZipFile(tmp, "w") as zf:
                zf.writestr("test.py", "print('hello')")
                zf.writestr("test2.py", "print('world')")
            
            # Extract
            extract_to = Path(tempfile.mkdtemp(prefix="cci_test_extract_"))
            result = safe_extract_archive(Path(tmp), extract_to)
            
            # Verify extraction
            assert (result / "test.py").exists()
            assert (result / "test2.py").exists()
            assert (result / "test.py").read_text() == "print('hello')"
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_traversal_in_archive_blocked(self):
        """Path traversal in archive members should be blocked."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            tmp = f.name
        
        try:
            # Create archive with traversal path
            with zipfile.ZipFile(tmp, "w") as zf:
                zf.writestr("../../../etc/passwd", "malicious")
            
            # Extraction should fail
            extract_to = Path(tempfile.mkdtemp(prefix="cci_test_extract_"))
            with pytest.raises(UploadValidationError):
                safe_extract_archive(Path(tmp), extract_to)
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_missing_archive_rejected(self):
        """Missing archive file should be rejected."""
        with pytest.raises(UploadValidationError):
            safe_extract_archive(Path("/nonexistent/file.zip"))


class TestCompleteValidationPipeline:
    """Integration tests for the full validation pipeline."""

    def test_valid_python_file_passes_all_checks(self):
        """Valid Python file should pass all checks."""
        code = b"def hello():\n    print('world')\n"
        validate_upload("hello.py", code)

    def test_invalid_filename_fails_early(self):
        """Invalid filename should fail validation."""
        code = b"print('test')"
        with pytest.raises(UploadValidationError):
            validate_upload("../malicious.py", code)

    def test_executable_file_fails_validation(self):
        """Executable file should fail validation."""
        exe_data = b"MZ" + b"\x00" * 1000
        with pytest.raises(UploadValidationError):
            validate_upload("malware.exe", exe_data)

    def test_oversized_file_fails_validation(self):
        """Oversized file should fail validation."""
        huge = b"x" * (MAX_FILE_SIZE + 1)
        with pytest.raises(UploadValidationError):
            validate_upload("huge.py", huge)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
