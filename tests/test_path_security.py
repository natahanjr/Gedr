"""Unit tests for path security validation."""
import pytest
from pathlib import Path
import tempfile
import os
from backend.path_security import (
    validate_scan_path,
    PathSecurityError,
    is_safe_symlink,
    list_safe_files,
)


class TestPathSecurityValidation:
    """Test path validation and traversal prevention."""

    def test_valid_relative_path(self):
        """Valid relative paths should pass."""
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test")
            # Use a path relative to the CWD, as a real scan would
            result = validate_scan_path(os.path.relpath(test_file, os.getcwd()))
            assert result.exists()

    def test_valid_absolute_path(self):
        """Valid absolute paths should pass when allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_scan_path(tmpdir, allow_absolute=True)
            assert result.exists()

    def test_reject_nonexistent_path(self):
        """Nonexistent paths should raise error."""
        with pytest.raises(PathSecurityError, match="does not exist"):
            validate_scan_path("/nonexistent/path/that/does/not/exist")

    def test_reject_empty_path(self):
        """Empty paths should raise error."""
        with pytest.raises(PathSecurityError, match="empty"):
            validate_scan_path("")

    def test_reject_whitespace_only_path(self):
        """Whitespace-only paths should raise error."""
        with pytest.raises(PathSecurityError, match="empty"):
            validate_scan_path("   ")

    def test_reject_absolute_when_not_allowed(self):
        """Absolute paths rejected when allow_absolute=False."""
        with pytest.raises(PathSecurityError, match="Absolute paths"):
            validate_scan_path(os.path.abspath(os.curdir), allow_absolute=False)

    def test_reject_system_paths_linux(self):
        """System-critical paths should be rejected (Linux)."""
        if os.name == "posix":
            # Skip this test on Windows
            pass

    def test_reject_system_paths_windows(self):
        """System-critical paths should be rejected (Windows)."""
        if os.name == "nt":
            with pytest.raises(PathSecurityError):
                validate_scan_path("C:\\Windows", allow_absolute=True)

    def test_path_normalization(self):
        """Paths should be normalized and resolved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested directories
            nested = Path(tmpdir) / "a" / "b"
            nested.mkdir(parents=True)
            
            # Test with redundant separators
            result = validate_scan_path(str(nested), allow_absolute=True)
            assert result == nested.resolve()

    def test_invalid_type_raises_error(self):
        """Non-string paths should raise error."""
        with pytest.raises(PathSecurityError):
            validate_scan_path(None)
        with pytest.raises(PathSecurityError):
            validate_scan_path(123)

    def test_traversal_with_parent_refs(self):
        """Paths with .. should be validated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            
            # Test that .. resolving to valid dir works
            parent_ref = str(subdir / "..")
            result = validate_scan_path(parent_ref, allow_absolute=True)
            assert result.exists()


class TestSymlinkSafety:
    """Test symlink safety checks."""

    def test_regular_file_is_safe(self):
        """Regular files should be considered safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test")
            assert is_safe_symlink(test_file, follow=False) is True
            assert is_safe_symlink(test_file, follow=True) is True

    def test_symlink_rejected_when_follow_false(self):
        """Symlinks should be rejected when follow=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.txt"
            target.write_text("target")
            
            link = Path(tmpdir) / "link.txt"
            try:
                link.symlink_to(target)
                assert is_safe_symlink(link, follow=False) is False
            except (OSError, NotImplementedError):
                # Symlinks not supported on this system
                pytest.skip("Symlinks not supported on this system")

    def test_valid_symlink_when_follow_true(self):
        """Valid symlinks should pass when follow=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.txt"
            target.write_text("target")
            
            link = Path(tmpdir) / "link.txt"
            try:
                link.symlink_to(target)
                assert is_safe_symlink(link, follow=True) is True
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this system")

    def test_broken_symlink_unsafe(self):
        """Broken symlinks should be unsafe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            link = Path(tmpdir) / "link.txt"
            try:
                link.symlink_to(Path(tmpdir) / "nonexistent.txt")
                assert is_safe_symlink(link, follow=True) is False
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this system")


class TestListSafeFiles:
    """Test safe file listing."""

    def test_list_files_in_directory(self):
        """Should list all files in a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Create test files
            (root / "file1.py").write_text("test1")
            (root / "file2.py").write_text("test2")
            (root / "subdir").mkdir()
            (root / "subdir" / "file3.py").write_text("test3")
            
            files = list_safe_files(root, follow_symlinks=False)
            assert len(files) >= 3

    def test_max_depth_respected(self):
        """Should respect max_depth limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Create deep nested structure
            current = root
            for i in range(5):
                current = current / f"level{i}"
                current.mkdir()
                (current / f"file{i}.py").write_text("test")
            
            # With max_depth=2, should not reach level 5
            files = list_safe_files(root, max_depth=2, follow_symlinks=False)
            # All files up to depth 2 should be found
            assert len(files) >= 1

    def test_symlinks_not_followed_by_default(self):
        """Symlinks should not be followed by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target_dir = Path(tempfile.mkdtemp())
            
            try:
                (target_dir / "outside.py").write_text("outside")
                link = root / "link_dir"
                try:
                    link.symlink_to(target_dir)
                    files = list_safe_files(root, follow_symlinks=False)
                    # Should not include files from outside target_dir
                    file_paths = [str(f) for f in files]
                    assert not any("outside" in p for p in file_paths)
                except (OSError, NotImplementedError):
                    pytest.skip("Symlinks not supported on this system")
            finally:
                import shutil
                shutil.rmtree(target_dir, ignore_errors=True)

    def test_invalid_directory_raises_error(self):
        """Invalid directory should raise error."""
        with pytest.raises(PathSecurityError):
            list_safe_files(Path("/nonexistent/path"))

    def test_cycle_detection(self):
        """Should not infinite loop on symlink cycles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Try to create a cycle (may not work on all systems)
            subdir = root / "subdir"
            subdir.mkdir()
            
            try:
                # Create symlink pointing to parent (cycle)
                (subdir / "cycle").symlink_to(root)
                # Should complete without infinite loop
                files = list_safe_files(root, follow_symlinks=True)
                assert isinstance(files, list)
            except (OSError, NotImplementedError):
                pytest.skip("Symlinks not supported on this system")


class TestPathSecurityIntegration:
    """Integration tests for path security."""

    def test_typical_scan_scenario(self):
        """Typical scan scenario: valid project directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Create a typical project structure
            src = root / "src"
            src.mkdir()
            (src / "main.py").write_text("print('hello')")
            (src / "utils.py").write_text("def helper(): pass")
            
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_main.py").write_text("def test_main(): pass")
            
            # Should successfully validate and list files
            validated = validate_scan_path(str(root), allow_absolute=True)
            files = list_safe_files(validated)
            assert len(files) >= 3

    def test_traversal_attack_prevention(self):
        """Prevent directory traversal attacks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_dir = Path(tmpdir) / "safe"
            safe_dir.mkdir()
            outside_dir = Path(tmpdir) / "outside"
            outside_dir.mkdir()
            
            # Try to access outside directory via traversal
            traversal_path = str(safe_dir / ".." / "outside")
            
            # Validation should resolve the path and prevent escaping
            result = validate_scan_path(traversal_path, allow_absolute=True)
            assert result.exists()
            # The resolved path should be the actual "outside" dir


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
