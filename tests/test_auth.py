"""
Authentication and Authorization tests for Gədr.
"""
import os
import time
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

# Set SECRET_KEY before importing auth module
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-only-32chars!")

from backend.auth import AuthHandler, get_current_user


class TestPasswordHashing:
    def test_hash_password(self):
        password = "testpassword123"
        hashed = AuthHandler.get_password_hash(password)
        assert hashed != password
        assert len(hashed) > 0

    def test_verify_password_correct(self):
        password = "testpassword123"
        hashed = AuthHandler.get_password_hash(password)
        assert AuthHandler.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        password = "testpassword123"
        hashed = AuthHandler.get_password_hash(password)
        assert AuthHandler.verify_password("wrongpassword", hashed) is False

    def test_different_hashes_for_same_password(self):
        password = "testpassword123"
        hash1 = AuthHandler.get_password_hash(password)
        hash2 = AuthHandler.get_password_hash(password)
        assert hash1 != hash2  # bcrypt uses random salt


class TestJWT:
    def test_create_access_token(self):
        data = {"sub": "testuser", "role": "user"}
        token = AuthHandler.create_access_token(data)
        assert token is not None
        assert len(token) > 0

    def test_decode_valid_token(self):
        data = {"sub": "testuser", "role": "user"}
        token = AuthHandler.create_access_token(data)
        payload = AuthHandler.decode_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["role"] == "user"

    def test_decode_expired_token(self):
        data = {"sub": "testuser", "role": "user"}
        # exp is stored at whole-second resolution, so a 0-second delta
        # is boundary-flaky; use a clearly-past expiry instead.
        token = AuthHandler.create_access_token(data, expires_delta=timedelta(seconds=-5))
        payload = AuthHandler.decode_token(token)
        assert payload is None

    def test_decode_invalid_token(self):
        payload = AuthHandler.decode_token("invalid.token.here")
        assert payload is None

    def test_decode_token_without_subject(self):
        # Create token without 'sub' claim
        data = {"role": "user"}
        token = AuthHandler.create_access_token(data)
        payload = AuthHandler.decode_token(token)
        assert payload is None


class TestPathSecurity:
    def test_path_traversal_prevention(self):
        from backend.path_security import validate_scan_path, PathSecurityError

        # Traversal attempts must be rejected even when they would
        # resolve to an existing location.
        for bad in ("/safe/../etc/passwd", "/safe/../../etc/passwd", "/safe/./../etc/passwd"):
            with pytest.raises(PathSecurityError):
                validate_scan_path(bad, allow_absolute=True)

    def test_relative_traversal_rejected(self):
        from backend.path_security import validate_scan_path, PathSecurityError

        with pytest.raises(PathSecurityError):
            validate_scan_path("subdir/../../etc", allow_absolute=True)


class TestRateLimit:
    def _request(self, ip="10.0.0.1"):
        req = MagicMock()
        req.headers = {}
        req.client.host = ip
        return req

    def test_rate_limit_allows_normal_requests(self):
        from backend import rate_limit

        # Should allow up to `limit` requests from one client
        for _ in range(10):
            allowed, _info = rate_limit.check(10, self._request())
            assert allowed is True

    def test_rate_limit_blocks_excess_requests(self):
        from backend import rate_limit

        # Exhaust the limit
        for _ in range(5):
            rate_limit.check(5, self._request(ip="10.0.0.2"))
        # Should block the 6th request
        allowed, info = rate_limit.check(5, self._request(ip="10.0.0.2"))
        assert allowed is False
        assert "retry_after" in info


class TestInputValidation:
    def test_file_size_validation(self):
        from backend.upload_validator import validate_file_content, UploadValidationError, MAX_FILE_SIZE

        # Within limit: no error
        validate_file_content(b"x" * 1024, "test.py")

        # Over limit: rejected
        with pytest.raises(UploadValidationError):
            validate_file_content(b"x" * (MAX_FILE_SIZE + 1), "test.py")

    def test_file_type_validation(self):
        from backend.upload_validator import validate_filename, UploadValidationError

        # Allowed types
        validate_filename("test.py")
        validate_filename("test.js")

        # Disallowed types
        with pytest.raises(UploadValidationError):
            validate_filename("test.exe")
        with pytest.raises(UploadValidationError):
            validate_filename("test.bat")
