"""
Authentication and Authorization tests for Gədr.
"""
import os
import time
import pytest
from unittest.mock import patch, MagicMock

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
        # Create token with 0 expiry (immediately expired)
        token = AuthHandler.create_access_token(data, expires_delta=timedelta(seconds=0))
        time.sleep(0.1)  # Wait for expiry
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
        from backend.path_security import is_safe_path
        
        # Test safe paths
        assert is_safe_path("/safe/path", ["/safe"]) is True
        
        # Test traversal attempts
        assert is_safe_path("/safe/../etc/passwd", ["/safe"]) is False
        assert is_safe_path("/safe/../../etc/passwd", ["/safe"]) is False
        assert is_safe_path("/safe/./../etc/passwd", ["/safe"]) is False


class TestRateLimit:
    def test_rate_limit_allows_normal_requests(self):
        from backend.rate_limit import RateLimiter
        
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        # Should allow 10 requests
        for _ in range(10):
            assert limiter.is_allowed("testuser") is True

    def test_rate_limit_blocks_excess_requests(self):
        from backend.rate_limit import RateLimiter
        
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        # Exhaust the limit
        for _ in range(5):
            limiter.is_allowed("testuser")
        # Should block the 6th request
        assert limiter.is_allowed("testuser") is False


class TestInputValidation:
    def test_file_size_validation(self):
        from backend.upload_validator import validate_file_size
        
        # Test within limit
        assert validate_file_size(1024, max_bytes=1024*1024) is True
        
        # Test over limit
        assert validate_file_size(1024*1024*10, max_bytes=1024*1024) is False

    def test_file_type_validation(self):
        from backend.upload_validator import validate_file_type
        
        # Test allowed types
        assert validate_file_type("test.py", [".py", ".js"]) is True
        assert validate_file_type("test.js", [".py", ".js"]) is True
        
        # Test disallowed types
        assert validate_file_type("test.exe", [".py", ".js"]) is False
        assert validate_file_type("test.bat", [".py", ".js"]) is False
