"""
Authentication and Authorization for Gədr.
"""
import logging
import os
import secrets as _secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = _secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY not set — using auto-generated key. "
        "Set SECRET_KEY in .env for persistent token validation."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Token blacklist (in-memory; survives across requests but not restarts)
_token_blacklist: set[str] = set()


class AuthHandler:
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        to_encode["jti"] = _secrets.token_hex(16)
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("jti") in _token_blacklist:
                return None
            return payload if payload.get("sub") else None
        except JWTError:
            return None

    @staticmethod
    def revoke_token(token: str):
        """Add a token's jti to the blacklist so it can no longer be used."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            if payload.get("jti"):
                _token_blacklist.add(payload["jti"])
        except JWTError:
            pass

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = AuthHandler.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


async def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)),
):
    """Return the current user if a valid token is supplied, otherwise None.

    Used by endpoints that should be authenticated in production
    but stay reachable without a token for local development.
    Controlled by CCI_PUBLIC_SCAN_MODE: when "true" the endpoint is
    fully open; when "false" (default) a token is required.
    """
    public_mode = os.getenv("CCI_PUBLIC_SCAN_MODE", "false").lower() in (
        "1", "true", "yes", "on",
    )
    if public_mode:
        return None
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Set CCI_PUBLIC_SCAN_MODE=true "
                   "to allow anonymous access (development only).",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = AuthHandler.decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload
