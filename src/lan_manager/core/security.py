"""Security services: password hashing, RBAC authorization, HMAC signing, and audit sanitization."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from lan_manager.domain.enums.system_enums import RoleType
from lan_manager.domain.exceptions import PermissionDeniedError

try:
    import bcrypt

    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False


_ROLE_WEIGHTS: dict[RoleType, int] = {
    RoleType.VIEWER: 10,
    RoleType.TECHNICIAN: 20,
    RoleType.OPERATOR: 30,
    RoleType.ADMIN: 40,
}

_SENSITIVE_METADATA_KEYS = {
    "password",
    "password_hash",
    "secret",
    "shared_secret",
    "token",
    "private_key",
    "snmp_community",
    "authorization",
    "credential",
}


@dataclass(frozen=True)
class UserSessionContext:
    """Represents the authenticated operator performing an action."""

    user_id: UUID | None
    username: str
    full_name: str
    role: RoleType
    client_host: str = "127.0.0.1"

    def has_minimum_role(self, required_role: RoleType) -> bool:
        return _ROLE_WEIGHTS.get(self.role, 0) >= _ROLE_WEIGHTS.get(required_role, 100)


def require_role(
    context: UserSessionContext | None, minimum_role: RoleType, action_name: str
) -> None:
    """Enforce RBAC permissions at the application/service layer."""
    if context is None:
        raise PermissionDeniedError(f"Yêu cầu xác thực người dùng để thực hiện '{action_name}'.")
    if not context.has_minimum_role(minimum_role):
        raise PermissionDeniedError(
            f"Tài khoản '{context.username}' (vai trò {context.role.value}) không đủ quyền "
            f"thực hiện '{action_name}'. Yêu cầu tối thiểu: {minimum_role.value}."
        )


def hash_password(plain_password: str) -> str:
    """Hash a user password using bcrypt (or scrypt fallback). Never stores plaintext."""
    if not plain_password or len(plain_password) < 8:
        raise ValueError("Mật khẩu phải có độ dài tối thiểu 8 ký tự.")

    if _HAS_BCRYPT:
        hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        return f"bcrypt${hashed.decode('utf-8')}"

    salt = secrets.token_hex(16)
    derived = hashlib.scrypt(
        plain_password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt${salt}${derived.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Constant-time verification of a password against its stored hash."""
    if not plain_password or not stored_hash:
        return False

    try:
        if stored_hash.startswith("bcrypt$") and _HAS_BCRYPT:
            raw_bcrypt = stored_hash.split("bcrypt$", 1)[1].encode("utf-8")
            return bool(bcrypt.checkpw(plain_password.encode("utf-8"), raw_bcrypt))

        if stored_hash.startswith("$2b$") and _HAS_BCRYPT:
            return bool(bcrypt.checkpw(plain_password.encode("utf-8"), stored_hash.encode("utf-8")))

        if stored_hash.startswith("scrypt$"):
            _, salt, expected_hex = stored_hash.split("$", 2)
            derived = hashlib.scrypt(
                plain_password.encode("utf-8"),
                salt=salt.encode("utf-8"),
                n=16384,
                r=8,
                p=1,
                dklen=32,
            )
            return hmac.compare_digest(derived.hex(), expected_hex)
    except Exception:
        return False
    return False


def sanitize_audit_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Recursively scrub sensitive keys from metadata before writing to audit logs."""
    if not metadata:
        return {}

    cleaned: dict[str, Any] = {}
    for key, value in metadata.items():
        normalized_key = str(key).strip().lower()
        if any(secret_word in normalized_key for secret_word in _SENSITIVE_METADATA_KEYS):
            cleaned[key] = "***REDACTED***"
        elif isinstance(value, dict):
            cleaned[key] = sanitize_audit_metadata(value)
        elif isinstance(value, list):
            cleaned[key] = [
                sanitize_audit_metadata(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            cleaned[key] = value
    return cleaned


def sign_agent_payload(
    shared_secret: str,
    task_type: str,
    target_ip: str,
    parameters: dict[str, Any],
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Create an anti-replay HMAC-SHA256 signed envelope for remote agent tasks."""
    if not shared_secret:
        raise ValueError("Chưa cấu hình REMOTE_AGENT_SHARED_SECRET để ký xác thực tác vụ từ xa.")

    ts = timestamp if timestamp is not None else int(time.time())
    request_nonce = nonce or secrets.token_hex(16)
    canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    signing_input = f"{ts}:{request_nonce}:{task_type}:{target_ip}:{canonical_params}"
    signature = hmac.new(
        shared_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "task_type": task_type,
        "target_ip": target_ip,
        "parameters": parameters,
        "timestamp": ts,
        "nonce": request_nonce,
        "signature": signature,
    }


def verify_agent_signature(
    shared_secret: str,
    envelope: dict[str, Any],
    max_skew_seconds: int = 60,
    seen_nonces: set[str] | None = None,
) -> bool:
    """Verify HMAC-SHA256 signature, timestamp freshness, and replay nonce."""
    if not shared_secret:
        return False
    try:
        ts = int(envelope["timestamp"])
        nonce = str(envelope["nonce"])
        task_type = str(envelope["task_type"])
        target_ip = str(envelope["target_ip"])
        parameters = envelope.get("parameters") or {}
        provided_sig = str(envelope["signature"])
    except (KeyError, TypeError, ValueError):
        return False

    now = int(time.time())
    if abs(now - ts) > max_skew_seconds:
        return False

    if seen_nonces is not None:
        if nonce in seen_nonces:
            return False
        seen_nonces.add(nonce)

    canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    signing_input = f"{ts}:{nonce}:{task_type}:{target_ip}:{canonical_params}"
    expected_sig = hmac.new(
        shared_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(provided_sig, expected_sig)
