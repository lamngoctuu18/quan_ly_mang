"""Authenticated HTTPS + HMAC-SHA256 anti-replay remote agent client and verifier."""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from lan_manager.core.config import AppConfig, get_config
from lan_manager.core.logging_config import get_logger
from lan_manager.core.security import sign_agent_payload, verify_agent_signature
from lan_manager.domain.enums.system_enums import TaskType
from lan_manager.domain.exceptions import RemoteExecutionError, TaskNotAllowedError

logger = get_logger(__name__)

ALLOWED_AGENT_TASKS: frozenset[str] = frozenset(t.value for t in TaskType)


class AgentRequestVerifier:
    """
    Server-side validator for the Python Remote Agent.
    Ensures:
    1. Only predefined TaskType allowlist keys are accepted (never arbitrary shell commands).
    2. HMAC-SHA256 signature and timestamp freshness (<= 60s) are verified.
    3. Replay nonces are rejected.
    """

    def __init__(self, shared_secret: str, max_skew_seconds: int = 60) -> None:
        self._shared_secret = shared_secret
        self._max_skew_seconds = max_skew_seconds
        self._seen_nonces: set[str] = set()

    def validate_envelope(self, envelope: dict[str, Any]) -> tuple[TaskType, dict[str, Any]]:
        task_key = str(envelope.get("task_type") or "")
        if task_key not in ALLOWED_AGENT_TASKS:
            raise TaskNotAllowedError(
                f"Agent từ chối tác vụ không nằm trong Allowlist: '{task_key}'."
            )

        if not verify_agent_signature(
            shared_secret=self._shared_secret,
            envelope=envelope,
            max_skew_seconds=self._max_skew_seconds,
            seen_nonces=self._seen_nonces,
        ):
            raise RemoteExecutionError(
                "Xác thực chữ ký HMAC hoặc kiểm tra chống phát lại (Anti-Replay) thất bại."
            )

        params = envelope.get("parameters")
        if not isinstance(params, dict):
            params = {}
        # Reject any unexpected command/shell injection fields
        forbidden_keys = {"cmd", "command", "shell", "script", "powershell", "exec"}
        if forbidden_keys.intersection(k.lower() for k in params):
            raise TaskNotAllowedError("Từ chối tham số chứa từ khóa thực thi lệnh tùy ý.")

        return TaskType(task_key), params


class AuthenticatedAgentClient:
    """
    HTTPS client for dispatching allowlisted administrative tasks to remote LAN workstations
    running the authenticated LAN Printer Manager Agent.
    """

    def __init__(self, config: AppConfig | None = None) -> None:
        self._config = config or get_config()

    def execute_remote_task(
        self,
        target_ip: str,
        task_type: TaskType,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a signed allowlisted task request to https://<target_ip>:<port>/api/v1/tasks/execute."""
        validated_ip = str(ipaddress.ip_address(str(target_ip).strip()))
        if task_type.value not in ALLOWED_AGENT_TASKS:
            raise TaskNotAllowedError(f"Tác vụ '{task_type}' không nằm trong danh mục cho phép.")

        if not self._config.remote_agent_shared_secret:
            raise RemoteExecutionError(
                "Chưa cấu hình REMOTE_AGENT_SHARED_SECRET trong .env để xác thực với Agent từ xa."
            )

        envelope = sign_agent_payload(
            shared_secret=self._config.remote_agent_shared_secret,
            task_type=task_type.value,
            target_ip=validated_ip,
            parameters=parameters or {},
        )
        body_bytes = json.dumps(envelope).encode("utf-8")
        url = f"https://{validated_ip}:{self._config.remote_agent_port}/api/v1/tasks/execute"

        req = urllib.request.Request(
            url=url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "X-LAN-Manager-Signature": str(envelope["signature"]),
                "X-LAN-Manager-Nonce": str(envelope["nonce"]),
            },
            method="POST",
        )

        ssl_ctx = ssl.create_default_context()
        if not self._config.remote_agent_verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(  # noqa: S310
                req, timeout=self._config.remote_agent_timeout_sec, context=ssl_ctx
            ) as resp:
                resp_body = resp.read().decode("utf-8")
                parsed: dict[str, Any] = json.loads(resp_body)
                return parsed
        except urllib.error.HTTPError as exc:
            raise RemoteExecutionError(
                f"Agent tại {validated_ip} trả về mã lỗi HTTP {exc.code}."
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteExecutionError(
                f"Không thể kết nối tới Agent quản trị tại {validated_ip}:{self._config.remote_agent_port} ({exc})."
            ) from exc
