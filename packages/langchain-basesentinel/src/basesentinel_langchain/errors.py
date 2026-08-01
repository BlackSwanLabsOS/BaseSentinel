"""Stable BaseSentinel API error_code contract."""

from __future__ import annotations

from typing import Any


class ErrorCode:
    PAYMENT_REQUIRED = "PAYMENT_REQUIRED"
    INVALID_ADDRESS_FORMAT = "INVALID_ADDRESS_FORMAT"
    INVALID_PROOF_FORMAT = "INVALID_PROOF_FORMAT"
    TX_HASH_CONSUMED = "TX_HASH_CONSUMED"
    TX_HASH_BOUND_OTHER = "TX_HASH_BOUND_OTHER"
    INSUFFICIENT_USDC = "INSUFFICIENT_USDC"
    PAYMENT_INVALID = "PAYMENT_INVALID"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    KV_LIMIT_EXCEEDED = "KV_LIMIT_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    PAYMENT_EXPIRED = "PAYMENT_EXPIRED"
    TX_HASH_BUSY = "TX_HASH_BUSY"
    INVALID_JSON = "INVALID_JSON"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"

    ALL = frozenset(
        {
            PAYMENT_REQUIRED,
            INVALID_ADDRESS_FORMAT,
            INVALID_PROOF_FORMAT,
            TX_HASH_CONSUMED,
            TX_HASH_BOUND_OTHER,
            INSUFFICIENT_USDC,
            PAYMENT_INVALID,
            UPSTREAM_TIMEOUT,
            KV_LIMIT_EXCEEDED,
            RATE_LIMITED,
            PAYMENT_EXPIRED,
            TX_HASH_BUSY,
            INVALID_JSON,
            METHOD_NOT_ALLOWED,
            NOT_FOUND,
            UNKNOWN,
        }
    )


def normalize_error_code(raw: Any) -> str:
    if isinstance(raw, str) and raw in ErrorCode.ALL:
        return raw
    return ErrorCode.UNKNOWN


class BaseSentinelError(Exception):
    """Typed API / payment failure. Prefer returning tool strings to agents;
    raise when calling the library programmatically.
    """

    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        http_status: int = 0,
        payment_info: dict[str, Any] | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.error_code = normalize_error_code(error_code)
        self.message = message
        self.http_status = http_status
        self.payment_info = payment_info
        self.body = body

    def to_agent_message(self) -> str:
        """Machine-readable failure line for ReAct agents (does not crash)."""
        return (
            f"BASESENTINEL_ERROR error_code={self.error_code} "
            f"http_status={self.http_status} message={self.message}"
        )
