"""HTTP client for BaseSentinel /scan."""

from __future__ import annotations

import re
from typing import Any

import httpx

from basesentinel_langchain.constants import (
    DEFAULT_API_BASE_URL,
    PAYMENT_PROOF_HEADER,
)
from basesentinel_langchain.errors import (
    BaseSentinelError,
    ErrorCode,
    normalize_error_code,
)

_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_TX_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")


def normalize_address(raw: str) -> str:
    value = raw.strip()
    if not _ADDRESS_RE.match(value):
        raise BaseSentinelError(
            ErrorCode.INVALID_ADDRESS_FORMAT,
            f"Invalid smart contract address: {raw}",
            http_status=400,
        )
    return value.lower()


def _strip_slash(url: str) -> str:
    return url.rstrip("/")


def probe_payment_required(
    address: str,
    *,
    api_base_url: str = DEFAULT_API_BASE_URL,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """GET /scan without proof — expect 402 + payment_info."""
    normalized = normalize_address(address)
    url = f"{_strip_slash(api_base_url)}/scan/{normalized}"
    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.get(url)
    except httpx.TimeoutException as exc:
        raise BaseSentinelError(
            ErrorCode.UPSTREAM_TIMEOUT,
            "Timed out probing BaseSentinel API",
            http_status=502,
        ) from exc
    except httpx.HTTPError as exc:
        raise BaseSentinelError(
            ErrorCode.UPSTREAM_TIMEOUT,
            f"Failed to reach BaseSentinel API: {exc}",
            http_status=502,
        ) from exc

    try:
        body: dict[str, Any] = res.json() if res.content else {}
    except ValueError as exc:
        raise BaseSentinelError(
            ErrorCode.INVALID_JSON,
            "API returned non-JSON body",
            http_status=res.status_code,
            body=res.text,
        ) from exc

    if res.status_code == 402 or body.get("error_code") == ErrorCode.PAYMENT_REQUIRED:
        info = body.get("payment_info")
        if isinstance(info, dict):
            return info
        raise BaseSentinelError(
            ErrorCode.PAYMENT_REQUIRED,
            "Payment required but payment_info missing",
            http_status=res.status_code,
            body=body,
        )

    raise BaseSentinelError(
        normalize_error_code(body.get("error_code")),
        body.get("message") or body.get("error") or f"Unexpected probe status {res.status_code}",
        http_status=res.status_code,
        payment_info=body.get("payment_info") if isinstance(body.get("payment_info"), dict) else None,
        body=body,
    )


def scan_contract(
    address: str,
    payment_proof: str,
    *,
    api_base_url: str = DEFAULT_API_BASE_URL,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Paid GET /scan/{address} with X-Payment-Proof."""
    normalized = normalize_address(address)
    proof = payment_proof.strip()
    if not _TX_RE.match(proof):
        raise BaseSentinelError(
            ErrorCode.INVALID_PROOF_FORMAT,
            "Invalid payment proof format. Expected a transaction hash (0x + 64 hex).",
            http_status=400,
        )

    url = f"{_strip_slash(api_base_url)}/scan/{normalized}"
    try:
        with httpx.Client(timeout=timeout) as client:
            res = client.get(url, headers={PAYMENT_PROOF_HEADER: proof})
    except httpx.TimeoutException as exc:
        raise BaseSentinelError(
            ErrorCode.UPSTREAM_TIMEOUT,
            "Timed out calling BaseSentinel /scan",
            http_status=502,
        ) from exc
    except httpx.HTTPError as exc:
        raise BaseSentinelError(
            ErrorCode.UPSTREAM_TIMEOUT,
            f"Failed to reach BaseSentinel API: {exc}",
            http_status=502,
        ) from exc

    try:
        body: Any = res.json() if res.content else None
    except ValueError as exc:
        raise BaseSentinelError(
            ErrorCode.INVALID_JSON,
            "API returned non-JSON body",
            http_status=res.status_code,
            body=res.text,
        ) from exc

    if not res.is_success:
        err = body if isinstance(body, dict) else {}
        code = (
            ErrorCode.PAYMENT_REQUIRED
            if res.status_code == 402
            else normalize_error_code(err.get("error_code"))
        )
        raise BaseSentinelError(
            code,
            err.get("message")
            or err.get("error")
            or f"BaseSentinel scan failed (HTTP {res.status_code})",
            http_status=res.status_code,
            payment_info=err.get("payment_info") if isinstance(err.get("payment_info"), dict) else None,
            body=body,
        )

    if not isinstance(body, dict) or "status" not in body:
        raise BaseSentinelError(
            ErrorCode.INVALID_JSON,
            "Scan response missing status",
            http_status=res.status_code,
            body=body,
        )
    return body
