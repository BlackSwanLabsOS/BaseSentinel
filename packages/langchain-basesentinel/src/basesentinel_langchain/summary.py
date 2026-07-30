"""LLM-facing scan summary (no payment details)."""

from __future__ import annotations

from typing import Any


def summarize_scan_result(result: dict[str, Any]) -> str:
    address = result.get("address") or "unknown"
    status = result.get("status") or "UNKNOWN"
    verdict = result.get("verdict") or "UNKNOWN"
    score = result.get("verdict_score", "?")
    reasons = result.get("reasons")
    if isinstance(reasons, list):
        reason_text = ", ".join(str(r) for r in reasons if r) or "None"
    else:
        reason_text = "None"
    return (
        f"Contract {address} is {status} ({verdict}). "
        f"Score: {score}/100. Reasons: {reason_text}"
    )
