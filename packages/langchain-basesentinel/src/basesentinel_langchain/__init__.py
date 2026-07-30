"""LangChain integration for BaseSentinel (M2M USDC tx-hash settlement)."""

from basesentinel_langchain.client import (
    normalize_address,
    probe_payment_required,
    scan_contract,
)
from basesentinel_langchain.constants import (
    DEFAULT_API_BASE_URL,
    SCAN_AMOUNT_ATOMIC,
    SCAN_AMOUNT_DISPLAY,
    TREASURY_ADDRESS,
    USDC_ADDRESS,
)
from basesentinel_langchain.errors import BaseSentinelError, ErrorCode
from basesentinel_langchain.payer import (
    PaymentSettlement,
    get_api_base_url,
    get_payment_proof_override,
    pay_for_scan,
    resolve_payment_terms,
)
from basesentinel_langchain.summary import summarize_scan_result
from basesentinel_langchain.tool import BaseSentinelScanInput, BaseSentinelScanTool

__all__ = [
    "BaseSentinelScanTool",
    "BaseSentinelScanInput",
    "BaseSentinelError",
    "ErrorCode",
    "scan_contract",
    "probe_payment_required",
    "normalize_address",
    "pay_for_scan",
    "resolve_payment_terms",
    "get_payment_proof_override",
    "get_api_base_url",
    "PaymentSettlement",
    "summarize_scan_result",
    "DEFAULT_API_BASE_URL",
    "USDC_ADDRESS",
    "TREASURY_ADDRESS",
    "SCAN_AMOUNT_ATOMIC",
    "SCAN_AMOUNT_DISPLAY",
]

__version__ = "0.1.0"
