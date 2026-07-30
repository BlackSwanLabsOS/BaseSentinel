"""USDC payment on Base via web3.py (tx-hash proof settlement)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from web3 import Web3

from basesentinel_langchain.client import probe_payment_required
from basesentinel_langchain.constants import (
    DEFAULT_API_BASE_URL,
    ENV_API_BASE_URL,
    ENV_PAYMENT_PROOF,
    ENV_PRIVATE_KEY,
    ENV_RPC_URL,
    ERC20_ABI,
    SCAN_AMOUNT_ATOMIC,
    TREASURY_ADDRESS,
    USDC_ADDRESS,
)
from basesentinel_langchain.errors import BaseSentinelError, ErrorCode


@dataclass(frozen=True)
class PaymentSettlement:
    tx_hash: str
    recipient: str
    token: str
    amount_atomic: int


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def get_payment_proof_override() -> str | None:
    return _env(ENV_PAYMENT_PROOF)


def get_api_base_url(override: str | None = None) -> str:
    return (override or _env(ENV_API_BASE_URL) or DEFAULT_API_BASE_URL).rstrip("/")


def _checksum(addr: str, label: str) -> str:
    if not Web3.is_address(addr):
        raise BaseSentinelError(
            ErrorCode.PAYMENT_INVALID,
            f"Invalid {label} address: {addr}",
            http_status=422,
        )
    return Web3.to_checksum_address(addr)


def resolve_payment_terms(
    contract_address: str,
    *,
    api_base_url: str | None = None,
    skip_probe: bool = False,
) -> tuple[str, str, int, dict[str, Any] | None]:
    """Return (recipient, token, amount_atomic, payment_info)."""
    base = get_api_base_url(api_base_url)
    info: dict[str, Any] | None = None
    if not skip_probe:
        try:
            info = probe_payment_required(contract_address, api_base_url=base)
        except BaseSentinelError:
            info = None

    recipient = _checksum(
        str(info.get("recipient") if info and info.get("recipient") else TREASURY_ADDRESS),
        "recipient",
    )
    token = _checksum(
        str(info.get("token") if info and info.get("token") else USDC_ADDRESS),
        "token",
    )
    raw_amount = info.get("amount") if info else None
    if isinstance(raw_amount, str) and raw_amount.isdigit():
        amount = int(raw_amount)
    elif isinstance(raw_amount, int):
        amount = raw_amount
    else:
        amount = SCAN_AMOUNT_ATOMIC

    if amount < SCAN_AMOUNT_ATOMIC:
        raise BaseSentinelError(
            ErrorCode.INSUFFICIENT_USDC,
            f"payment_info.amount {amount} below scan minimum {SCAN_AMOUNT_ATOMIC}",
            http_status=422,
            payment_info=info,
        )
    return recipient, token, amount, info


def pay_for_scan(
    contract_address: str,
    *,
    private_key: str | None = None,
    rpc_url: str | None = None,
    api_base_url: str | None = None,
    skip_probe: bool = False,
) -> PaymentSettlement:
    """
    Transfer USDC on Base to treasury and wait for a successful receipt.
    Returns tx hash for X-Payment-Proof.
    """
    key = (private_key or _env(ENV_PRIVATE_KEY) or "").strip()
    if not key:
        raise BaseSentinelError(
            ErrorCode.PAYMENT_INVALID,
            f"Missing {ENV_PRIVATE_KEY} (runtime wallet for M2M payment)",
            http_status=400,
        )
    if not key.startswith("0x"):
        key = "0x" + key
    if len(key) != 66:
        raise BaseSentinelError(
            ErrorCode.PAYMENT_INVALID,
            f"{ENV_PRIVATE_KEY} must be 0x + 64 hex characters",
            http_status=400,
        )

    rpc = (rpc_url or _env(ENV_RPC_URL) or "https://mainnet.base.org").strip()
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        raise BaseSentinelError(
            ErrorCode.UPSTREAM_TIMEOUT,
            f"Cannot connect to Base RPC: {rpc}",
            http_status=502,
        )

    account = Account.from_key(key)
    recipient, token, amount, info = resolve_payment_terms(
        contract_address,
        api_base_url=api_base_url,
        skip_probe=skip_probe,
    )

    usdc = w3.eth.contract(address=token, abi=ERC20_ABI)
    balance = int(usdc.functions.balanceOf(account.address).call())
    if balance < amount:
        raise BaseSentinelError(
            ErrorCode.INSUFFICIENT_USDC,
            f"Wallet {account.address} has {balance} USDC atomic, need {amount}",
            http_status=422,
            payment_info=info,
        )

    nonce = w3.eth.get_transaction_count(account.address)
    tx = usdc.functions.transfer(recipient, amount).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "chainId": w3.eth.chain_id,
        }
    )
    # Let web3 fill gas; prefer EIP-1559 fields when available
    if "maxFeePerGas" not in tx and "gasPrice" not in tx:
        try:
            base_fee = w3.eth.get_block("latest").get("baseFeePerGas") or 0
            tip = w3.to_wei(0.001, "gwei")
            tx["maxPriorityFeePerGas"] = tip
            tx["maxFeePerGas"] = int(base_fee * 2) + tip
        except Exception:
            tx["gasPrice"] = w3.eth.gas_price

    if "gas" not in tx:
        tx["gas"] = w3.eth.estimate_gas(tx)

    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    try:
        tx_hash = w3.eth.send_raw_transaction(raw)
    except Exception as exc:  # noqa: BLE001 — surface as typed payment error
        message = str(exc)
        code = (
            ErrorCode.INSUFFICIENT_USDC
            if "insufficient" in message.lower()
            else ErrorCode.PAYMENT_INVALID
        )
        raise BaseSentinelError(
            code,
            message,
            http_status=422,
            payment_info=info,
        ) from exc

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt.get("status") != 1:
        raise BaseSentinelError(
            ErrorCode.PAYMENT_INVALID,
            f"USDC transfer reverted: {tx_hash.to_0x_hex() if hasattr(tx_hash, 'to_0x_hex') else w3.to_hex(tx_hash)}",
            http_status=422,
            payment_info=info,
        )

    hex_hash = (
        tx_hash.to_0x_hex()
        if hasattr(tx_hash, "to_0x_hex")
        else w3.to_hex(tx_hash)
    )
    return PaymentSettlement(
        tx_hash=hex_hash,
        recipient=recipient,
        token=token,
        amount_atomic=amount,
    )
