"""Shared BaseSentinel constants (Base mainnet)."""

from __future__ import annotations

DEFAULT_API_BASE_URL = "https://api.blackswanlabs.pl"
BASE_CHAIN_ID = 8453
USDC_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TREASURY_ADDRESS = "0x21360A04853b85a8d2E918b73f97C8ccf5939946"
SCAN_AMOUNT_ATOMIC = 5000  # 0.005 USDC (6 decimals)
SCAN_AMOUNT_DISPLAY = "0.005 USDC"
PAYMENT_PROOF_HEADER = "X-Payment-Proof"

ENV_API_BASE_URL = "BASESENTINEL_API_BASE_URL"
ENV_PRIVATE_KEY = "BASESENTINEL_PRIVATE_KEY"
ENV_PAYMENT_PROOF = "BASESENTINEL_PAYMENT_PROOF"
ENV_RPC_URL = "BASESENTINEL_RPC_URL"

# Minimal ERC-20 ABI for transfer + balanceOf
ERC20_ABI = [
    {
        "name": "transfer",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "decimals",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
]
