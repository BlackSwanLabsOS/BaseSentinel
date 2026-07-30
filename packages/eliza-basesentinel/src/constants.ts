/** Production BaseSentinel API (no trailing slash). */
export const DEFAULT_API_BASE_URL = "https://api.blackswanlabs.pl";

/** Base mainnet chain id. */
export const BASE_CHAIN_ID = 8453;

/** Circle USDC on Base (6 decimals). */
export const USDC_ADDRESS =
  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as const;

/** BaseSentinel treasury (PAYMENT_ADDRESS). */
export const TREASURY_ADDRESS =
  "0x21360A04853b85a8d2E918b73f97C8ccf5939946" as const;

/** Scan product: 0.005 USDC = 5000 atomic units. */
export const SCAN_AMOUNT_ATOMIC = 5000n;
export const SCAN_AMOUNT_DISPLAY = "0.005 USDC";

export const PAYMENT_PROOF_HEADER = "X-Payment-Proof";

/** Runtime / env keys (M2M config — never shown to the LLM). */
export const ENV = {
  apiBaseUrl: "BASESENTINEL_API_BASE_URL",
  privateKey: "BASESENTINEL_PRIVATE_KEY",
  paymentProof: "BASESENTINEL_PAYMENT_PROOF",
  rpcUrl: "BASESENTINEL_RPC_URL",
} as const;
