export interface Env {
  SCAN_CACHE: KVNamespace;
  ALCHEMY_API_KEY: string;
  /** Wallet address that should receive M2M scan payments (USDC). */
  PAYMENT_ADDRESS: string;
  /** Shared secret for admin threat-intel endpoints (X-Admin-Key). */
  ADMIN_API_KEY: string;
  /**
   * Active chain: "base-sepolia" (default) or "base".
   * Controls Alchemy RPC + USDC contract used for payment verification.
   */
  NETWORK: string;
}
