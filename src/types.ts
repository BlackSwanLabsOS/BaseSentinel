export interface Env {
  SCAN_CACHE: KVNamespace;
  ALCHEMY_API_KEY: string;
  /**
   * Optional dedicated RPC for mass eth_getLogs / discovery reads.
   * Default: https://mainnet.base.org (or Sepolia public).
   */
  LOGS_RPC_URL?: string;
  /**
   * Optional override for payment/critical RPC.
   * Default: Alchemy via ALCHEMY_API_KEY (no public fallback).
   */
  CRITICAL_RPC_URL?: string;
  /** Treasury wallet receiving USDC payments. */
  PAYMENT_ADDRESS: string;
  /** Admin key for diagnostics + payment smoke bypass (`X-Admin-Key` / `X-Admin-Secret`). */
  ADMIN_API_KEY: string;
  /** Chain: `base` (production) or `base-sepolia` (local tests). */
  NETWORK: string;
  /** Optional Discord webhook for threat alerts. */
  DISCORD_WEBHOOK_URL?: string;
  /**
   * Optional Discord webhook for ops-only discovery logs (no SCAM noise).
   * Create a separate channel webhook e.g. #ops-logs.
   */
  DISCORD_OPS_WEBHOOK_URL?: string;
}
