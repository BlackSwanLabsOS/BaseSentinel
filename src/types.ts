export interface Env {
  SCAN_CACHE: KVNamespace;
  ALCHEMY_API_KEY: string;
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
