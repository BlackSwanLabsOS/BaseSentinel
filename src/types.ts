export interface Env {
  SCAN_CACHE: KVNamespace;
  ALCHEMY_API_KEY: string;
  /** Treasury wallet receiving USDC payments. */
  PAYMENT_ADDRESS: string;
  /** Admin key for diagnostics endpoints (X-Admin-Key). */
  ADMIN_API_KEY: string;
  /** Chain: `base` (production) or `base-sepolia` (local tests). */
  NETWORK: string;
  /** Optional Discord webhook for threat alerts. */
  DISCORD_WEBHOOK_URL?: string;
}
