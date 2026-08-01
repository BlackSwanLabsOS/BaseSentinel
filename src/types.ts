export interface Env {
  SCAN_CACHE: KVNamespace;
  ALCHEMY_API_KEY: string;
  /**
   * Optional discovery RPC override: one URL or comma-separated pool
   * (tried first, then built-in public Base failover list).
   * Example: "https://mainnet.base.org,https://1rpc.io/base"
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
   * Optional Discord webhook for ops-only alerts (#ops-logs):
   * cron errors, fatal failures, stale discovery — not routine listings.
   */
  DISCORD_OPS_WEBHOOK_URL?: string;
  /**
   * Optional Discord webhook for scam autopsy posts (publisher may also use
   * a local DISCORD_AUTOPSY_WEBHOOK_URL outside the Worker).
   */
  DISCORD_AUTOPSY_WEBHOOK_URL?: string;
  /**
   * Per-tx payment redeem lock. Serializes first consume so concurrent
   * requests cannot double-spend the same proof (KV has no CAS).
   */
  PAYMENT_LOCK: DurableObjectNamespace;
}
