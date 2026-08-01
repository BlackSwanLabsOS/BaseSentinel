/**
 * Autopsy metrics v1 — estimate rules + copy guardrails.
 *
 * Facts are computed on-chain after a SCAM flag ages ≥24h.
 * Copy must never claim exact "stolen" amounts from deployer balance.
 */

import { isAaInfrastructureAddress } from "../config/aaInfrastructure";

/** Minimum age of a SCAM flag before autopsy runs. */
export const AUTOPSY_MIN_AGE_MS = 24 * 60 * 60 * 1000;

/** Max SCAM contracts processed per daily batch (RPC thrift). */
export const AUTOPSY_MAX_PER_RUN = 20;

/** How often the autopsy batch may run (shared minute cron throttle). */
export const AUTOPSY_INTERVAL_MS = 24 * 60 * 60 * 1000;

/** Look back at most this many day-indexes for candidates. */
export const AUTOPSY_DAY_LOOKBACK = 3;

/** Cap eth_getLogs span per contract (~2s Base blocks). */
export const AUTOPSY_MAX_BLOCK_SPAN = 50_000;

/** Approx Base blocks per hour (~2s). */
export const BASE_BLOCKS_PER_HOUR = 1_800;

/** ERC-20 Transfer(address,address,uint256) */
export const ERC20_TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/** Uniswap V2 Pair Burn(address,uint256,uint256,address) */
export const PAIR_BURN_TOPIC0 =
  "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496";

export type AutopsyReportStatus = "ready" | "published" | "skipped";

export type AutopsySkipReason =
  | "aa_infrastructure"
  | "empty_or_eoa"
  | "not_scam";

export interface AutopsyActivityEstimate {
  /**
   * Count of ERC-20 Transfer logs on the scam token after the flag block.
   * Proxy for post-flag trading / distribution activity — not USD stolen.
   */
  token_transfer_count: number | null;
  /**
   * WETH Transfer logs where `to` is the listing pair (buy-side pressure),
   * summed in wei. Null when pair unknown or RPC failed.
   */
  weth_to_pair_wei: string | null;
  /**
   * USDC Transfer logs where `to` is the listing pair, summed in atomic units.
   */
  usdc_to_pair_atomic: string | null;
  /** True when ≥1 Uniswap V2 Burn was observed on the listing pair after flag. */
  lp_burn_observed: boolean | null;
  /** Human note always present for publishers / LLM. */
  caveat: string;
}

export interface AutopsyReport {
  schema: "basesentinel.autopsy.v1";
  address: string;
  network: string;
  status: AutopsyReportStatus;
  flagged_at: string;
  autopsy_at: string;
  age_hours: number;
  risk_score: number;
  reasons: string[];
  listing: {
    source: string | null;
    pair: string | null;
    paired_with: string | null;
    tx_hash: string | null;
    block_number: number | null;
  };
  creator_address: string | null;
  owner_address: string | null;
  activity: AutopsyActivityEstimate;
  /** Basescan URL for humans. */
  explorer_url: string;
  /** Short machine blurb — safe for Discord without LLM. */
  facts_summary: string;
  published_at?: string;
  /** Set when autopsy skipped (AA infra / empty EOA) — not for publish. */
  skip_reason?: AutopsySkipReason;
}

/**
 * Hard rules for any human / LLM post built from an AutopsyReport.
 * Enforce in marketing-agent system prompt and Discord fallbacks.
 */
export const AUTOPSY_COPY_GUARDRAILS = [
  "Never claim an exact amount 'stolen' or 'rug pulled in USD' unless activity fields explicitly support an estimate — and then say approximate / estimate.",
  "Never use eth_getBalance of the deployer as proof of theft.",
  "Prefer: hours since BaseSentinel SCAM flag, detection reasons, post-flag transfer activity, LP burn observed.",
  "Do not shame victims; frame as protection for agents that query /scan before trade.",
  "CTA may mention 0.005 USDC /scan and https://api.blackswanlabs.pl — no hype adjectives.",
  "If token_transfer_count and pair volumes are null/zero, omit dollar figures entirely.",
  "Never autopsy or publish AA EntryPoint/bundler addresses or empty/EOA 'contracts' as scam tokens.",
] as const;

export const AUTOPSY_ACTIVITY_CAVEAT =
  "Post-flag activity is an on-chain estimate (token transfers + WETH/USDC inflow to listing pair + optional LP burn). Not a forensic accounting of funds stolen.";

/** When dossier has no listing pair — pair volume / LP burn cannot be estimated. */
export const AUTOPSY_NO_PAIR_CAVEAT =
  "No listing pair in dossier — WETH/USDC pair inflow and LP burn were not estimated. Token Transfer logs may still be present.";

/** Reasons that mean "not a tradable scam token" — skip autopsy / publish. */
const AUTOPSY_SKIP_REASON_CODES = new Set([
  "Empty_Contract",
  "Empty_Or_EOA_No_Bytecode",
]);

/**
 * Autopsy is for SCAM *tokens* with real bytecode surface — not AA bundlers / empty EOAs.
 * Returns skip reason, or null when eligible.
 */
export function getAutopsySkipReason(record: {
  address: string;
  status?: string;
  reasons?: readonly string[];
  bytecodeLength?: number;
}): AutopsySkipReason | null {
  if ((record.status ?? "SAFE") !== "SCAM") {
    return "not_scam";
  }
  if (isAaInfrastructureAddress(record.address)) {
    return "aa_infrastructure";
  }
  const reasons = record.reasons ?? [];
  if (reasons.some((r) => AUTOPSY_SKIP_REASON_CODES.has(r))) {
    return "empty_or_eoa";
  }
  if (
    typeof record.bytecodeLength === "number" &&
    record.bytecodeLength <= 2
  ) {
    return "empty_or_eoa";
  }
  return null;
}

export function autopsyReportKey(address: string): string {
  return `autopsy:report:${address.toLowerCase()}`;
}

export function autopsyDoneKey(address: string): string {
  return `autopsy:done:${address.toLowerCase()}`;
}

export const AUTOPSY_PENDING_KEY = "autopsy:pending";
export const AUTOPSY_STATE_KEY = "autopsy:state";

export function formatWeiAsEth(wei: string | null): string | null {
  if (!wei) return null;
  try {
    const v = BigInt(wei);
    const whole = v / 10n ** 18n;
    const frac = v % 10n ** 18n;
    const fracStr = frac.toString().padStart(18, "0").slice(0, 4);
    return `${whole}.${fracStr}`;
  } catch {
    return null;
  }
}

export function formatUsdcAtomic(atomic: string | null): string | null {
  if (!atomic) return null;
  try {
    const v = BigInt(atomic);
    const whole = v / 10n ** 6n;
    const frac = v % 10n ** 6n;
    const fracStr = frac.toString().padStart(6, "0").slice(0, 2);
    return `${whole}.${fracStr}`;
  } catch {
    return null;
  }
}

/** Build a non-LLM facts line for Discord / outbox. */
export function buildFactsSummary(
  report: Omit<AutopsyReport, "facts_summary">,
): string {
  const bits: string[] = [
    `Flagged SCAM ${report.age_hours}h ago`,
    `score ${report.risk_score}`,
  ];
  if (report.reasons[0]) {
    bits.push(report.reasons.slice(0, 2).join(", "));
  }
  if (report.activity.token_transfer_count != null) {
    bits.push(
      `${report.activity.token_transfer_count} post-flag token transfers`,
    );
  }
  const weth = formatWeiAsEth(report.activity.weth_to_pair_wei);
  if (weth && report.activity.weth_to_pair_wei !== "0") {
    bits.push(`~${weth} WETH to pair (est.)`);
  }
  const usdc = formatUsdcAtomic(report.activity.usdc_to_pair_atomic);
  if (usdc && report.activity.usdc_to_pair_atomic !== "0") {
    bits.push(`~${usdc} USDC to pair (est.)`);
  }
  if (report.activity.lp_burn_observed === true) {
    bits.push("LP burn observed");
  }
  return bits.join(" · ");
}
