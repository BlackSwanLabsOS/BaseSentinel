/**
 * Agent verdict layer: CLEAR / CAUTION / AVOID.
 * `verdict_score`: 100 = clean, 0 = high risk.
 */

import { shouldIgnoreGoPlusPriorHoneypot } from "../config/aaInfrastructure";

export type AgentVerdict = "CLEAR" | "CAUTION" | "AVOID";

export interface VerdictInput {
  status: "SAFE" | "SUSPICIOUS" | "SCAM";
  riskScore: number;
  reasons: string[];
  goplus?: {
    isHoneypot?: boolean;
    cantSell?: boolean;
    cannotBuy?: boolean;
    isOpenSource?: boolean | null;
    buyTax?: number | null;
    sellTax?: number | null;
    isProxy?: boolean | null;
    isMintable?: boolean | null;
    ownerCanChangeBalance?: boolean | null;
    hiddenOwner?: boolean | null;
    canTakeBackOwnership?: boolean | null;
    isBlacklisted?: boolean | null;
    honeypotWithSameCreator?: boolean | null;
    creatorAddress?: string | null;
  } | null;
  /** Discovery source when known (e.g. zora_coin_v4). */
  listingSource?: string | null;
  honeypotIs?: {
    isHoneypot?: boolean | null;
    buyTax?: number | null;
    sellTax?: number | null;
    isProxy?: boolean | null;
    hasProxyCalls?: boolean | null;
    openSource?: boolean | null;
  } | null;
  dualSourceConsensus?: boolean;
  /** Optional market-structure hints (premium dossier). */
  deployerBalancePct?: number | null;
  top5HoldersPct?: number | null;
}

export interface VerdictResult {
  verdict: AgentVerdict;
  /** 100 = clean, 0 = high risk. */
  verdict_score: number;
  risk_flags: string[];
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

export function maxTax(
  goplus: VerdictInput["goplus"],
  honeypotIs: VerdictInput["honeypotIs"],
): number | null {
  const taxes = [
    goplus?.buyTax,
    goplus?.sellTax,
    honeypotIs?.buyTax,
    honeypotIs?.sellTax,
  ].filter((t): t is number => typeof t === "number" && Number.isFinite(t));
  if (taxes.length === 0) return null;
  return Math.max(...taxes);
}

/** Machine-readable risk flag codes for agent branching. */
export function collectRiskFlags(input: VerdictInput): string[] {
  const flags = new Set<string>();
  const { goplus, honeypotIs, reasons } = input;
  const tax = maxTax(goplus, honeypotIs);

  if (goplus?.isHoneypot || honeypotIs?.isHoneypot === true) {
    flags.add("HONEYPOT");
  }
  if (goplus?.cantSell) flags.add("CANT_SELL");
  if (goplus?.cannotBuy) flags.add("CANT_BUY");
  if (input.dualSourceConsensus) flags.add("DUAL_SOURCE_HONEYPOT");

  if (tax !== null) {
    if (tax >= 49) flags.add("EXTREME_TAX");
    else if (tax > 10) flags.add("HIGH_TAX");
    else if (tax >= 3) flags.add("MODERATE_TAX");
  }

  if (goplus?.isOpenSource === false || honeypotIs?.openSource === false) {
    flags.add("UNVERIFIED_SOURCE");
  }

  const listing = (input.listingSource || "").toLowerCase();
  const zoraLike = listing.startsWith("zora");
  // Zora / minimal proxies are normal — do not flag proxy alone there.
  if (
    !zoraLike &&
    (goplus?.isProxy === true ||
      honeypotIs?.isProxy === true ||
      honeypotIs?.hasProxyCalls === true)
  ) {
    flags.add("PROXY_RISK");
  }
  if (goplus?.isMintable === true) flags.add("MINTABLE");
  if (goplus?.ownerCanChangeBalance === true) flags.add("OWNER_CHANGE_BALANCE");
  if (goplus?.hiddenOwner === true) flags.add("HIDDEN_OWNER");
  if (goplus?.canTakeBackOwnership === true) {
    flags.add("CAN_TAKE_BACK_OWNERSHIP");
  }
  if (goplus?.isBlacklisted === true) flags.add("TOKEN_BLACKLIST_FEATURE");
  if (goplus?.honeypotWithSameCreator === true) {
    if (
      shouldIgnoreGoPlusPriorHoneypot({
        creatorAddress: goplus.creatorAddress,
        honeypotWithSameCreator: true,
        listingSource: input.listingSource,
      })
    ) {
      // Creator matched our verified AA/bundler/EntryPoint allowlist.
      flags.add("AA_BUNDLER_CREATOR");
    } else {
      flags.add("DEPLOYER_PRIOR_HONEYPOT");
    }
  }

  const joined = reasons.join(" ").toLowerCase();
  if (
    joined.includes("empty_contract") ||
    joined.includes("empty_or_eoa") ||
    joined.includes("no bytecode")
  ) {
    flags.add("EMPTY_OR_MINIMAL_BYTECODE");
  }
  if (
    joined.includes("stub_or_hidden") ||
    joined.includes("eof_or_reserved_bytecode")
  ) {
    flags.add("STUB_OR_HIDDEN_CODE");
  }
  if (joined.includes("admin_policy_surface")) {
    flags.add("ADMIN_POLICY_SURFACE");
  }
  if (joined.includes("blacklist") || joined.includes("antibot")) {
    flags.add("BLACKLIST_SELECTORS");
  }
  if (joined.includes("trading") && joined.includes("gate")) {
    flags.add("TRADING_GATE");
  }
  // Only real upgrade-surface wording — not every "proxy" mention / Zora coin.
  if (joined.includes("proxy_upgrade_surface") && !zoraLike) {
    flags.add("PROXY_RISK");
  }

  if (
    typeof input.deployerBalancePct === "number" &&
    input.deployerBalancePct >= 10
  ) {
    flags.add("DEPLOYER_HOLDS_SUPPLY");
  }
  if (
    typeof input.top5HoldersPct === "number" &&
    input.top5HoldersPct >= 50
  ) {
    flags.add("HIGH_HOLDER_CONCENTRATION");
  }

  return [...flags].sort();
}

function verdictFromScore(score: number): AgentVerdict {
  if (score < 40) return "AVOID";
  if (score < 80) return "CAUTION";
  return "CLEAR";
}

/** Build CLEAR / CAUTION / AVOID from scan signals. */
export function buildVerdict(input: VerdictInput): VerdictResult {
  const risk_flags = collectRiskFlags(input);
  let verdict_score = clamp(100 - Math.round(input.riskScore), 0, 100);

  // Hard AVOID: force score into the AVOID band.
  // True empty/EOA stays caution; stub/hidden code + admin policy → AVOID.
  const tax = maxTax(input.goplus, input.honeypotIs);
  const hardAvoid =
    risk_flags.includes("HONEYPOT") ||
    risk_flags.includes("CANT_SELL") ||
    risk_flags.includes("DUAL_SOURCE_HONEYPOT") ||
    risk_flags.includes("EXTREME_TAX") ||
    risk_flags.includes("HIGH_TAX") ||
    risk_flags.includes("DEPLOYER_PRIOR_HONEYPOT") ||
    risk_flags.includes("STUB_OR_HIDDEN_CODE") ||
    risk_flags.includes("ADMIN_POLICY_SURFACE") ||
    (typeof tax === "number" && tax > 10) ||
    input.status === "SCAM";

  if (hardAvoid) {
    verdict_score = Math.min(verdict_score, 39);
  } else if (
    risk_flags.includes("UNVERIFIED_SOURCE") ||
    risk_flags.includes("MODERATE_TAX") ||
    risk_flags.includes("PROXY_RISK") ||
    risk_flags.includes("EMPTY_OR_MINIMAL_BYTECODE") ||
    risk_flags.includes("TRADING_GATE") ||
    risk_flags.includes("AA_BUNDLER_CREATOR") ||
    risk_flags.includes("DEPLOYER_HOLDS_SUPPLY") ||
    risk_flags.includes("HIGH_HOLDER_CONCENTRATION") ||
    input.status === "SUSPICIOUS"
  ) {
    // SAFE + caution flags → CAUTION unless score stays high.
    if (verdict_score >= 80) {
      verdict_score = Math.min(verdict_score, 79);
    }
  }

  // SAFE with no caution flags → nudge toward CLEAR.
  if (
    input.status === "SAFE" &&
    !hardAvoid &&
    risk_flags.length === 0 &&
    verdict_score < 80
  ) {
    verdict_score = Math.max(verdict_score, 80);
  }

  return {
    verdict: verdictFromScore(verdict_score),
    verdict_score,
    risk_flags,
  };
}
