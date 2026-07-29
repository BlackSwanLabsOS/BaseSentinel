/**
 * Deterministic agent verdict layer.
 * Maps internal riskScore (0=clean … 100=deadly) to Gemini-style
 * verdict_score (100=clean … 0=deadly) + CLEAR/CAUTION/AVOID.
 */

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
  } | null;
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
  /** 100 = clean, 0 = deadly (inverted from internal riskScore). */
  verdict_score: number;
  risk_flags: string[];
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function maxTax(
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

/**
 * Stable machine codes for agent branching (no free-text).
 */
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
  if (
    goplus?.isProxy === true ||
    honeypotIs?.isProxy === true ||
    honeypotIs?.hasProxyCalls === true
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
    flags.add("DEPLOYER_PRIOR_HONEYPOT");
  }

  const joined = reasons.join(" ").toLowerCase();
  if (joined.includes("empty contract") || joined.includes("no bytecode")) {
    flags.add("EMPTY_OR_MINIMAL_BYTECODE");
  }
  if (joined.includes("blacklist") || joined.includes("antibot")) {
    flags.add("BLACKLIST_SELECTORS");
  }
  if (joined.includes("trading") && joined.includes("gate")) {
    flags.add("TRADING_GATE");
  }
  if (joined.includes("proxy")) flags.add("PROXY_RISK");

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

/**
 * Build agent-facing verdict. Prefer inverted riskScore, then tighten with hard rules.
 */
export function buildVerdict(input: VerdictInput): VerdictResult {
  const risk_flags = collectRiskFlags(input);
  let verdict_score = clamp(100 - Math.round(input.riskScore), 0, 100);

  // Hard AVOID rules (Gemini spec) — force score into AVOID band.
  const tax = maxTax(input.goplus, input.honeypotIs);
  const hardAvoid =
    risk_flags.includes("HONEYPOT") ||
    risk_flags.includes("CANT_SELL") ||
    risk_flags.includes("DUAL_SOURCE_HONEYPOT") ||
    risk_flags.includes("EXTREME_TAX") ||
    risk_flags.includes("HIGH_TAX") ||
    risk_flags.includes("EMPTY_OR_MINIMAL_BYTECODE") ||
    risk_flags.includes("DEPLOYER_PRIOR_HONEYPOT") ||
    (typeof tax === "number" && tax > 10) ||
    input.status === "SCAM";

  if (hardAvoid) {
    verdict_score = Math.min(verdict_score, 39);
  } else if (
    risk_flags.includes("UNVERIFIED_SOURCE") ||
    risk_flags.includes("MODERATE_TAX") ||
    risk_flags.includes("PROXY_RISK") ||
    risk_flags.includes("DEPLOYER_HOLDS_SUPPLY") ||
    risk_flags.includes("HIGH_HOLDER_CONCENTRATION") ||
    input.status === "SUSPICIOUS"
  ) {
    // Keep CLEAR only if already high; otherwise floor into CAUTION.
    if (verdict_score >= 80) {
      verdict_score = Math.min(verdict_score, 79);
    }
  }

  // Soft CLEAR nudge when status is SAFE and no caution flags.
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
