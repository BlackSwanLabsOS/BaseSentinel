import type { NetworkId } from "../config/network";
import {
  fetchGoPlusTokenSecurity,
  type GoPlusTokenFlags,
} from "./goplus";
import type { HoneypotIsFlags } from "./honeypotIs";

export type AnalysisStatus = "SAFE" | "SUSPICIOUS" | "SCAM";

export interface AnalysisResult {
  status: AnalysisStatus;
  riskScore: number;
  reasons: string[];
}

/** Score band: watchlist / softer pack (not a hard conviction). */
export const RISK_SUSPICIOUS = 50;
/** Score band: hard SCAM for alerts + primary threat pack. */
export const RISK_SCAM = 70;

export function statusFromScore(score: number): AnalysisStatus {
  if (score >= RISK_SCAM) return "SCAM";
  if (score >= RISK_SUSPICIOUS) return "SUSPICIOUS";
  return "SAFE";
}

/** Minimum runtime bytecode size (hex chars excluding 0x) to not be "empty". */
const MIN_BYTECODE_HEX_LENGTH = 10;

/** Sell/buy tax (%) above this is treated as a serious risk signal. */
const HIGH_TAX_PERCENT = 10;
/** Extreme tax (%) — effectively unsellable for snipers. */
const EXTREME_TAX_PERCENT = 49;

/**
 * PUSH4 (0x63) + 4-byte selector — far fewer false positives than raw substring search.
 */
function hasPush4Selector(codeHex: string, selector: string): boolean {
  const sel = selector.replace(/^0x/i, "").toLowerCase();
  return codeHex.includes(`63${sel}`);
}

function countPush4Selectors(codeHex: string, selectors: string[]): number {
  return selectors.reduce(
    (count, selector) => count + (hasPush4Selector(codeHex, selector) ? 1 : 0),
    0,
  );
}

/** Core ERC-20 selectors. */
const ERC20 = {
  transfer: "a9059cbb",
  transferFrom: "23b872dd",
  approve: "095ea7b3",
  balanceOf: "70a08231",
  totalSupply: "18160ddd",
  allowance: "dd62ed3e",
} as const;

const TRADING_GATE_SELECTORS = [
  "8a8c523c", // enableTrading()
  "c9567bf9", // openTrading()
  "293230b8", // startTrading()
  "4a4fbe79", // tradingEnable / variants
  "8f70ccf7", // setTrading(bool)
  "fb07105d", // setTradingEnabled(bool) — common kit
  "6ceb0275", // tradingStatus / variants
];

const BLACKLIST_SELECTORS = [
  "f9f92be4", // blacklist(address)
  "fe575a87", // isBlacklisted(address)
  "0ecb93c0", // includeInBlacklist
  "e4997dc5", // excludeFromBlacklist / setBlacklist
  "7b1cdfdd", // addBot / antiBot kits
  "4188bf5a", // setBotBlacklist
];

const FEE_WEAPON_SELECTORS = [
  "c49b9a80", // setSwapAndLiquifyEnabled
  "730c2107", // setFees
  "5d098b38", // setMarketingWallet
  "65b8dbc0", // setLiquidityFee
  "ea2f0b37", // excludeFromFee
  "c0246668", // setFeeExempt / variants
];

const MAX_TX_COOLDOWN_SELECTORS = [
  "7d1db4a5", // maxTxAmount()
  "8f9a55c0", // maxWallet()
  "cc1776d3", // setMaxTx
  "f8b45b05", // maxWalletToken
  "a8c62e26", // cooldown / tradingCooldown
];

const OWNER_POWER_SELECTORS = [
  "8da5cb5b", // owner()
  "715018a6", // renounceOwnership()
  "f2fde38b", // transferOwnership(address)
  "40c10f19", // mint(address,uint256)
];

/** Proxy / upgrade surface (bytecode heuristics — not EIP-1967 storage). */
const PROXY_SELECTORS = [
  "5c60da1b", // implementation()
  "3659cfe6", // upgradeTo(address)
  "4f1ef286", // upgradeToAndCall(address,bytes)
  "8f283970", // changeAdmin(address)
  "f851a440", // admin()
];

function looksLikeErc20Token(codeHex: string): boolean {
  const hasBalanceOf = hasPush4Selector(codeHex, ERC20.balanceOf);
  const hasSupplyOrApprove =
    hasPush4Selector(codeHex, ERC20.totalSupply) ||
    hasPush4Selector(codeHex, ERC20.approve) ||
    hasPush4Selector(codeHex, ERC20.allowance);

  return hasBalanceOf && hasSupplyOrApprove;
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function finalize(reasons: string[], riskScore: number): AnalysisResult {
  const score = clampScore(riskScore);
  const cleaned = reasons.filter((r) => r !== "None");
  if (cleaned.length === 0) {
    cleaned.push("None");
  }

  return {
    status: statusFromScore(score),
    riskScore: score,
    reasons: cleaned,
  };
}

/**
 * Fast heuristic bytecode analysis for common Base honeypot / scam patterns.
 */
export function analyzeBytecode(bytecode: string): AnalysisResult {
  const reasons: string[] = [];
  let riskScore = 0;

  const raw = (bytecode ?? "").trim();
  const codeHex = raw.toLowerCase().replace(/^0x/, "");

  if (!codeHex || codeHex === "0" || codeHex.length < MIN_BYTECODE_HEX_LENGTH) {
    return {
      status: "SCAM",
      riskScore: 100,
      reasons: ["Empty_Contract"],
    };
  }

  const isToken = looksLikeErc20Token(codeHex);
  const hasTransfer = hasPush4Selector(codeHex, ERC20.transfer);
  const hasTransferFrom = hasPush4Selector(codeHex, ERC20.transferFrom);

  if (isToken && !hasTransfer && !hasTransferFrom) {
    reasons.push("Missing_Transfer_Functions");
    riskScore += 85;
  } else if (isToken && !hasTransfer) {
    reasons.push("Missing_Transfer_Selector");
    riskScore += 45;
  }

  const tradingGates = countPush4Selectors(codeHex, TRADING_GATE_SELECTORS);
  if (tradingGates > 0) {
    reasons.push("Trading_Gate_Detected");
    riskScore += 15 + Math.min(tradingGates - 1, 2) * 8;
  }

  const blacklistHits = countPush4Selectors(codeHex, BLACKLIST_SELECTORS);
  if (blacklistHits > 0) {
    reasons.push("Blacklist_Functions_Detected");
    riskScore += 20 + Math.min(blacklistHits - 1, 2) * 10;
  }

  const feeWeapons = countPush4Selectors(codeHex, FEE_WEAPON_SELECTORS);
  if (feeWeapons > 0) {
    reasons.push("Mutable_Fee_Controls_Detected");
    riskScore += 12 + Math.min(feeWeapons - 1, 2) * 6;
  }

  const maxTxHits = countPush4Selectors(codeHex, MAX_TX_COOLDOWN_SELECTORS);
  if (maxTxHits > 0) {
    reasons.push("MaxTx_Or_Cooldown_Controls");
    riskScore += 8 + Math.min(maxTxHits - 1, 2) * 4;
  }

  if (isToken && hasPush4Selector(codeHex, "40c10f19") && tradingGates > 0) {
    reasons.push("Owner_Mint_With_Trading_Gate");
    riskScore += 25;
  }

  if (isToken && tradingGates > 0 && blacklistHits > 0) {
    reasons.push("Honeypot_Toolkit_Pattern");
    riskScore += 30;
  }

  if (isToken && countPush4Selectors(codeHex, OWNER_POWER_SELECTORS) >= 3) {
    reasons.push("High_Owner_Privilege_Surface");
    riskScore += 10;
  }

  const proxyHits = countPush4Selectors(codeHex, PROXY_SELECTORS);
  if (proxyHits >= 2) {
    reasons.push("Proxy_Upgrade_Surface_Detected");
    riskScore += 18;
  } else if (proxyHits === 1) {
    reasons.push("Proxy_Selector_Detected");
    riskScore += 10;
  }

  if (codeHex.length > 50_000) {
    reasons.push("Unusually_Large_Bytecode");
    riskScore += 8;
  }

  return finalize(reasons, riskScore);
}

/**
 * Merges GoPlus flags into a local bytecode analysis result.
 * Critical GoPlus signals force SCAM / riskScore 100.
 */
export function mergeGoPlusEnrichment(
  local: AnalysisResult,
  goplus: GoPlusTokenFlags | null,
): AnalysisResult {
  if (!goplus || !goplus.rawAvailable) {
    return local;
  }

  const reasons = [...local.reasons];
  let riskScore = local.riskScore;

  if (goplus.isHoneypot) {
    reasons.push("GoPlus: Honeypot detected");
    riskScore = 100;
  }

  if (goplus.cantSell) {
    reasons.push("GoPlus: Cannot sell (cant_sell / cannot_sell_all)");
    riskScore = 100;
  }

  if (goplus.sellTax !== null) {
    if (goplus.sellTax >= EXTREME_TAX_PERCENT) {
      reasons.push(`GoPlus: Extreme sell tax (${goplus.sellTax}%)`);
      riskScore = Math.max(riskScore, 95);
    } else if (goplus.sellTax >= HIGH_TAX_PERCENT) {
      reasons.push(`GoPlus: High sell tax (${goplus.sellTax}%)`);
      riskScore += 25;
    }
  }

  if (goplus.buyTax !== null) {
    if (goplus.buyTax >= EXTREME_TAX_PERCENT) {
      reasons.push(`GoPlus: Extreme buy tax (${goplus.buyTax}%)`);
      riskScore = Math.max(riskScore, 90);
    } else if (goplus.buyTax >= HIGH_TAX_PERCENT) {
      reasons.push(`GoPlus: High buy tax (${goplus.buyTax}%)`);
      riskScore += 15;
    }
  }

  if (goplus.cannotBuy) {
    reasons.push("GoPlus: Cannot buy");
    riskScore = Math.max(riskScore, 90);
  }

  if (goplus.ownerCanChangeBalance) {
    reasons.push("GoPlus: Owner can change balances");
    riskScore += 20;
  }

  if (goplus.hiddenOwner) {
    reasons.push("GoPlus: Hidden owner");
    riskScore += 15;
  }

  if (goplus.canTakeBackOwnership) {
    reasons.push("GoPlus: Can take back ownership");
    riskScore += 15;
  }

  if (goplus.isMintable) {
    reasons.push("GoPlus: Mintable");
    riskScore += 10;
  }

  if (goplus.honeypotWithSameCreator) {
    reasons.push("GoPlus: Creator linked to prior honeypot");
    riskScore = Math.max(riskScore, 85);
  }

  if (goplus.isOpenSource === false) {
    reasons.push("GoPlus: Source not verified");
    riskScore += 10;
  }

  return finalize(reasons, riskScore);
}

/**
 * Merges honeypot.is simulation into a local (+ GoPlus) analysis.
 * Treats confirmed isHoneypot strongly; ignores failed sims with no verdict.
 */
export function mergeHoneypotIsEnrichment(
  local: AnalysisResult,
  honeypot: HoneypotIsFlags | null,
): AnalysisResult {
  if (!honeypot || !honeypot.rawAvailable) {
    return local;
  }

  const reasons = [...local.reasons];
  let riskScore = local.riskScore;

  if (honeypot.isHoneypot === true) {
    // Soften obvious false positives: honeypot flag but 0 sell tax + many holders.
    const likelyFalsePositive =
      honeypot.sellTax === 0 &&
      honeypot.buyTax === 0 &&
      (honeypot.holderCount ?? 0) >= 50;

    if (likelyFalsePositive) {
      reasons.push("HoneypotIs: Flagged honeypot (softened — 0 tax + holders)");
      riskScore = Math.max(riskScore, 60);
    } else {
      reasons.push("HoneypotIs: Honeypot detected (simulation)");
      riskScore = Math.max(riskScore, 95);
    }
  }

  if (honeypot.sellTax !== null && honeypot.simulationSuccess) {
    if (honeypot.sellTax >= EXTREME_TAX_PERCENT) {
      reasons.push(`HoneypotIs: Extreme sell tax (${honeypot.sellTax}%)`);
      riskScore = Math.max(riskScore, 95);
    } else if (honeypot.sellTax >= HIGH_TAX_PERCENT) {
      reasons.push(`HoneypotIs: High sell tax (${honeypot.sellTax}%)`);
      riskScore += 20;
    }
  }

  if (honeypot.buyTax !== null && honeypot.simulationSuccess) {
    if (honeypot.buyTax >= EXTREME_TAX_PERCENT) {
      reasons.push(`HoneypotIs: Extreme buy tax (${honeypot.buyTax}%)`);
      riskScore = Math.max(riskScore, 90);
    } else if (honeypot.buyTax >= HIGH_TAX_PERCENT) {
      reasons.push(`HoneypotIs: High buy tax (${honeypot.buyTax}%)`);
      riskScore += 12;
    }
  }

  if (honeypot.isProxy || honeypot.hasProxyCalls) {
    reasons.push("HoneypotIs: Proxy / proxy calls");
    riskScore += 12;
  }

  if (honeypot.openSource === false) {
    reasons.push("HoneypotIs: Source not verified");
    riskScore += 8;
  }

  if (
    honeypot.riskLevel !== null &&
    honeypot.riskLevel >= 3 &&
    honeypot.isHoneypot !== false
  ) {
    reasons.push(`HoneypotIs: Elevated risk (${honeypot.risk ?? honeypot.riskLevel})`);
    riskScore = Math.max(riskScore, 55 + honeypot.riskLevel * 5);
  }

  return finalize(reasons, riskScore);
}

/**
 * Dual-source consensus: GoPlus + honeypot.is both screaming honeypot → hard 100.
 */
export function applyExternalHoneypotConsensus(
  analysis: AnalysisResult,
  goplus: GoPlusTokenFlags | null,
  honeypot: HoneypotIsFlags | null,
): AnalysisResult {
  const goplusHit = Boolean(
    goplus?.rawAvailable && (goplus.isHoneypot || goplus.cantSell),
  );
  const honeypotHit = Boolean(
    honeypot?.rawAvailable && honeypot.isHoneypot === true,
  );

  if (!goplusHit || !honeypotHit) {
    return analysis;
  }

  const reasons = [
    ...analysis.reasons.filter((r) => r !== "None"),
    "DualSource_Honeypot_Consensus",
  ];

  return {
    status: "SCAM",
    riskScore: 100,
    reasons,
  };
}

/**
 * Full analysis: local bytecode + GoPlus + honeypot.is + consensus vote.
 */
export async function analyzeContract(
  bytecode: string,
  contractAddress: string,
  network: NetworkId,
): Promise<AnalysisResult> {
  const local = analyzeBytecode(bytecode);

  if (local.reasons.includes("Empty_Contract")) {
    return local;
  }

  const goplus = await fetchGoPlusTokenSecurity(contractAddress, network);
  return mergeGoPlusEnrichment(local, goplus);
}

/**
 * Sync enrichment pipeline used by the scanner (parallel fetches happen outside).
 */
export function enrichAnalysis(
  local: AnalysisResult,
  goplus: GoPlusTokenFlags | null,
  honeypot: HoneypotIsFlags | null,
): AnalysisResult {
  if (local.reasons.includes("Empty_Contract")) {
    return local;
  }

  const withGoPlus = mergeGoPlusEnrichment(local, goplus);
  const withHoneypot = mergeHoneypotIsEnrichment(withGoPlus, honeypot);
  return applyExternalHoneypotConsensus(withHoneypot, goplus, honeypot);
}
