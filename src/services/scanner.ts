import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  analyzeBytecode,
  enrichAnalysis,
  type AnalysisStatus,
} from "./analyzer";
import { getContractBytecode } from "./alchemy";
import {
  fetchGoPlusTokenSecurity,
  type GoPlusTokenFlags,
} from "./goplus";
import {
  fetchHoneypotIs,
  type HoneypotIsFlags,
} from "./honeypotIs";
import { recordThreat, type RecordThreatOptions } from "./threatIntel";
import type { ListingContext, ScanDossier } from "./scanTypes";
import {
  isValidEthereumAddress,
  normalizeEthereumAddress,
} from "../utils/validation";
import { buildVerdict, type AgentVerdict } from "./verdict";

export type { ListingContext, ScanDossier } from "./scanTypes";
export type { AgentVerdict };

const CACHE_TTL_SECONDS = 86_400; // 24 hours

export interface ScanResult {
  address: string;
  network: string;
  status: AnalysisStatus;
  riskScore: number;
  reasons: string[];
  bytecodeLength: number;
  cachedAt: string;
  dossier: ScanDossier;
  /** Agent-facing decision (CLEAR / CAUTION / AVOID). */
  verdict: AgentVerdict;
  /** 100 = clean, 0 = deadly. */
  verdict_score: number;
  risk_flags: string[];
}

export interface ScanOptions {
  waitUntil?: RecordThreatOptions["waitUntil"];
  listing?: ListingContext;
}

function cacheKey(network: string, contractAddress: string): string {
  return `contract:${network}:${contractAddress}`;
}

function toPublicGoPlus(
  flags: GoPlusTokenFlags | null,
): ScanDossier["goplus"] {
  if (!flags || !flags.rawAvailable) return null;
  const { rawAvailable: _r, ...rest } = flags;
  return rest;
}

function toPublicHoneypotIs(
  flags: HoneypotIsFlags | null,
): ScanDossier["honeypotIs"] {
  if (!flags || !flags.rawAvailable) return null;
  const { rawAvailable: _r, ...rest } = flags;
  return rest;
}

function withVerdict(
  result: Omit<ScanResult, "verdict" | "verdict_score" | "risk_flags"> &
    Partial<Pick<ScanResult, "verdict" | "verdict_score" | "risk_flags">>,
): ScanResult {
  const v = buildVerdict({
    status: result.status,
    riskScore: result.riskScore,
    reasons: result.reasons,
    goplus: result.dossier?.goplus ?? null,
    honeypotIs: result.dossier?.honeypotIs ?? null,
    dualSourceConsensus: result.dossier?.dualSourceConsensus ?? false,
  });
  return {
    ...result,
    dossier: result.dossier ?? {
      goplus: null,
      honeypotIs: null,
      listing: null,
      ageHintSeconds: null,
      dualSourceConsensus: false,
    },
    verdict: v.verdict,
    verdict_score: v.verdict_score,
    risk_flags: v.risk_flags,
  };
}

/**
 * Scans a contract: bytecode heuristics + GoPlus + honeypot.is (parallel),
 * with dual-source consensus when both external APIs agree.
 */
export async function scanContract(
  contractAddress: string,
  env: Env,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const address = normalizeEthereumAddress(contractAddress);
  if (!address || !isValidEthereumAddress(address)) {
    throw new Error("Invalid smart contract address format");
  }

  const network = resolveNetwork(env);
  const key = cacheKey(network, address);
  const cached = await env.SCAN_CACHE.get(key, "json");

  if (cached) {
    const cachedResult = cached as ScanResult;
    if (options.listing && !cachedResult.dossier?.listing) {
      const merged = withVerdict({
        ...cachedResult,
        dossier: {
          goplus: cachedResult.dossier?.goplus ?? null,
          honeypotIs: cachedResult.dossier?.honeypotIs ?? null,
          listing: options.listing,
          ageHintSeconds: cachedResult.dossier?.ageHintSeconds ?? null,
          dualSourceConsensus:
            cachedResult.dossier?.dualSourceConsensus ?? false,
        },
      });
      await env.SCAN_CACHE.put(key, JSON.stringify(merged), {
        expirationTtl: CACHE_TTL_SECONDS,
      });
      if (merged.status === "SCAM" || merged.status === "SUSPICIOUS") {
        await recordThreat(env, merged, { waitUntil: options.waitUntil });
      }
      return merged;
    }
    return withVerdict({
      ...cachedResult,
      dossier: cachedResult.dossier ?? {
        goplus: null,
        honeypotIs: null,
        listing: options.listing ?? null,
        ageHintSeconds: null,
        dualSourceConsensus: false,
      },
    });
  }

  const [bytecode, goplus, honeypotIs] = await Promise.all([
    getContractBytecode(address, env),
    fetchGoPlusTokenSecurity(address, network),
    fetchHoneypotIs(address, network),
  ]);

  const local = analyzeBytecode(bytecode);
  const analysis = enrichAnalysis(local, goplus, honeypotIs);
  const dualSourceConsensus = analysis.reasons.includes(
    "DualSource_Honeypot_Consensus",
  );

  const result = withVerdict({
    address,
    network,
    status: analysis.status,
    riskScore: analysis.riskScore,
    reasons: analysis.reasons,
    bytecodeLength: bytecode.length,
    cachedAt: new Date().toISOString(),
    dossier: {
      goplus: toPublicGoPlus(goplus),
      honeypotIs: toPublicHoneypotIs(honeypotIs),
      listing: options.listing ?? null,
      ageHintSeconds: null,
      dualSourceConsensus,
    },
  });

  await env.SCAN_CACHE.put(key, JSON.stringify(result), {
    expirationTtl: CACHE_TTL_SECONDS,
  });

  if (result.status === "SCAM" || result.status === "SUSPICIOUS") {
    await recordThreat(env, result, { waitUntil: options.waitUntil });
  }

  return result;
}

export { analyzeContract } from "./analyzer";
