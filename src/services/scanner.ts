import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  getBluechipSymbol,
  isBluechipAddress,
} from "../config/bluechips";
import {
  analyzeBytecode,
  enrichAnalysis,
  type AnalysisStatus,
} from "./analyzer";
import { getContractBytecode } from "./alchemy";
import {
  applyStubAdminProbes,
  probeStubAndAdminSurface,
} from "./stubCodeProbes";
import {
  fetchGoPlusTokenSecurity,
  type GoPlusTokenFlags,
} from "./goplus";
import {
  fetchHoneypotIs,
  type HoneypotIsFlags,
} from "./honeypotIs";
import { recordThreat, type RecordThreatOptions } from "./threatIntel";
import { kvPutBestEffort } from "./kvSafe";
import type { ListingContext, ScanDossier } from "./scanTypes";
import {
  isValidEthereumAddress,
  normalizeEthereumAddress,
} from "../utils/validation";
import { buildVerdict, type AgentVerdict } from "./verdict";

export type { ListingContext, ScanDossier } from "./scanTypes";
export type { AgentVerdict };

const CACHE_TTL_SECONDS = 86_400; // 24 hours
/** Default max age when watch asks for semi-fresh cache. */
export const WATCH_CACHE_MAX_AGE_SECONDS = 5 * 60;

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
  /** Skip SCAN_CACHE read (still writes cache). Used by watchdog re-checks. */
  bypassCache?: boolean;
  /**
   * If set and cache entry is older than this many seconds, treat as miss.
   * Saves KV writes vs bypassCache while keeping watch reasonably fresh.
   */
  maxCacheAgeSeconds?: number;
}

function cacheKey(network: string, contractAddress: string): string {
  return `contract:${network}:${contractAddress}`;
}

/** Read scan cache without running enrichment (cron budget / dedupe). */
export async function peekScanCache(
  env: Env,
  contractAddress: string,
): Promise<ScanResult | null> {
  const address = normalizeEthereumAddress(contractAddress);
  if (!address || !isValidEthereumAddress(address)) return null;
  const network = resolveNetwork(env);
  const cached = await env.SCAN_CACHE.get(cacheKey(network, address), "json");
  return cached ? (cached as ScanResult) : null;
}

export function scanResultAgeSeconds(result: ScanResult): number {
  const cachedAtMs = Date.parse(result.cachedAt);
  if (!Number.isFinite(cachedAtMs)) return Number.POSITIVE_INFINITY;
  return (Date.now() - cachedAtMs) / 1000;
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
    listingSource: result.dossier?.listing?.source ?? null,
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

  // Known Base bluechips: SAFE/CLEAR, skip GoPlus / honeypot / bytecode heuristics.
  if (isBluechipAddress(network, address)) {
    const symbol = getBluechipSymbol(network, address) ?? "BLUECHIP";
    const result: ScanResult = {
      address,
      network,
      status: "SAFE",
      riskScore: 0,
      reasons: [`Bluechip_Allowlist:${symbol}`],
      bytecodeLength: 0,
      cachedAt: new Date().toISOString(),
      dossier: {
        goplus: null,
        honeypotIs: null,
        listing: options.listing ?? null,
        ageHintSeconds: null,
        dualSourceConsensus: false,
      },
      verdict: "CLEAR",
      verdict_score: 100,
      risk_flags: [],
    };
    await kvPutBestEffort(env.SCAN_CACHE, key, JSON.stringify(result), {
      expirationTtl: CACHE_TTL_SECONDS,
    });
    return result;
  }

  const cached = options.bypassCache
    ? null
    : await env.SCAN_CACHE.get(key, "json");

  if (cached) {
    const cachedResult = cached as ScanResult;
    const maxAge = options.maxCacheAgeSeconds;
    if (typeof maxAge === "number" && maxAge >= 0) {
      const cachedAtMs = Date.parse(cachedResult.cachedAt);
      const ageSec = Number.isFinite(cachedAtMs)
        ? (Date.now() - cachedAtMs) / 1000
        : Number.POSITIVE_INFINITY;
      if (ageSec > maxAge) {
        // Stale for this caller — fall through to fresh scan.
      } else {
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
    } else {
      // Cache hit: return (optionally with listing overlay). No KV put.
      if (options.listing && !cachedResult.dossier?.listing) {
        return withVerdict({
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
  }

  const [bytecode, goplus, honeypotIs] = await Promise.all([
    getContractBytecode(address, env),
    fetchGoPlusTokenSecurity(address, network),
    fetchHoneypotIs(address, network),
  ]);

  const local = analyzeBytecode(bytecode);
  // Minimal / 0xef code: probe live ERC-20 + AccessControl views (MoonBase-style stubs).
  const stubProbes = await probeStubAndAdminSurface(env, address, bytecode);
  const withStub = applyStubAdminProbes(local, stubProbes);
  const analysis = enrichAnalysis(
    withStub,
    goplus,
    honeypotIs,
    options.listing?.source ?? null,
  );
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

  // Never fail the scan when Free KV write quota is exhausted.
  await kvPutBestEffort(env.SCAN_CACHE, key, JSON.stringify(result), {
    expirationTtl: CACHE_TTL_SECONDS,
  });

  if (result.status === "SCAM" || result.status === "SUSPICIOUS") {
    try {
      await recordThreat(env, result, { waitUntil: options.waitUntil });
    } catch (error) {
      console.error(
        `[scan] recordThreat failed ${address}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }

  return result;
}

export { analyzeContract } from "./analyzer";
