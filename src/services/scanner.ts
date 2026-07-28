import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  analyzeBytecode,
  analyzeContract,
  mergeGoPlusEnrichment,
  type AnalysisStatus,
} from "./analyzer";
import { getContractBytecode } from "./alchemy";
import { fetchGoPlusTokenSecurity } from "./goplus";
import { recordThreat, type RecordThreatOptions } from "./threatIntel";
import {
  isValidEthereumAddress,
  normalizeEthereumAddress,
} from "../utils/validation";

const CACHE_TTL_SECONDS = 86_400; // 24 hours

export interface ScanResult {
  address: string;
  network: string;
  status: AnalysisStatus;
  riskScore: number;
  reasons: string[];
  bytecodeLength: number;
  cachedAt: string;
}

export interface ScanOptions {
  waitUntil?: RecordThreatOptions["waitUntil"];
}

function cacheKey(network: string, contractAddress: string): string {
  return `contract:${network}:${contractAddress}`;
}

/**
 * Scans a contract address: returns cached result from KV when available,
 * otherwise fetches bytecode + GoPlus enrichment in parallel, caches and returns it.
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
    return cached as ScanResult;
  }

  // Parallel: Alchemy bytecode + GoPlus (GoPlus failure is swallowed inside client).
  const [bytecode, goplus] = await Promise.all([
    getContractBytecode(address, env),
    fetchGoPlusTokenSecurity(address, network),
  ]);

  const local = analyzeBytecode(bytecode);
  const analysis = local.reasons.includes("Empty_Contract")
    ? local
    : mergeGoPlusEnrichment(local, goplus);

  const result: ScanResult = {
    address,
    network,
    status: analysis.status,
    riskScore: analysis.riskScore,
    reasons: analysis.reasons,
    bytecodeLength: bytecode.length,
    cachedAt: new Date().toISOString(),
  };

  await env.SCAN_CACHE.put(key, JSON.stringify(result), {
    expirationTtl: CACHE_TTL_SECONDS,
  });

  if (result.status === "SCAM") {
    await recordThreat(env, result, { waitUntil: options.waitUntil });
  }

  return result;
}

export { analyzeContract };
