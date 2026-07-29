import type { NetworkId } from "../config/network";
import { getGoPlusChainId } from "../config/network";

const HONEYPOT_IS_URL = "https://api.honeypot.is/v2/IsHoneypot";
const HONEYPOT_IS_TIMEOUT_MS = 3_500;

/** Compact honeypot.is simulation signals for dossier A buyers. */
export interface HoneypotIsFlags {
  rawAvailable: boolean;
  isHoneypot: boolean | null;
  simulationSuccess: boolean;
  simulationError: string | null;
  buyTax: number | null;
  sellTax: number | null;
  transferTax: number | null;
  risk: string | null;
  riskLevel: number | null;
  openSource: boolean | null;
  isProxy: boolean | null;
  hasProxyCalls: boolean | null;
  holderCount: number | null;
  pairAddress: string | null;
  liquidityUsd: number | null;
}

interface HoneypotIsResponse {
  honeypotResult?: { isHoneypot?: boolean };
  simulationSuccess?: boolean;
  simulationError?: string;
  simulationResult?: {
    buyTax?: number;
    sellTax?: number;
    transferTax?: number;
  };
  summary?: { risk?: string; riskLevel?: number };
  contractCode?: {
    openSource?: boolean;
    isProxy?: boolean;
    hasProxyCalls?: boolean;
  };
  token?: { totalHolders?: number };
  pair?: { liquidity?: number; pair?: { address?: string } };
  pairAddress?: string;
}

/**
 * Fetches honeypot.is buy/sell simulation for Base (or mapped chain).
 * Never throws — returns null on timeout/error so other signals remain authoritative.
 */
export async function fetchHoneypotIs(
  contractAddress: string,
  network: NetworkId,
): Promise<HoneypotIsFlags | null> {
  // honeypot.is supports Base (8453); Sepolia is unsupported → skip.
  if (network !== "base") {
    return null;
  }

  const chainId = getGoPlusChainId(network);
  const url = `${HONEYPOT_IS_URL}?address=${encodeURIComponent(contractAddress.toLowerCase())}&chainID=${chainId}`;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(HONEYPOT_IS_TIMEOUT_MS),
    });

    if (!response.ok) {
      console.warn(
        `[honeypot.is] HTTP ${response.status} for ${contractAddress}`,
      );
      return null;
    }

    const payload = (await response.json()) as HoneypotIsResponse;
    const sim = payload.simulationResult;

    return {
      rawAvailable: true,
      isHoneypot:
        typeof payload.honeypotResult?.isHoneypot === "boolean"
          ? payload.honeypotResult.isHoneypot
          : null,
      simulationSuccess: Boolean(payload.simulationSuccess),
      simulationError: payload.simulationError ?? null,
      buyTax: typeof sim?.buyTax === "number" ? sim.buyTax : null,
      sellTax: typeof sim?.sellTax === "number" ? sim.sellTax : null,
      transferTax: typeof sim?.transferTax === "number" ? sim.transferTax : null,
      risk: payload.summary?.risk ?? null,
      riskLevel:
        typeof payload.summary?.riskLevel === "number"
          ? payload.summary.riskLevel
          : null,
      openSource:
        typeof payload.contractCode?.openSource === "boolean"
          ? payload.contractCode.openSource
          : null,
      isProxy:
        typeof payload.contractCode?.isProxy === "boolean"
          ? payload.contractCode.isProxy
          : null,
      hasProxyCalls:
        typeof payload.contractCode?.hasProxyCalls === "boolean"
          ? payload.contractCode.hasProxyCalls
          : null,
      holderCount:
        typeof payload.token?.totalHolders === "number"
          ? payload.token.totalHolders
          : null,
      pairAddress:
        payload.pairAddress ?? payload.pair?.pair?.address ?? null,
      liquidityUsd:
        typeof payload.pair?.liquidity === "number"
          ? payload.pair.liquidity
          : null,
    };
  } catch (error) {
    console.warn(
      `[honeypot.is] enrichment skipped for ${contractAddress}:`,
      error instanceof Error ? error.message : error,
    );
    return null;
  }
}
