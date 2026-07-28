import type { NetworkId } from "../config/network";
import { getGoPlusChainId } from "../config/network";

const GOPLUS_BASE_URL = "https://api.gopluslabs.io/api/v1/token_security";
const GOPLUS_TIMEOUT_MS = 2_500;

export interface GoPlusTokenFlags {
  isHoneypot: boolean;
  cantSell: boolean;
  isOpenSource: boolean | null;
  buyTax: number | null;
  sellTax: number | null;
  rawAvailable: boolean;
}

interface GoPlusApiResponse {
  code?: number;
  message?: string;
  result?: Record<string, GoPlusTokenResult | null | undefined>;
}

interface GoPlusTokenResult {
  is_honeypot?: string | number | boolean;
  buy_tax?: string | number;
  sell_tax?: string | number;
  is_open_source?: string | number | boolean;
  /** GoPlus common field */
  cannot_sell_all?: string | number | boolean;
  /** Alias some docs / clients use */
  cant_sell?: string | number | boolean;
  cannot_buy?: string | number | boolean;
}

function isTruthyFlag(value: unknown): boolean {
  return value === "1" || value === 1 || value === true || value === "true";
}

function parseTaxPercent(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const parsed = Number.parseFloat(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function parseOpenSource(value: unknown): boolean | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  return isTruthyFlag(value);
}

/**
 * Fetches GoPlus token security flags.
 * Never throws — returns null on timeout/error/unsupported/empty so local analysis remains authoritative.
 */
export async function fetchGoPlusTokenSecurity(
  contractAddress: string,
  network: NetworkId,
): Promise<GoPlusTokenFlags | null> {
  const chainId = getGoPlusChainId(network);
  const url = `${GOPLUS_BASE_URL}/${chainId}?contract_addresses=${encodeURIComponent(contractAddress.toLowerCase())}`;

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(GOPLUS_TIMEOUT_MS),
    });

    if (!response.ok) {
      console.warn(`[goplus] HTTP ${response.status} for ${contractAddress}`);
      return null;
    }

    const payload = (await response.json()) as GoPlusApiResponse;
    if (payload.code !== 1 || !payload.result) {
      return null;
    }

    const entry =
      payload.result[contractAddress.toLowerCase()] ??
      payload.result[Object.keys(payload.result)[0] ?? ""];

    if (!entry || typeof entry !== "object") {
      return null;
    }

    return {
      isHoneypot: isTruthyFlag(entry.is_honeypot),
      cantSell:
        isTruthyFlag(entry.cant_sell) || isTruthyFlag(entry.cannot_sell_all),
      isOpenSource: parseOpenSource(entry.is_open_source),
      buyTax: parseTaxPercent(entry.buy_tax),
      sellTax: parseTaxPercent(entry.sell_tax),
      rawAvailable: true,
    };
  } catch (error) {
    console.warn(
      `[goplus] enrichment skipped for ${contractAddress}:`,
      error instanceof Error ? error.message : error,
    );
    return null;
  }
}
