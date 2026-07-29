import type { NetworkId } from "../config/network";
import { getGoPlusChainId } from "../config/network";

const GOPLUS_BASE_URL = "https://api.gopluslabs.io/api/v1/token_security";
const GOPLUS_TIMEOUT_MS = 2_500;

export interface GoPlusHolderRow {
  address: string;
  percent: number | null;
  isLocked: boolean | null;
  isContract: boolean | null;
  tag: string | null;
}

/** Compact GoPlus signals exposed to paying buyers (dossier A). */
export interface GoPlusTokenFlags {
  rawAvailable: boolean;
  isHoneypot: boolean;
  cantSell: boolean;
  cannotBuy: boolean;
  isOpenSource: boolean | null;
  buyTax: number | null;
  sellTax: number | null;
  isProxy: boolean | null;
  isMintable: boolean | null;
  ownerCanChangeBalance: boolean | null;
  hiddenOwner: boolean | null;
  canTakeBackOwnership: boolean | null;
  isBlacklisted: boolean | null;
  isInDex: boolean | null;
  holderCount: number | null;
  lpHolderCount: number | null;
  creatorAddress: string | null;
  ownerAddress: string | null;
  honeypotWithSameCreator: boolean | null;
  /** Top holders from GoPlus (percent of supply). */
  holders: GoPlusHolderRow[] | null;
  /** LP token holders — used for lock/burn heuristics. */
  lpHolders: GoPlusHolderRow[] | null;
  creatorPercent: number | null;
  ownerPercent: number | null;
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
  cannot_sell_all?: string | number | boolean;
  cant_sell?: string | number | boolean;
  cannot_buy?: string | number | boolean;
  is_proxy?: string | number | boolean;
  is_mintable?: string | number | boolean;
  owner_change_balance?: string | number | boolean;
  hidden_owner?: string | number | boolean;
  can_take_back_ownership?: string | number | boolean;
  is_blacklisted?: string | number | boolean;
  is_in_dex?: string | number | boolean;
  holder_count?: string | number;
  lp_holder_count?: string | number;
  creator_address?: string;
  owner_address?: string;
  creator_percent?: string | number;
  owner_percent?: string | number;
  honeypot_with_same_creator?: string | number | boolean;
  holders?: unknown;
  lp_holders?: unknown;
}

function parsePercent(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number.parseFloat(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function parseHolderRows(value: unknown): GoPlusHolderRow[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const rows: GoPlusHolderRow[] = [];
  for (const raw of value.slice(0, 20)) {
    if (!raw || typeof raw !== "object") continue;
    const row = raw as Record<string, unknown>;
    const address = parseAddress(row.address);
    if (!address) continue;
    rows.push({
      address,
      percent: parsePercent(row.percent ?? row.balance),
      isLocked: parseOptionalFlag(row.is_locked),
      isContract: parseOptionalFlag(row.is_contract),
      tag: typeof row.tag === "string" ? row.tag : null,
    });
  }
  return rows.length > 0 ? rows : null;
}

function isTruthyFlag(value: unknown): boolean {
  return value === "1" || value === 1 || value === true || value === "true";
}

function parseOptionalFlag(value: unknown): boolean | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  return isTruthyFlag(value);
}

function parseTaxPercent(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const parsed = Number.parseFloat(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function parseCount(value: unknown): number | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseAddress(value: unknown): string | null {
  if (typeof value !== "string" || !value.startsWith("0x")) {
    return null;
  }
  return value.toLowerCase();
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
      rawAvailable: true,
      isHoneypot: isTruthyFlag(entry.is_honeypot),
      cantSell:
        isTruthyFlag(entry.cant_sell) || isTruthyFlag(entry.cannot_sell_all),
      cannotBuy: isTruthyFlag(entry.cannot_buy),
      isOpenSource: parseOptionalFlag(entry.is_open_source),
      buyTax: parseTaxPercent(entry.buy_tax),
      sellTax: parseTaxPercent(entry.sell_tax),
      isProxy: parseOptionalFlag(entry.is_proxy),
      isMintable: parseOptionalFlag(entry.is_mintable),
      ownerCanChangeBalance: parseOptionalFlag(entry.owner_change_balance),
      hiddenOwner: parseOptionalFlag(entry.hidden_owner),
      canTakeBackOwnership: parseOptionalFlag(entry.can_take_back_ownership),
      isBlacklisted: parseOptionalFlag(entry.is_blacklisted),
      isInDex: parseOptionalFlag(entry.is_in_dex),
      holderCount: parseCount(entry.holder_count),
      lpHolderCount: parseCount(entry.lp_holder_count),
      creatorAddress: parseAddress(entry.creator_address),
      ownerAddress: parseAddress(entry.owner_address),
      honeypotWithSameCreator: parseOptionalFlag(
        entry.honeypot_with_same_creator,
      ),
      holders: parseHolderRows(entry.holders),
      lpHolders: parseHolderRows(entry.lp_holders),
      creatorPercent: parsePercent(entry.creator_percent),
      ownerPercent: parsePercent(entry.owner_percent),
    };
  } catch (error) {
    console.warn(
      `[goplus] enrichment skipped for ${contractAddress}:`,
      error instanceof Error ? error.message : error,
    );
    return null;
  }
}
