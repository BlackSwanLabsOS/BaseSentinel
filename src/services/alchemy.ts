import type { Env } from "../types";
import { getAlchemyRpcBase, resolveNetwork, type NetworkId } from "../config/network";

interface RpcErrorBody {
  code?: number;
  message?: string;
}

interface RpcResponse<T> {
  jsonrpc?: string;
  id?: number;
  result?: T;
  error?: RpcErrorBody;
}

export interface TransactionReceiptLog {
  address: string;
  topics: string[];
  data: string;
}

export interface TransactionReceipt {
  status: string | null;
  to: string | null;
  from: string | null;
  logs: TransactionReceiptLog[];
  transactionHash?: string;
  blockNumber?: string;
}

export interface EthLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex?: string;
}

/** Public Base discovery pool (round-robin on 429 / timeout / usage limits). */
const DEFAULT_BASE_LOGS_POOL = [
  "https://mainnet.base.org",
  "https://base.gateway.tenderly.co",
  "https://1rpc.io/base",
  "https://base-mainnet.public.blastapi.io",
  "https://base.meowrpc.com",
] as const;

const DEFAULT_SEPOLIA_LOGS_POOL = ["https://sepolia.base.org"] as const;

/** Alchemy Free Base eth_getLogs max range. */
const ALCHEMY_LOGS_CHUNK_BLOCKS = 10;
/** Public / dedicated logs RPC — larger spans. */
const LOGS_RPC_CHUNK_BLOCKS = 2000;

/** Sticky index so successful endpoints stay preferred across calls. */
let logsRpcCursor = 0;

function trimKey(key: string): string {
  return key.trim();
}

function looksLikeAlchemyUrl(url: string): boolean {
  return /alchemy\.com/i.test(url);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableLogsError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    /\b429\b/.test(msg) ||
    /\b520\b|\b521\b|\b522\b|\b523\b|\b524\b|\b525\b|\b526\b|\b530\b/.test(msg) ||
    /-32016\b/.test(msg) ||
    /rate limit/i.test(msg) ||
    /usage limit/i.test(msg) ||
    /too many requests/i.test(msg) ||
    /capacity/i.test(msg) ||
    /quota/i.test(msg) ||
    /upgrade here/i.test(msg) ||
    /error code:\s*52\d/i.test(msg) ||
    /timeout/i.test(msg) ||
    /timed out/i.test(msg) ||
    /Failed to reach RPC/i.test(msg) ||
    /\b502\b/.test(msg) ||
    /\b503\b/.test(msg) ||
    /\b504\b/.test(msg) ||
    /HTTP 5\d\d/i.test(msg) ||
    /ECONNRESET|ENOTFOUND|EAI_AGAIN|fetch failed/i.test(msg) ||
    // Free / hostile public nodes — rotate instead of binary-splitting to 10-block hell.
    /up to a \d+ block range/i.test(msg) ||
    /block range should work/i.test(msg) ||
    /limited to a [\d,]+ range/i.test(msg) ||
    /limited to 0\s*-\s*\d+ blocks/i.test(msg) ||
    /eth_getLogs is not supported/i.test(msg) ||
    /method eth_getLogs/i.test(msg)
  );
}

function isRangeOrPayloadError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  if (isRetryableLogsError(error)) return false;
  return /block range|query returned more than|response size|too large|log response size|exceeds max/i.test(
    msg,
  );
}

async function postRpc<T>(
  url: string,
  method: string,
  params: unknown[],
  headers: Record<string, string> = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method,
        params,
      }),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to reach RPC (${method}): ${message}`);
  }

  const rawText = await response.text();
  let data: RpcResponse<T> | null = null;
  try {
    data = JSON.parse(rawText) as RpcResponse<T>;
  } catch {
    // keep raw text for error
  }

  if (!response.ok) {
    const detail = (rawText || response.statusText).slice(0, 300);
    throw new Error(
      `RPC ${method} failed with HTTP ${response.status}: ${detail}`,
    );
  }

  if (!data) {
    throw new Error(`RPC ${method} returned non-JSON body`);
  }

  if (data.error) {
    throw new Error(
      `RPC ${method} error: ${data.error.message ?? JSON.stringify(data.error)}`,
    );
  }

  return data.result as T;
}

function resolveCriticalRpcUrl(env: Env): {
  url: string;
  headers: Record<string, string>;
} {
  const network = resolveNetwork(env);
  const override = env.CRITICAL_RPC_URL?.trim();
  if (override) {
    return { url: override, headers: {} };
  }
  if (!env.ALCHEMY_API_KEY) {
    throw new Error(
      "ALCHEMY_API_KEY or CRITICAL_RPC_URL is required for payment RPC",
    );
  }
  const apiKey = trimKey(env.ALCHEMY_API_KEY);
  return {
    url: `${getAlchemyRpcBase(network)}/${apiKey}`,
    headers: { Authorization: `Bearer ${apiKey}` },
  };
}

/**
 * Build logs RPC pool.
 * `LOGS_RPC_URL` may be a single URL or comma-separated list (tried first),
 * then remaining public defaults are appended for failover.
 */
export function resolveLogsRpcPool(env: Env): string[] {
  const network = resolveNetwork(env);
  const defaults =
    network === "base"
      ? [...DEFAULT_BASE_LOGS_POOL]
      : [...DEFAULT_SEPOLIA_LOGS_POOL];

  const override = env.LOGS_RPC_URL?.trim();
  if (!override) {
    return defaults;
  }

  const preferred = override
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (preferred.length === 0) {
    return defaults;
  }

  return [...new Set([...preferred, ...defaults])];
}

/**
 * Critical path only: payment proof / receipts.
 * Uses CRITICAL_RPC_URL or Alchemy — no public fallback (x402 must stay deterministic).
 */
export async function criticalRpc<T>(
  env: Env,
  method: string,
  params: unknown[],
): Promise<T> {
  const { url, headers } = resolveCriticalRpcUrl(env);
  return postRpc<T>(url, method, params, headers);
}

/**
 * Discovery / scan reads via public RPC pool with round-robin failover.
 * On 429 / timeout / 5xx: short backoff, then next endpoint.
 */
export async function logsRpc<T>(
  env: Env,
  method: string,
  params: unknown[],
): Promise<T> {
  const pool = resolveLogsRpcPool(env);
  if (pool.length === 0) {
    throw new Error("No LOGS RPC endpoints configured");
  }

  const start = ((logsRpcCursor % pool.length) + pool.length) % pool.length;
  let lastError: unknown;

  for (let attempt = 0; attempt < pool.length; attempt++) {
    const idx = (start + attempt) % pool.length;
    const url = pool[idx];
    try {
      const result = await postRpc<T>(url, method, params);
      logsRpcCursor = idx;
      return result;
    } catch (error) {
      lastError = error;
      const retryable = isRetryableLogsError(error);
      const moreLeft = attempt < pool.length - 1;
      if (!retryable || !moreLeft) {
        break;
      }
      const waitMs = 1000 + attempt * 500;
      console.warn(
        `[logsRpc] ${method} failed on ${url} (${error instanceof Error ? error.message.slice(0, 120) : error}); rotating in ${waitMs}ms`,
      );
      await sleep(waitMs);
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(String(lastError ?? "logsRpc failed"));
}

/** @deprecated Prefer criticalRpc / logsRpc. Alias → criticalRpc. */
export async function alchemyRpc<T>(
  env: Env,
  method: string,
  params: unknown[],
): Promise<T> {
  return criticalRpc(env, method, params);
}

export async function getContractBytecode(
  contractAddress: string,
  env: Env,
): Promise<string> {
  const bytecode = await logsRpc<string | null>(env, "eth_getCode", [
    contractAddress,
    "latest",
  ]);

  if (!bytecode || bytecode === "0x0") {
    return "0x";
  }

  return bytecode;
}

/**
 * Payment settlement: Alchemy / CRITICAL_RPC only.
 */
export async function getTransactionReceipt(
  txHash: string,
  env: Env,
): Promise<TransactionReceipt | null> {
  const receipt = await criticalRpc<TransactionReceipt | null>(
    env,
    "eth_getTransactionReceipt",
    [txHash],
  );

  return receipt ?? null;
}

/**
 * Block timestamp (unix seconds) for payment age checks. Critical RPC only.
 */
export async function getBlockTimestampSeconds(
  blockNumberHex: string,
  env: Env,
): Promise<number | null> {
  const block = await criticalRpc<{ timestamp?: string } | null>(
    env,
    "eth_getBlockByNumber",
    [blockNumberHex, false],
  );
  if (!block?.timestamp) return null;
  const ts = Number.parseInt(block.timestamp, 16);
  return Number.isFinite(ts) ? ts : null;
}

export async function getLatestBlockNumber(env: Env): Promise<number> {
  const hex = await logsRpc<string>(env, "eth_blockNumber", []);
  return Number.parseInt(hex, 16);
}

function toHexBlock(block: number): string {
  return `0x${Math.max(0, block).toString(16)}`;
}

function logsChunkSize(env: Env): number {
  const pool = resolveLogsRpcPool(env);
  if (pool.some((url) => looksLikeAlchemyUrl(url))) {
    return ALCHEMY_LOGS_CHUNK_BLOCKS;
  }
  return LOGS_RPC_CHUNK_BLOCKS;
}

/**
 * Mass discovery eth_getLogs via LOGS RPC pool (large chunks on public nodes).
 */
export async function getLogs(
  env: Env,
  filter: {
    address: string;
    topics: Array<string | null>;
    fromBlock: string;
    toBlock: string;
  },
): Promise<EthLog[]> {
  const from = Number.parseInt(filter.fromBlock, 16);
  const to = Number.parseInt(filter.toBlock, 16);

  if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) {
    return [];
  }

  const chunkSize = logsChunkSize(env);
  const all: EthLog[] = [];

  for (let start = from; start <= to; start += chunkSize) {
    const end = Math.min(to, start + chunkSize - 1);
    const chunk = await fetchLogsChunk(env, filter, start, end, chunkSize);
    if (chunk.length) {
      all.push(...chunk);
    }
  }

  return all;
}

async function fetchLogsChunk(
  env: Env,
  filter: {
    address: string;
    topics: Array<string | null>;
  },
  from: number,
  to: number,
  chunkSize: number,
): Promise<EthLog[]> {
  try {
    const chunk = await logsRpc<EthLog[]>(env, "eth_getLogs", [
      {
        address: filter.address,
        topics: filter.topics,
        fromBlock: toHexBlock(from),
        toBlock: toHexBlock(to),
      },
    ]);
    return chunk ?? [];
  } catch (error) {
    // Adaptive split for true oversized responses (not per-provider free caps —
    // those rotate via isRetryableLogsError).
    if (to > from && isRangeOrPayloadError(error)) {
      const mid = Math.floor((from + to) / 2);
      if (mid < from || mid >= to) {
        throw error;
      }
      const left = await fetchLogsChunk(
        env,
        filter,
        from,
        mid,
        Math.max(1, Math.floor(chunkSize / 2)),
      );
      const right = await fetchLogsChunk(
        env,
        filter,
        mid + 1,
        to,
        Math.max(1, Math.floor(chunkSize / 2)),
      );
      return [...left, ...right];
    }
    throw error;
  }
}
