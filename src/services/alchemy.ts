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

/** Default public Base RPCs for discovery / non-payment reads. */
const DEFAULT_LOGS_RPC_BY_NETWORK: Record<NetworkId, string> = {
  base: "https://mainnet.base.org",
  "base-sepolia": "https://sepolia.base.org",
};

/** Alchemy Free Base eth_getLogs max range. */
const ALCHEMY_LOGS_CHUNK_BLOCKS = 10;
/** Public / dedicated logs RPC — larger spans (probe-verified on mainnet.base.org). */
const LOGS_RPC_CHUNK_BLOCKS = 2000;

function trimKey(key: string): string {
  return key.trim();
}

function looksLikeAlchemyUrl(url: string): boolean {
  return /alchemy\.com/i.test(url);
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

function resolveCriticalRpcUrl(env: Env): { url: string; headers: Record<string, string> } {
  const network = resolveNetwork(env);
  const override = env.CRITICAL_RPC_URL?.trim();
  if (override) {
    return { url: override, headers: {} };
  }
  if (!env.ALCHEMY_API_KEY) {
    throw new Error("ALCHEMY_API_KEY or CRITICAL_RPC_URL is required for payment RPC");
  }
  const apiKey = trimKey(env.ALCHEMY_API_KEY);
  return {
    url: `${getAlchemyRpcBase(network)}/${apiKey}`,
    headers: { Authorization: `Bearer ${apiKey}` },
  };
}

function resolveLogsRpcUrl(env: Env): string {
  const network = resolveNetwork(env);
  const override = env.LOGS_RPC_URL?.trim();
  if (override) return override;
  return DEFAULT_LOGS_RPC_BY_NETWORK[network];
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
 * Discovery / scan reads: LOGS_RPC_URL (default public Base).
 * Keeps mass eth_getLogs + bytecode off Alchemy CU.
 */
export async function logsRpc<T>(
  env: Env,
  method: string,
  params: unknown[],
): Promise<T> {
  return postRpc<T>(resolveLogsRpcUrl(env), method, params);
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

export async function getLatestBlockNumber(env: Env): Promise<number> {
  const hex = await logsRpc<string>(env, "eth_blockNumber", []);
  return Number.parseInt(hex, 16);
}

function toHexBlock(block: number): string {
  return `0x${Math.max(0, block).toString(16)}`;
}

function logsChunkSize(env: Env): number {
  const url = resolveLogsRpcUrl(env);
  return looksLikeAlchemyUrl(url) ? ALCHEMY_LOGS_CHUNK_BLOCKS : LOGS_RPC_CHUNK_BLOCKS;
}

/**
 * Mass discovery eth_getLogs via LOGS_RPC (large chunks on public nodes).
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
    // Adaptive split when public node rejects span / payload size.
    if (to > from && chunkSize > 50) {
      const mid = Math.floor((from + to) / 2);
      const left = await fetchLogsChunk(env, filter, from, mid, Math.floor(chunkSize / 2));
      const right = await fetchLogsChunk(env, filter, mid + 1, to, Math.floor(chunkSize / 2));
      return [...left, ...right];
    }
    throw error;
  }
}
