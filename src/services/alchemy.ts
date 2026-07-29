import type { Env } from "../types";
import { getAlchemyRpcBase, resolveNetwork } from "../config/network";

interface AlchemyRpcErrorBody {
  code?: number;
  message?: string;
}

interface AlchemyRpcResponse<T> {
  jsonrpc?: string;
  id?: number;
  result?: T;
  error?: AlchemyRpcErrorBody;
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

/** Public Base RPCs as fallback when Alchemy rejects a call (e.g. eth_getLogs limits). */
const PUBLIC_RPC_BY_NETWORK = {
  base: "https://mainnet.base.org",
  "base-sepolia": "https://sepolia.base.org",
} as const;

/** eth_getLogs chunk size (Alchemy-safe range). */
const GET_LOGS_CHUNK_BLOCKS = 10;

function trimKey(key: string): string {
  return key.trim();
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
  let data: AlchemyRpcResponse<T> | null = null;
  try {
    data = JSON.parse(rawText) as AlchemyRpcResponse<T>;
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

/**
 * Low-level JSON-RPC call: Alchemy first, public Base RPC fallback on failure.
 */
export async function alchemyRpc<T>(
  env: Env,
  method: string,
  params: unknown[],
): Promise<T> {
  if (!env.ALCHEMY_API_KEY) {
    throw new Error("ALCHEMY_API_KEY is not configured");
  }

  const network = resolveNetwork(env);
  const apiKey = trimKey(env.ALCHEMY_API_KEY);
  const alchemyUrl = `${getAlchemyRpcBase(network)}/${apiKey}`;
  const publicUrl = PUBLIC_RPC_BY_NETWORK[network];

  try {
    // Prefer URL-key style (classic). Also send Bearer for newer alch_ keys.
    return await postRpc<T>(alchemyUrl, method, params, {
      Authorization: `Bearer ${apiKey}`,
    });
  } catch (alchemyError) {
    try {
      return await postRpc<T>(publicUrl, method, params);
    } catch {
      const message =
        alchemyError instanceof Error ? alchemyError.message : String(alchemyError);
      throw new Error(message);
    }
  }
}

/**
 * Fetches raw contract bytecode via Alchemy JSON-RPC for the configured network.
 */
export async function getContractBytecode(
  contractAddress: string,
  env: Env,
): Promise<string> {
  const bytecode = await alchemyRpc<string | null>(env, "eth_getCode", [
    contractAddress,
    "latest",
  ]);

  // Empty accounts return "0x" — analyzer classifies these as Empty_Contract.
  if (!bytecode || bytecode === "0x0") {
    return "0x";
  }

  return bytecode;
}

/**
 * Fetches a transaction receipt for the configured network.
 * Returns null when the transaction is unknown / not yet mined.
 */
export async function getTransactionReceipt(
  txHash: string,
  env: Env,
): Promise<TransactionReceipt | null> {
  const receipt = await alchemyRpc<TransactionReceipt | null>(
    env,
    "eth_getTransactionReceipt",
    [txHash],
  );

  return receipt ?? null;
}

export async function getLatestBlockNumber(env: Env): Promise<number> {
  const hex = await alchemyRpc<string>(env, "eth_blockNumber", []);
  return Number.parseInt(hex, 16);
}

export interface EthLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex?: string;
}

function toHexBlock(block: number): string {
  return `0x${Math.max(0, block).toString(16)}`;
}

/**
 * eth_getLogs in small chunks — avoids Alchemy HTTP 400 on large block ranges.
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

  const all: EthLog[] = [];

  for (let start = from; start <= to; start += GET_LOGS_CHUNK_BLOCKS) {
    const end = Math.min(to, start + GET_LOGS_CHUNK_BLOCKS - 1);
    const chunk = await alchemyRpc<EthLog[]>(env, "eth_getLogs", [
      {
        address: filter.address,
        topics: filter.topics,
        fromBlock: toHexBlock(start),
        toBlock: toHexBlock(end),
      },
    ]);
    if (chunk?.length) {
      all.push(...chunk);
    }
  }

  return all;
}
