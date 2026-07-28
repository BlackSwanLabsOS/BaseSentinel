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

/**
 * Low-level JSON-RPC call to Alchemy for the configured network.
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
  const url = `${getAlchemyRpcBase(network)}/${env.ALCHEMY_API_KEY}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
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
    throw new Error(`Failed to reach Alchemy RPC: ${message}`);
  }

  if (!response.ok) {
    throw new Error(
      `Alchemy RPC request failed with HTTP ${response.status} ${response.statusText}`,
    );
  }

  const data = (await response.json()) as AlchemyRpcResponse<T>;

  if (data.error) {
    throw new Error(
      `Alchemy RPC error: ${data.error.message ?? JSON.stringify(data.error)}`,
    );
  }

  return data.result as T;
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

export async function getLogs(
  env: Env,
  filter: {
    address: string;
    topics: Array<string | null>;
    fromBlock: string;
    toBlock: string;
  },
): Promise<EthLog[]> {
  const logs = await alchemyRpc<EthLog[]>(env, "eth_getLogs", [filter]);
  return logs ?? [];
}
