import type { Env } from "../types";
import {
  getUniswapV2Factory,
  getUsdcContractAddress,
  getWethAddress,
  resolveNetwork,
} from "../config/network";
import { getLatestBlockNumber, getLogs } from "./alchemy";
import { normalizeEthereumAddress } from "../utils/validation";

/** keccak256("PairCreated(address,address,address,uint256)") */
export const PAIR_CREATED_TOPIC =
  "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9";

/** Max blocks to scan per cron tick (keeps eth_getLogs cheap). */
export const MAX_BLOCK_SPAN = 1_500;

/** On first run, only look back this many blocks. */
export const INITIAL_LOOKBACK_BLOCKS = 500;

export interface DiscoveredToken {
  address: string;
  pair: string;
  pairedWith: string;
  blockNumber: number;
  txHash: string;
}

function addressFromTopic(topic: string): string {
  return `0x${topic.slice(-40)}`.toLowerCase();
}

function addressFromDataWord(data: string, wordIndex: number): string {
  const hex = data.replace(/^0x/i, "");
  const start = wordIndex * 64;
  const word = hex.slice(start, start + 64);
  return `0x${word.slice(-40)}`.toLowerCase();
}

function toHexBlock(block: number): string {
  return `0x${block.toString(16)}`;
}

/**
 * Discovers newly listed tokens from Uniswap V2 PairCreated events.
 * Returns unique token addresses (excluding WETH/USDC).
 */
export async function discoverRecentTokens(
  env: Env,
  fromBlockInclusive: number,
): Promise<{
  tokens: DiscoveredToken[];
  toBlock: number;
  fromBlock: number;
  factory: string;
}> {
  const network = resolveNetwork(env);
  const factory = getUniswapV2Factory(network);
  const latest = await getLatestBlockNumber(env);

  let fromBlock = Math.max(0, fromBlockInclusive);
  if (fromBlock > latest) {
    return { tokens: [], toBlock: latest, fromBlock: latest, factory };
  }

  // Cap span so a long outage doesn't explode the query.
  if (latest - fromBlock > MAX_BLOCK_SPAN) {
    fromBlock = latest - MAX_BLOCK_SPAN;
  }

  const logs = await getLogs(env, {
    address: factory,
    topics: [PAIR_CREATED_TOPIC],
    fromBlock: toHexBlock(fromBlock),
    toBlock: toHexBlock(latest),
  });

  const skip = new Set(
    [
      getWethAddress(network),
      getUsdcContractAddress(network),
    ].map((a) => a.toLowerCase()),
  );

  const byAddress = new Map<string, DiscoveredToken>();

  for (const log of logs) {
    if (!log.topics || log.topics.length < 3) continue;

    const token0 = addressFromTopic(log.topics[1]);
    const token1 = addressFromTopic(log.topics[2]);
    const pair = addressFromDataWord(log.data, 0);
    const blockNumber = Number.parseInt(log.blockNumber, 16);

    for (const [token, pairedWith] of [
      [token0, token1],
      [token1, token0],
    ] as const) {
      if (skip.has(token)) continue;
      const normalized = normalizeEthereumAddress(token);
      if (!normalized) continue;

      // Keep the newest sighting if duplicates appear in the window.
      byAddress.set(normalized, {
        address: normalized,
        pair,
        pairedWith,
        blockNumber,
        txHash: log.transactionHash,
      });
    }
  }

  return {
    tokens: [...byAddress.values()],
    toBlock: latest,
    fromBlock,
    factory,
  };
}

export async function resolveCronFromBlock(
  env: Env,
  lastProcessedBlock: number | null,
): Promise<number> {
  if (lastProcessedBlock !== null && lastProcessedBlock >= 0) {
    return lastProcessedBlock + 1;
  }

  const latest = await getLatestBlockNumber(env);
  return Math.max(0, latest - INITIAL_LOOKBACK_BLOCKS);
}
