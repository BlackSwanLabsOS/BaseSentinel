import type { Env } from "../types";
import {
  getUsdcContractAddress,
  getVirtualTokenAddress,
  getWethAddress,
  resolveNetwork,
} from "../config/network";
import {
  getDexFactories,
  type DexFactorySource,
} from "../config/dexFactories";
import { getLatestBlockNumber, getLogs, type EthLog } from "./alchemy";
import { normalizeEthereumAddress } from "../utils/validation";

/** Max block span covered per cron tick (catch-up after delays). */
export const MAX_BLOCK_SPAN = 300;

/** On first run, only look back this many blocks. */
export const INITIAL_LOOKBACK_BLOCKS = 150;

export interface DiscoveredToken {
  address: string;
  pair: string;
  pairedWith: string;
  blockNumber: number;
  txHash: string;
  source: string;
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

function parseFactoryLog(
  source: DexFactorySource,
  log: EthLog,
): {
  token0: string;
  token1: string;
  pool: string;
  /** Clanker / Virtuals emit one created token; AMM factories emit a pair (scan both sides). */
  dualSided: boolean;
} | null {
  if (!log.topics || log.topics.length < 2) return null;

  switch (source.kind) {
    case "univ2_pair_created": {
      if (log.topics.length < 3) return null;
      return {
        token0: addressFromTopic(log.topics[1]),
        token1: addressFromTopic(log.topics[2]),
        // data: pair, uint
        pool: addressFromDataWord(log.data, 0),
        dualSided: true,
      };
    }
    case "aero_pool_created": {
      if (log.topics.length < 3) return null;
      return {
        token0: addressFromTopic(log.topics[1]),
        token1: addressFromTopic(log.topics[2]),
        // topics: sig, token0, token1, stable — data: pool, uint
        pool: addressFromDataWord(log.data, 0),
        dualSided: true,
      };
    }
    case "univ3_pool_created": {
      if (log.topics.length < 3) return null;
      return {
        token0: addressFromTopic(log.topics[1]),
        token1: addressFromTopic(log.topics[2]),
        // data: tickSpacing, pool
        pool: addressFromDataWord(log.data, 1),
        dualSided: true,
      };
    }
    case "clanker_token_created": {
      // topics: sig, tokenAddress, tokenAdmin
      // non-indexed data word7 = poolHook, word9 = pairedToken (ABI layout verified on-chain)
      if (log.topics.length < 3) return null;
      if (!log.data || log.data.length < 2 + 10 * 64) return null;
      return {
        token0: addressFromTopic(log.topics[1]),
        token1: addressFromDataWord(log.data, 9),
        pool: addressFromDataWord(log.data, 7),
        dualSided: false,
      };
    }
    case "virtuals_launched": {
      // topics: sig, token (fun), pair — paired with $VIRTUAL
      if (log.topics.length < 3) return null;
      return {
        token0: addressFromTopic(log.topics[1]),
        token1: getVirtualTokenAddress("base").toLowerCase(),
        pool: addressFromTopic(log.topics[2]),
        dualSided: false,
      };
    }
    case "virtuals_graduated": {
      // topics: sig, funToken — data word0 = agentToken (scan the graduated Agent ERC20)
      if (!log.data || log.data.length < 2 + 64) return null;
      return {
        token0: addressFromDataWord(log.data, 0),
        token1: addressFromTopic(log.topics[1]),
        pool: addressFromTopic(log.topics[1]),
        dualSided: false,
      };
    }
    default:
      return null;
  }
}

/**
 * Discovers newly listed tokens from Base DEX factories + Clanker + Virtuals Bonding.
 */
export async function discoverRecentTokens(
  env: Env,
  fromBlockInclusive: number,
): Promise<{
  tokens: DiscoveredToken[];
  toBlock: number;
  fromBlock: number;
  factories: string[];
  bySource: Record<string, number>;
}> {
  const network = resolveNetwork(env);
  const factories = getDexFactories(network);
  const latest = await getLatestBlockNumber(env);

  let fromBlock = Math.max(0, fromBlockInclusive);
  if (fromBlock > latest) {
    return {
      tokens: [],
      toBlock: latest,
      fromBlock: latest,
      factories: factories.map((f) => f.address),
      bySource: {},
    };
  }

  // Cap span after downtime to limit RPC usage.
  if (latest - fromBlock > MAX_BLOCK_SPAN) {
    fromBlock = latest - MAX_BLOCK_SPAN;
  }

  const skip = new Set(
    [
      getWethAddress(network),
      getUsdcContractAddress(network),
      getVirtualTokenAddress(network),
    ]
      .filter((a) => a && !/^0x0{40}$/i.test(a))
      .map((a) => a.toLowerCase()),
  );

  const byAddress = new Map<string, DiscoveredToken>();
  const bySource: Record<string, number> = {};

  // Parallel per factory — one failing source must not stop the tick.
  const logSets = await Promise.all(
    factories.map(async (factory) => {
      try {
        const logs = await getLogs(env, {
          address: factory.address.toLowerCase(),
          topics: [factory.topic],
          fromBlock: toHexBlock(fromBlock),
          toBlock: toHexBlock(latest),
        });
        return { factory, logs, error: null as string | null };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[discovery] ${factory.id} failed:`, message);
        return { factory, logs: [] as EthLog[], error: message };
      }
    }),
  );

  for (const { factory, logs } of logSets) {
    for (const log of logs) {
      const parsed = parseFactoryLog(factory, log);
      if (!parsed) continue;

      const blockNumber = Number.parseInt(log.blockNumber, 16);

      const sides: Array<[string, string]> = parsed.dualSided
        ? [
            [parsed.token0, parsed.token1],
            [parsed.token1, parsed.token0],
          ]
        : [[parsed.token0, parsed.token1]];

      for (const [token, pairedWith] of sides) {
        if (skip.has(token)) continue;
        const normalized = normalizeEthereumAddress(token);
        if (!normalized) continue;

        const existing = byAddress.get(normalized);
        if (!existing || blockNumber >= existing.blockNumber) {
          byAddress.set(normalized, {
            address: normalized,
            pair: parsed.pool,
            pairedWith,
            blockNumber,
            txHash: log.transactionHash,
            source: factory.id,
          });
        }
      }
    }
  }

  for (const token of byAddress.values()) {
    bySource[token.source] = (bySource[token.source] ?? 0) + 1;
  }

  return {
    tokens: [...byAddress.values()],
    toBlock: latest,
    fromBlock,
    factories: factories.map((f) => f.address),
    bySource,
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
