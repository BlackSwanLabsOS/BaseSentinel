import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  getLatestBlockNumber,
  getLogs,
  lightRpc,
  type EthLog,
} from "./alchemy";
import type { GoPlusTokenFlags, GoPlusHolderRow } from "./goplus";
import type { HoneypotIsFlags } from "./honeypotIs";
import type { ScanResult } from "./scanner";

export type LpStatus = "LOCKED" | "BURNED" | "UNLOCKED" | "UNKNOWN";

export interface MarketStructure {
  deployer_balance_pct: number | null;
  top_5_holders_pct: number | null;
  lp_status: LpStatus;
  is_whale_concentrated: boolean;
  notes: string[];
  /**
   * Best-effort extras when GoPlus holders/LP are thin.
   * Often filled from honeypot.is so dossier still feels premium.
   */
  holder_count: number | null;
  liquidity_usd: number | null;
  pair_address: string | null;
  /** Which sources contributed market fields (e.g. goplus, honeypot.is, live_logs). */
  market_sources: string[];
}

const DEAD_ADDRESSES = new Set(
  [
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0x0000000000000000000000000000000000000001",
    "0xdead000000000000000000000000000000000000",
  ].map((a) => a.toLowerCase()),
);

const DEX_TAGS = /uniswap|aerodrome|pancake|sushiswap|curve|balancer|pool|pair|router|virtuals|clanker|locker|lock/i;

/** ERC-20 selectors */
const SEL_TOTAL_SUPPLY = "0x18160ddd";
const SEL_BALANCE_OF = "0x70a08231";

/** keccak256("Transfer(address,address,uint256)") */
const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ZERO_TOPIC =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Shorter windows for dossier live-holder fallback — wide spans (60k+) often
 * 429 on public LOGS RPC and leave market_structure empty.
 */
/** ~4.5h @ 2s/block — mint discovery when code looks stub/hidden. */
const MINT_LOOKBACK_BLOCKS = 8_000;
/** ~1.7h — recent Transfer participants. */
const RECENT_TRANSFER_LOOKBACK_BLOCKS = 3_000;
const MAX_LOGS_TO_SCAN = 300;
const MAX_BALANCE_PROBES = 20;

function padAddress(address: string): string {
  return address.replace(/^0x/i, "").toLowerCase().padStart(64, "0");
}

function decodeUint256(hex: string | null): bigint | null {
  if (!hex || hex === "0x" || hex === "0x0") return 0n;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

async function ethCall(
  env: Env,
  to: string,
  data: string,
): Promise<string | null> {
  try {
    // Dossier is always a paid product — use Alchemy for light eth_call.
    // Heavy eth_getLogs stay on the public logs pool (see getLogs below).
    return await lightRpc<string>(env, "critical", "eth_call", [
      { to, data },
      "latest",
    ]);
  } catch (error) {
    console.warn(
      `[market] eth_call failed ${to}:`,
      error instanceof Error ? error.message : error,
    );
    return null;
  }
}

async function erc20BalanceOf(
  env: Env,
  token: string,
  holder: string,
): Promise<bigint | null> {
  const data = `${SEL_BALANCE_OF}${padAddress(holder)}`;
  const raw = await ethCall(env, token, data);
  return decodeUint256(raw);
}

async function erc20TotalSupply(
  env: Env,
  token: string,
): Promise<bigint | null> {
  const raw = await ethCall(env, token, SEL_TOTAL_SUPPLY);
  return decodeUint256(raw);
}

function pctOf(balance: bigint, supply: bigint): number | null {
  if (supply <= 0n) return null;
  // Keep 2 decimal places without float overflow for huge supplies.
  const scaled = (balance * 10000n) / supply;
  return Number(scaled) / 100;
}

function isDexLike(row: GoPlusHolderRow): boolean {
  if (row.isContract === true && row.tag && DEX_TAGS.test(row.tag)) return true;
  if (row.tag && DEX_TAGS.test(row.tag)) return true;
  return false;
}

function sumTopNonDexHolders(holders: GoPlusHolderRow[] | null): number | null {
  if (!holders || holders.length === 0) return null;
  const ranked = holders
    .filter((h) => !DEAD_ADDRESSES.has(h.address) && !isDexLike(h))
    .filter((h) => typeof h.percent === "number")
    .sort((a, b) => (b.percent ?? 0) - (a.percent ?? 0))
    .slice(0, 5);
  if (ranked.length === 0) return null;
  return ranked.reduce((sum, h) => sum + (h.percent ?? 0), 0);
}

function inferLpStatus(lpHolders: GoPlusHolderRow[] | null): LpStatus {
  if (!lpHolders || lpHolders.length === 0) return "UNKNOWN";

  let lockedPct = 0;
  let burnedPct = 0;
  let unlockedPct = 0;

  for (const row of lpHolders) {
    const pct = row.percent ?? 0;
    if (DEAD_ADDRESSES.has(row.address)) {
      burnedPct += pct;
      continue;
    }
    if (row.isLocked === true || (row.tag && /lock/i.test(row.tag))) {
      lockedPct += pct;
      continue;
    }
    unlockedPct += pct;
  }

  if (burnedPct >= 50) return "BURNED";
  if (lockedPct >= 50) return "LOCKED";
  if (unlockedPct > 0 || lockedPct + burnedPct > 0) return "UNLOCKED";
  return "UNKNOWN";
}

function topicAddress(topic: string | undefined): string | null {
  if (!topic || topic.length < 66) return null;
  return `0x${topic.slice(26).toLowerCase()}`;
}

function collectAddressesFromTransferLogs(logs: EthLog[]): string[] {
  const out = new Set<string>();
  for (const log of logs.slice(0, MAX_LOGS_TO_SCAN)) {
    const from = topicAddress(log.topics[1]);
    const to = topicAddress(log.topics[2]);
    if (to && !DEAD_ADDRESSES.has(to)) out.add(to);
    if (from && !DEAD_ADDRESSES.has(from)) out.add(from);
  }
  return [...out];
}

interface LiveHolderConcentration {
  top5Pct: number | null;
  topHolderPct: number | null;
  topHolder: string | null;
  probed: number;
  notes: string[];
}

/**
 * Fallback when GoPlus holders are empty: mint + recent Transfer logs → balanceOf.
 * Bounded lookback / candidate cap so dossier stays within Worker budget.
 */
async function liveHolderConcentrationFromLogs(
  env: Env,
  token: string,
  supply: bigint,
  options: { preferMintFirst?: boolean } = {},
): Promise<LiveHolderConcentration> {
  const notes: string[] = [];
  if (supply <= 0n) {
    return {
      top5Pct: null,
      topHolderPct: null,
      topHolder: null,
      probed: 0,
      notes: ["live holders skipped — totalSupply is 0"],
    };
  }

  let latest: number;
  try {
    latest = await getLatestBlockNumber(env);
  } catch (error) {
    notes.push(
      `live holders: eth_blockNumber failed (${error instanceof Error ? error.message : error})`,
    );
    return {
      top5Pct: null,
      topHolderPct: null,
      topHolder: null,
      probed: 0,
      notes,
    };
  }

  const mintFrom = Math.max(0, latest - MINT_LOOKBACK_BLOCKS);
  const recentFrom = Math.max(0, latest - RECENT_TRANSFER_LOOKBACK_BLOCKS);
  const tokenAddr = token.toLowerCase();

  const safeLogs = async (
    label: string,
    topics: Array<string | null>,
    fromBlock: number,
  ): Promise<EthLog[]> => {
    try {
      return await getLogs(env, {
        address: tokenAddr,
        topics,
        fromBlock: `0x${fromBlock.toString(16)}`,
        toBlock: `0x${latest.toString(16)}`,
      });
    } catch (error) {
      notes.push(
        `live holders: ${label} eth_getLogs failed (${error instanceof Error ? error.message.slice(0, 160) : error})`,
      );
      return [];
    }
  };

  let mintLogs: EthLog[] = [];
  let recentLogs: EthLog[] = [];

  // Stub / hidden-code tokens: mint recipient is usually the whale — query that first (sparse).
  if (options.preferMintFirst) {
    mintLogs = await safeLogs("mint", [TRANSFER_TOPIC, ZERO_TOPIC], mintFrom);
    if (mintLogs.length === 0) {
      recentLogs = await safeLogs("recent", [TRANSFER_TOPIC], recentFrom);
    }
  } else {
    recentLogs = await safeLogs("recent", [TRANSFER_TOPIC], recentFrom);
    mintLogs = await safeLogs("mint", [TRANSFER_TOPIC, ZERO_TOPIC], mintFrom);
  }

  const candidates = collectAddressesFromTransferLogs([
    ...mintLogs,
    ...recentLogs,
  ]).slice(0, MAX_BALANCE_PROBES);

  notes.push(
    `live holders: mintLogs=${mintLogs.length} recentLogs=${recentLogs.length} candidates=${candidates.length}`,
  );

  if (candidates.length === 0) {
    notes.push("live holders: no Transfer counterparts in lookback window");
    return {
      top5Pct: null,
      topHolderPct: null,
      topHolder: null,
      probed: 0,
      notes,
    };
  }

  const balances = await Promise.all(
    candidates.map(async (holder) => {
      const bal = await erc20BalanceOf(env, tokenAddr, holder);
      return { holder, bal: bal ?? 0n };
    }),
  );

  const ranked = balances
    .filter((row) => row.bal > 0n)
    .sort((a, b) => (a.bal === b.bal ? 0 : a.bal > b.bal ? -1 : 1));

  if (ranked.length === 0) {
    notes.push("live holders: all probed balances are 0");
    return {
      top5Pct: null,
      topHolderPct: null,
      topHolder: null,
      probed: candidates.length,
      notes,
    };
  }

  const top5 = ranked.slice(0, 5);
  let top5Bal = 0n;
  for (const row of top5) top5Bal += row.bal;
  const top5Pct = pctOf(top5Bal, supply);
  const topHolderPct = pctOf(top5[0].bal, supply);

  notes.push(
    `top_5_holders_pct from Transfer logs + balanceOf (recent ${RECENT_TRANSFER_LOOKBACK_BLOCKS} / mint ${MINT_LOOKBACK_BLOCKS} blocks)`,
  );

  return {
    top5Pct,
    topHolderPct,
    topHolder: top5[0].holder,
    probed: ranked.length,
    notes,
  };
}

function enrichFromHoneypotIs(
  honeypotIs: HoneypotIsFlags | null | Omit<HoneypotIsFlags, "rawAvailable">,
  notes: string[],
  sources: string[],
): {
  holder_count: number | null;
  liquidity_usd: number | null;
  pair_address: string | null;
} {
  // Scan dossier stores public honeypot.is (rawAvailable stripped) — treat null as missing.
  if (!honeypotIs) {
    return { holder_count: null, liquidity_usd: null, pair_address: null };
  }
  if ("rawAvailable" in honeypotIs && honeypotIs.rawAvailable === false) {
    return { holder_count: null, liquidity_usd: null, pair_address: null };
  }

  const holder_count =
    typeof honeypotIs.holderCount === "number" &&
    Number.isFinite(honeypotIs.holderCount)
      ? Math.max(0, Math.floor(honeypotIs.holderCount))
      : null;
  const liquidity_usd =
    typeof honeypotIs.liquidityUsd === "number" &&
    Number.isFinite(honeypotIs.liquidityUsd)
      ? Math.round(honeypotIs.liquidityUsd * 100) / 100
      : null;
  const pair_address = honeypotIs.pairAddress?.toLowerCase() ?? null;

  const hasSignal =
    holder_count !== null || liquidity_usd !== null || pair_address !== null;
  if (!hasSignal && !honeypotIs.simulationSuccess) {
    return { holder_count: null, liquidity_usd: null, pair_address: null };
  }

  sources.push("honeypot.is");

  if (holder_count !== null) {
    notes.push(`holder_count from honeypot.is: ${holder_count}`);
  }
  if (liquidity_usd !== null) {
    notes.push(`liquidity_usd from honeypot.is (pair pool est.): $${liquidity_usd}`);
  }
  if (pair_address) {
    notes.push(`pair_address from honeypot.is: ${pair_address}`);
  }
  if (honeypotIs.simulationSuccess) {
    const buy = honeypotIs.buyTax;
    const sell = honeypotIs.sellTax;
    if (buy !== null || sell !== null) {
      notes.push(
        `honeypot.is simulated taxes: buy=${buy ?? "n/a"}% sell=${sell ?? "n/a"}%`,
      );
    }
  }

  return { holder_count, liquidity_usd, pair_address };
}

/**
 * Market structure for the premium dossier (holders / deployer share / LP hints).
 */
export async function analyzeMarketStructure(
  env: Env,
  scan: ScanResult,
): Promise<MarketStructure> {
  const notes: string[] = [];
  const market_sources: string[] = [];
  const goplus = scan.dossier.goplus as GoPlusTokenFlags | null;
  const honeypotIs = scan.dossier.honeypotIs as HoneypotIsFlags | null;

  if (goplus) {
    market_sources.push("goplus");
  }

  const deployer =
    goplus?.creatorAddress ?? goplus?.ownerAddress ?? null;

  let deployer_balance_pct: number | null =
    goplus?.creatorPercent ?? goplus?.ownerPercent ?? null;

  const supply = await erc20TotalSupply(env, scan.address);
  if (supply !== null) {
    market_sources.push("eth_call");
  }

  // Prefer live balanceOf(deployer) / totalSupply when deployer is known.
  if (deployer) {
    try {
      const bal = await erc20BalanceOf(env, scan.address, deployer);
      if (supply !== null && bal !== null) {
        const live = pctOf(bal, supply);
        if (live !== null) {
          deployer_balance_pct = live;
          notes.push("deployer_balance_pct from live eth_call balanceOf");
        }
      }
    } catch {
      notes.push("deployer live balanceOf failed; using GoPlus percent if any");
    }
  } else {
    notes.push("deployer address unknown — skipped live balanceOf(deployer)");
  }

  let top_5_holders_pct = sumTopNonDexHolders(goplus?.holders ?? null);
  if (top_5_holders_pct !== null) {
    notes.push("top_5_holders_pct from GoPlus holders (non-DEX wallets)");
  } else if (supply !== null) {
    const preferMintFirst = scan.reasons.some(
      (r) =>
        r === "Stub_Or_Hidden_Bytecode" ||
        r === "Eof_Or_Reserved_Bytecode_Prefix" ||
        r === "Empty_Or_EOA_No_Bytecode" ||
        r === "Admin_Policy_Surface_Detected",
    );
    const live = await liveHolderConcentrationFromLogs(
      env,
      scan.address,
      supply,
      { preferMintFirst },
    );
    notes.push(...live.notes);
    if (live.probed > 0 || live.top5Pct !== null) {
      market_sources.push("live_logs");
    }
    top_5_holders_pct = live.top5Pct;
    // When GoPlus omits creator, treat dominant mint/holder as concentration proxy.
    if (
      deployer_balance_pct === null &&
      typeof live.topHolderPct === "number" &&
      live.topHolderPct >= 10
    ) {
      deployer_balance_pct = live.topHolderPct;
      notes.push(
        `deployer_balance_pct proxy = top Transfer-log holder ${live.topHolder} (${live.topHolderPct}%)`,
      );
    }
  } else {
    notes.push(
      "top_5_holders_pct unavailable (GoPlus holders empty; totalSupply eth_call failed)",
    );
  }

  let lp_status = inferLpStatus(goplus?.lpHolders ?? null);
  if (lp_status === "UNKNOWN") {
    notes.push(
      "lp_status UNKNOWN — no usable GoPlus lp_holders lock/burn signal (liquidity_usd/pair may still be set from honeypot.is)",
    );
  } else {
    notes.push(`lp_status inferred from GoPlus lp_holders (${lp_status})`);
  }

  const hp = enrichFromHoneypotIs(honeypotIs, notes, market_sources);

  const is_whale_concentrated =
    (typeof top_5_holders_pct === "number" && top_5_holders_pct >= 50) ||
    (typeof deployer_balance_pct === "number" && deployer_balance_pct >= 10);

  void resolveNetwork(env);

  notes.push(
    "market_structure is best-effort enrichment on top of security scan — not a substitute for verdict",
  );

  return {
    deployer_balance_pct:
      deployer_balance_pct !== null
        ? Math.round(deployer_balance_pct * 100) / 100
        : null,
    top_5_holders_pct:
      top_5_holders_pct !== null
        ? Math.round(top_5_holders_pct * 100) / 100
        : null,
    lp_status,
    is_whale_concentrated,
    notes,
    holder_count: hp.holder_count,
    liquidity_usd: hp.liquidity_usd,
    pair_address: hp.pair_address,
    market_sources: [...new Set(market_sources)],
  };
}
