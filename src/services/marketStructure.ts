import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import { alchemyRpc } from "./alchemy";
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
    return await alchemyRpc<string>(env, "eth_call", [
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

/**
 * Market structure for the premium dossier (holders / deployer share / LP hints).
 */
export async function analyzeMarketStructure(
  env: Env,
  scan: ScanResult,
): Promise<MarketStructure> {
  const notes: string[] = [];
  const goplus = scan.dossier.goplus as GoPlusTokenFlags | null;
  const honeypotIs = scan.dossier.honeypotIs as HoneypotIsFlags | null;

  const deployer =
    goplus?.creatorAddress ?? goplus?.ownerAddress ?? null;

  let deployer_balance_pct: number | null =
    goplus?.creatorPercent ?? goplus?.ownerPercent ?? null;

  // Prefer live balanceOf(deployer) / totalSupply when deployer is known.
  if (deployer) {
    try {
      const [supply, bal] = await Promise.all([
        erc20TotalSupply(env, scan.address),
        erc20BalanceOf(env, scan.address, deployer),
      ]);
      if (supply !== null && bal !== null) {
        const live = pctOf(bal, supply);
        if (live !== null) {
          deployer_balance_pct = live;
          notes.push("deployer_balance_pct from Alchemy eth_call balanceOf");
        }
      }
    } catch {
      notes.push("deployer live balanceOf failed; using GoPlus percent if any");
    }
  } else {
    notes.push("deployer address unknown — skipped live balanceOf");
  }

  const top_5_holders_pct = sumTopNonDexHolders(goplus?.holders ?? null);
  if (top_5_holders_pct === null) {
    notes.push(
      "top_5_holders_pct unavailable (GoPlus holders empty; Alchemy has no top-holders API)",
    );
  } else {
    notes.push("top_5_holders_pct from GoPlus holders (non-DEX wallets)");
  }

  let lp_status = inferLpStatus(goplus?.lpHolders ?? null);
  if (lp_status === "UNKNOWN") {
    notes.push("lp_status UNKNOWN — no usable GoPlus lp_holders lock/burn signal");
  } else {
    notes.push(`lp_status inferred from GoPlus lp_holders (${lp_status})`);
  }

  // Soft hint when a pair is known but LP lock status is not.
  if (lp_status === "UNKNOWN" && honeypotIs?.pairAddress) {
    notes.push(`pair observed via honeypot.is: ${honeypotIs.pairAddress}`);
  }

  const is_whale_concentrated =
    (typeof top_5_holders_pct === "number" && top_5_holders_pct >= 50) ||
    (typeof deployer_balance_pct === "number" && deployer_balance_pct >= 10);

  void resolveNetwork(env);

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
  };
}
