import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  discoverRecentTokens,
  resolveCronFromBlock,
} from "./pairDiscovery";
import { scanContract } from "./scanner";
import { notifyCronDigest } from "./discord";
import { runWatchChecks, type WatchRunStats } from "./watchList";

const CRON_STATE_KEY = "cron:state";
/** Cap scans/tick to stay within free Alchemy + GoPlus limits. */
const MAX_SCANS_PER_RUN = 10;

export interface CronState {
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastProcessedBlock: number | null;
  network: string;
  lastStats: CronRunStats | null;
}

export interface CronRunStats {
  discovered: number;
  scanned: number;
  scams: number;
  suspicious: number;
  skippedCachedOrLimit: number;
  errors: number;
  fromBlock: number;
  toBlock: number;
  durationMs: number;
  bySource?: Record<string, number>;
  watch?: WatchRunStats;
}

export interface CronRunResult {
  ok: boolean;
  stats: CronRunStats;
  error?: string;
}

function emptyStats(fromBlock = 0, toBlock = 0): CronRunStats {
  return {
    discovered: 0,
    scanned: 0,
    scams: 0,
    suspicious: 0,
    skippedCachedOrLimit: 0,
    errors: 0,
    fromBlock,
    toBlock,
    durationMs: 0,
  };
}

export async function getCronState(env: Env): Promise<CronState> {
  const stored = (await env.SCAN_CACHE.get(CRON_STATE_KEY, "json")) as
    | CronState
    | null;

  return (
    stored ?? {
      lastRunAt: null,
      lastSuccessAt: null,
      lastError: null,
      lastProcessedBlock: null,
      network: resolveNetwork(env),
      lastStats: null,
    }
  );
}

async function saveCronState(env: Env, state: CronState): Promise<void> {
  await env.SCAN_CACHE.put(CRON_STATE_KEY, JSON.stringify(state));
}

/**
 * Background job: discover newly paired tokens and scan them.
 * Payment gate is bypassed (internal cron → scanContract directly).
 * SCAM hits are persisted via scanner → threatIntel (+ Discord via waitUntil).
 */
export async function runScheduledScan(
  env: Env,
  ctx?: ExecutionContext,
): Promise<CronRunResult> {
  const started = Date.now();
  const network = resolveNetwork(env);
  const previous = await getCronState(env);

  const running: CronState = {
    ...previous,
    lastRunAt: new Date().toISOString(),
    network,
    lastError: null,
  };
  await saveCronState(env, running);

  try {
    const fromBlock = await resolveCronFromBlock(
      env,
      previous.lastProcessedBlock,
    );
    const discovery = await discoverRecentTokens(env, fromBlock);
    const stats = emptyStats(discovery.fromBlock, discovery.toBlock);
    stats.discovered = discovery.tokens.length;
    stats.bySource = discovery.bySource;

    // Prefer newest listings first (sniper-relevant).
    const candidates = [...discovery.tokens].sort(
      (a, b) => b.blockNumber - a.blockNumber,
    );

    for (const token of candidates) {
      if (stats.scanned >= MAX_SCANS_PER_RUN) {
        stats.skippedCachedOrLimit += 1;
        continue;
      }

      try {
        const result = await scanContract(token.address, env, {
          waitUntil: ctx ? (p) => ctx.waitUntil(p) : undefined,
          listing: {
            source: token.source,
            pair: token.pair,
            pairedWith: token.pairedWith,
            txHash: token.txHash,
            blockNumber: token.blockNumber,
          },
        });
        stats.scanned += 1;
        if (result.status === "SCAM") {
          stats.scams += 1;
        } else if (result.status === "SUSPICIOUS") {
          stats.suspicious += 1;
        }
      } catch (error) {
        stats.errors += 1;
        console.error(
          `[cron] scan failed for ${token.address}:`,
          error instanceof Error ? error.message : error,
        );
      }
    }

    // Watchdog batch (separate budget from discovery scans).
    try {
      stats.watch = await runWatchChecks(env, ctx);
      stats.errors += stats.watch.errors;
    } catch (error) {
      stats.errors += 1;
      console.error(
        "[cron] watch batch failed:",
        error instanceof Error ? error.message : error,
      );
    }

    stats.durationMs = Date.now() - started;

    const nextState: CronState = {
      lastRunAt: running.lastRunAt,
      lastSuccessAt: new Date().toISOString(),
      lastError: null,
      lastProcessedBlock: discovery.toBlock,
      network,
      lastStats: stats,
    };
    await saveCronState(env, nextState);

    const digestTask = notifyCronDigest(env.DISCORD_WEBHOOK_URL, {
      discovered: stats.discovered,
      scanned: stats.scanned,
      scams: stats.scams,
      suspicious: stats.suspicious,
      errors: stats.errors,
      fromBlock: stats.fromBlock,
      toBlock: stats.toBlock,
      bySource: stats.bySource,
    });
    if (ctx) {
      ctx.waitUntil(digestTask);
    } else {
      await digestTask;
    }

    console.log(
      `[cron] ok discovered=${stats.discovered} scanned=${stats.scanned} scams=${stats.scams} suspicious=${stats.suspicious} errors=${stats.errors} blocks=${stats.fromBlock}-${stats.toBlock} sources=${JSON.stringify(stats.bySource)} watch=${JSON.stringify(stats.watch ?? null)}`,
    );

    return { ok: true, stats };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stats = emptyStats();
    stats.durationMs = Date.now() - started;
    stats.errors = 1;

    await saveCronState(env, {
      ...running,
      lastError: message,
      lastStats: stats,
    });

    console.error("[cron] fatal:", message);
    return { ok: false, stats, error: message };
  }
}
