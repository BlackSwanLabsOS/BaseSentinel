import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  discoverRecentTokens,
  resolveCronFromBlock,
} from "./pairDiscovery";
import { scanContract } from "./scanner";
import { notifyCronDigest, notifyOpsDiscovery } from "./discord";
import { runWatchChecks, type WatchRunStats } from "./watchList";
import { kvPutBestEffort } from "./kvSafe";

const CRON_STATE_KEY = "cron:state";
/** Max full contract scans per cron tick. */
const MAX_SCANS_PER_RUN = 10;
/**
 * On quiet ticks, persist cron cursor at most this often.
 * Free KV allows ~1000 writes/day — a put every minute alone exceeds that.
 */
const QUIET_STATE_WRITE_MS = 5 * 60 * 1000;
/** How often to list/re-scan paid watches (each run is multiple KV ops). */
const WATCH_INTERVAL_MS = 5 * 60 * 1000;

export interface CronState {
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastProcessedBlock: number | null;
  /** Last time watch batch ran (throttled separately from discovery). */
  lastWatchAt?: string | null;
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
  watchSkipped?: boolean;
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

function shouldRunWatches(previous: CronState, nowMs: number): boolean {
  if (!previous.lastWatchAt) return true;
  const last = Date.parse(previous.lastWatchAt);
  if (Number.isNaN(last)) return true;
  return nowMs - last >= WATCH_INTERVAL_MS;
}

function shouldPersistState(
  previous: CronState,
  stats: CronRunStats,
  nowMs: number,
  fatal: boolean,
): boolean {
  if (fatal) return true;
  const busy =
    stats.discovered > 0 ||
    stats.scanned > 0 ||
    stats.scams > 0 ||
    stats.suspicious > 0 ||
    stats.errors > 0 ||
    (stats.watch &&
      (stats.watch.checked > 0 ||
        stats.watch.notified > 0 ||
        stats.watch.errors > 0));
  if (busy) return true;
  if (!previous.lastSuccessAt) return true;
  const last = Date.parse(previous.lastSuccessAt);
  if (Number.isNaN(last)) return true;
  return nowMs - last >= QUIET_STATE_WRITE_MS;
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
      lastWatchAt: null,
      network: resolveNetwork(env),
      lastStats: null,
    }
  );
}

async function saveCronState(env: Env, state: CronState): Promise<void> {
  await kvPutBestEffort(env.SCAN_CACHE, CRON_STATE_KEY, JSON.stringify(state));
}

/**
 * Cron: discover new Base listings and scan them into the threat archive.
 */
export async function runScheduledScan(
  env: Env,
  ctx?: ExecutionContext,
): Promise<CronRunResult> {
  const started = Date.now();
  const network = resolveNetwork(env);
  const previous = await getCronState(env);
  const runAt = new Date().toISOString();

  try {
    const fromBlock = await resolveCronFromBlock(
      env,
      previous.lastProcessedBlock,
    );
    const discovery = await discoverRecentTokens(env, fromBlock);
    const stats = emptyStats(discovery.fromBlock, discovery.toBlock);
    stats.discovered = discovery.tokens.length;
    stats.bySource = discovery.bySource;

    // Newest listings first.
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

    let lastWatchAt = previous.lastWatchAt ?? null;
    if (shouldRunWatches(previous, started)) {
      try {
        stats.watch = await runWatchChecks(env, ctx);
        stats.errors += stats.watch.errors;
        lastWatchAt = runAt;
      } catch (error) {
        stats.errors += 1;
        console.error(
          "[cron] watch batch failed:",
          error instanceof Error ? error.message : error,
        );
      }
    } else {
      stats.watchSkipped = true;
    }

    stats.durationMs = Date.now() - started;

    const nextState: CronState = {
      lastRunAt: runAt,
      lastSuccessAt: runAt,
      lastError: null,
      lastProcessedBlock: discovery.toBlock,
      lastWatchAt,
      network,
      lastStats: stats,
    };

    if (shouldPersistState(previous, stats, started, false)) {
      await saveCronState(env, nextState);
    }

    if (stats.discovered > 0) {
      const opsTask = notifyOpsDiscovery(env.DISCORD_OPS_WEBHOOK_URL, {
        discovered: stats.discovered,
        scanned: stats.scanned,
        scams: stats.scams,
        suspicious: stats.suspicious,
        fromBlock: stats.fromBlock,
        toBlock: stats.toBlock,
        bySource: stats.bySource,
      });
      if (ctx) ctx.waitUntil(opsTask);
      else await opsTask;
    }

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
      `[cron] ok discovered=${stats.discovered} scanned=${stats.scanned} scams=${stats.scams} suspicious=${stats.suspicious} errors=${stats.errors} blocks=${stats.fromBlock}-${stats.toBlock} sources=${JSON.stringify(stats.bySource)} watch=${JSON.stringify(stats.watch ?? null)} watchSkipped=${Boolean(stats.watchSkipped)}`,
    );

    return { ok: true, stats };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stats = emptyStats();
    stats.durationMs = Date.now() - started;
    stats.errors = 1;

    await saveCronState(env, {
      ...previous,
      lastRunAt: runAt,
      lastError: message,
      lastStats: stats,
      network,
    });

    console.error("[cron] fatal:", message);
    return { ok: false, stats, error: message };
  }
}
