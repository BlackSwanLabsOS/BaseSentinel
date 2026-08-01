import type { Env } from "../types";
import { resolveNetwork } from "../config/network";
import {
  discoverRecentTokens,
  resolveCronFromBlock,
} from "./pairDiscovery";
import {
  peekScanCache,
  scanContract,
  scanResultAgeSeconds,
} from "./scanner";
import { notifyCronDigest, notifyOpsAlert } from "./discord";
import { runWatchChecks, type WatchRunStats } from "./watchList";
import { kvPutBestEffort } from "./kvSafe";
import {
  getAutopsyState,
  runAutopsyBatch,
  shouldRunAutopsy,
  type AutopsyRunStats,
} from "./autopsy";

const CRON_STATE_KEY = "cron:state";
/** Max *fresh* contract scans per cron tick (cache hits do not count). */
const MAX_SCANS_PER_RUN = 10;
/**
 * Rediscovered tokens fresher than this are skipped so the budget goes to
 * never-seen / stale launches.
 */
const CRON_CACHE_FRESH_SECONDS = 6 * 60 * 60;
/**
 * On quiet ticks, persist cron cursor at most this often (KV write thrift).
 */
const QUIET_STATE_WRITE_MS = 5 * 60 * 1000;
/** How often to list/re-scan paid watches (each run is multiple KV ops). */
const WATCH_INTERVAL_MS = 5 * 60 * 1000;
/** Ops Discord: no listings this long → warn (Base is rarely dead that long). */
const STALE_DISCOVERY_MS = 45 * 60 * 1000;
/** Don't spam #ops-logs more often than this when problems persist. */
const OPS_ALERT_COOLDOWN_MS = 15 * 60 * 1000;

export interface CronState {
  lastRunAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastProcessedBlock: number | null;
  /** Last time watch batch ran (throttled separately from discovery). */
  lastWatchAt?: string | null;
  /** Last tick with discovered > 0 (stale-discovery ops alerts). */
  lastDiscoveryAt?: string | null;
  /** Last ops Discord alert (cooldown). */
  lastOpsAlertAt?: string | null;
  /** Last scam-autopsy batch (daily throttle lives in autopsy state too). */
  lastAutopsyAt?: string | null;
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
  autopsy?: AutopsyRunStats;
  autopsySkipped?: boolean;
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
        stats.watch.errors > 0)) ||
    (stats.autopsy && stats.autopsy.processed > 0);
  if (busy) return true;
  if (!previous.lastSuccessAt) return true;
  const last = Date.parse(previous.lastSuccessAt);
  if (Number.isNaN(last)) return true;
  return nowMs - last >= QUIET_STATE_WRITE_MS;
}

function opsAlertAllowed(previous: CronState, nowMs: number): boolean {
  if (!previous.lastOpsAlertAt) return true;
  const last = Date.parse(previous.lastOpsAlertAt);
  if (Number.isNaN(last)) return true;
  return nowMs - last >= OPS_ALERT_COOLDOWN_MS;
}

function quietMinutesSince(
  iso: string | null | undefined,
  nowMs: number,
): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.max(0, Math.round((nowMs - t) / 60_000));
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
      lastDiscoveryAt: null,
      lastOpsAlertAt: null,
      lastAutopsyAt: null,
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
        const cached = await peekScanCache(env, token.address);
        if (
          cached &&
          scanResultAgeSeconds(cached) <= CRON_CACHE_FRESH_SECONDS
        ) {
          // Fresh cache — do not burn a scan slot (burst launches stay covered).
          stats.skippedCachedOrLimit += 1;
          continue;
        }

        const result = await scanContract(token.address, env, {
          waitUntil: ctx ? (p) => ctx.waitUntil(p) : undefined,
          maxCacheAgeSeconds: CRON_CACHE_FRESH_SECONDS,
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

    // Daily scam autopsy (aged SCAM → KV reports for marketing publisher).
    const autopsyState = await getAutopsyState(env);
    let lastAutopsyAt = previous.lastAutopsyAt ?? autopsyState.lastRunAt ?? null;
    if (shouldRunAutopsy(autopsyState, started)) {
      try {
        stats.autopsy = await runAutopsyBatch(env);
        stats.errors += stats.autopsy.errors;
        lastAutopsyAt = runAt;
      } catch (error) {
        stats.errors += 1;
        console.error(
          "[cron] autopsy batch failed:",
          error instanceof Error ? error.message : error,
        );
      }
    } else {
      stats.autopsySkipped = true;
    }

    stats.durationMs = Date.now() - started;

    const lastDiscoveryAt =
      stats.discovered > 0
        ? runAt
        : (previous.lastDiscoveryAt ?? null);

    let lastOpsAlertAt = previous.lastOpsAlertAt ?? null;
    let opsReason: "errors" | "stale_discovery" | null = null;

    if (stats.errors > 0) {
      opsReason = "errors";
    } else if (stats.discovered === 0 && lastDiscoveryAt) {
      const lastDiscMs = Date.parse(lastDiscoveryAt);
      if (
        Number.isFinite(lastDiscMs) &&
        started - lastDiscMs >= STALE_DISCOVERY_MS
      ) {
        opsReason = "stale_discovery";
      }
    }

    if (opsReason && opsAlertAllowed(previous, started)) {
      const opsTask = notifyOpsAlert(env.DISCORD_OPS_WEBHOOK_URL, {
        reason: opsReason,
        discovered: stats.discovered,
        scanned: stats.scanned,
        scams: stats.scams,
        suspicious: stats.suspicious,
        errors: stats.errors,
        fromBlock: stats.fromBlock,
        toBlock: stats.toBlock,
        bySource: stats.bySource,
        quietMinutes: quietMinutesSince(lastDiscoveryAt, started),
      });
      if (ctx) ctx.waitUntil(opsTask);
      else await opsTask;
      lastOpsAlertAt = runAt;
    }

    const nextState: CronState = {
      lastRunAt: runAt,
      lastSuccessAt: runAt,
      lastError: null,
      lastProcessedBlock: discovery.toBlock,
      lastWatchAt,
      lastDiscoveryAt,
      lastOpsAlertAt,
      lastAutopsyAt,
      network,
      lastStats: stats,
    };

    if (
      shouldPersistState(previous, stats, started, false) ||
      lastOpsAlertAt !== (previous.lastOpsAlertAt ?? null) ||
      lastDiscoveryAt !== (previous.lastDiscoveryAt ?? null) ||
      lastAutopsyAt !== (previous.lastAutopsyAt ?? null)
    ) {
      await saveCronState(env, nextState);
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
      `[cron] ok discovered=${stats.discovered} scanned=${stats.scanned} scams=${stats.scams} suspicious=${stats.suspicious} errors=${stats.errors} blocks=${stats.fromBlock}-${stats.toBlock} sources=${JSON.stringify(stats.bySource)} watch=${JSON.stringify(stats.watch ?? null)} watchSkipped=${Boolean(stats.watchSkipped)} autopsy=${JSON.stringify(stats.autopsy ?? null)} autopsySkipped=${Boolean(stats.autopsySkipped)}`,
    );

    return { ok: true, stats };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stats = emptyStats();
    stats.durationMs = Date.now() - started;
    stats.errors = 1;

    const fatalState: CronState = {
      ...previous,
      lastRunAt: runAt,
      lastError: message,
      lastStats: stats,
      network,
    };

    if (opsAlertAllowed(previous, started)) {
      const opsTask = notifyOpsAlert(env.DISCORD_OPS_WEBHOOK_URL, {
        reason: "fatal",
        message,
        discovered: 0,
        scanned: 0,
        scams: 0,
        suspicious: 0,
        errors: 1,
        fromBlock: 0,
        toBlock: 0,
      });
      if (ctx) ctx.waitUntil(opsTask);
      else await opsTask;
      fatalState.lastOpsAlertAt = runAt;
    }

    await saveCronState(env, fatalState);

    console.error("[cron] fatal:", message);
    return { ok: false, stats, error: message };
  }
}
