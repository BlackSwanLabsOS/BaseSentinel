/**
 * Daily scam autopsy batch: SCAM threats aged ≥24h → on-chain activity estimate → KV report.
 * Uses public LOGS RPC only (never Alchemy payment path).
 */
import type { Env } from "../types";
import {
  getUsdcContractAddress,
  getWethAddress,
  resolveNetwork,
} from "../config/network";
import {
  getLatestBlockNumber,
  getLogs,
  type EthLog,
} from "./alchemy";
import { kvPutBestEffort } from "./kvSafe";
import {
  AUTOPSY_ACTIVITY_CAVEAT,
  AUTOPSY_NO_PAIR_CAVEAT,
  AUTOPSY_DAY_LOOKBACK,
  AUTOPSY_INTERVAL_MS,
  AUTOPSY_MAX_BLOCK_SPAN,
  AUTOPSY_MAX_PER_RUN,
  AUTOPSY_MIN_AGE_MS,
  AUTOPSY_PENDING_KEY,
  AUTOPSY_STATE_KEY,
  BASE_BLOCKS_PER_HOUR,
  ERC20_TRANSFER_TOPIC,
  PAIR_BURN_TOPIC0,
  autopsyDoneKey,
  autopsyReportKey,
  buildFactsSummary,
  getAutopsySkipReason,
  type AutopsyReport,
  type AutopsyActivityEstimate,
  type AutopsySkipReason,
} from "./autopsyMetrics";
import {
  threatContractKvKey,
  threatDayKvKey,
  utcDateString,
  type ThreatRecord,
} from "./threatIntel";

export interface AutopsyState {
  lastRunAt: string | null;
  lastStats: AutopsyRunStats | null;
}

export interface AutopsyRunStats {
  candidates: number;
  processed: number;
  skippedDone: number;
  skippedYoung: number;
  skippedIneligible: number;
  errors: number;
  durationMs: number;
}

function topicAddress(address: string): string {
  return `0x${"0".repeat(24)}${address.toLowerCase().replace(/^0x/, "")}`;
}

function parseHexBigInt(data: string): bigint {
  if (!data || data === "0x") return 0n;
  try {
    return BigInt(data);
  } catch {
    return 0n;
  }
}

function sumTransferAmounts(logs: EthLog[]): bigint {
  let sum = 0n;
  for (const log of logs) {
    sum += parseHexBigInt(log.data);
  }
  return sum;
}

function explorerUrl(network: string, address: string): string {
  const host =
    network === "base" || network === "base-mainnet"
      ? "https://basescan.org"
      : "https://sepolia.basescan.org";
  return `${host}/address/${address}`;
}

function daysAgoUtc(days: number, from = new Date()): string {
  const d = new Date(from);
  d.setUTCDate(d.getUTCDate() - days);
  return utcDateString(d);
}

export async function getAutopsyState(env: Env): Promise<AutopsyState> {
  const stored = (await env.SCAN_CACHE.get(AUTOPSY_STATE_KEY, "json")) as
    | AutopsyState
    | null;
  return stored ?? { lastRunAt: null, lastStats: null };
}

export function shouldRunAutopsy(
  previous: AutopsyState,
  nowMs: number,
): boolean {
  if (!previous.lastRunAt) return true;
  const last = Date.parse(previous.lastRunAt);
  if (Number.isNaN(last)) return true;
  return nowMs - last >= AUTOPSY_INTERVAL_MS;
}

async function loadPendingList(env: Env): Promise<string[]> {
  return (
    ((await env.SCAN_CACHE.get(AUTOPSY_PENDING_KEY, "json")) as
      | string[]
      | null) ?? []
  );
}

async function savePendingList(env: Env, list: string[]): Promise<void> {
  const unique = [...new Set(list.map((a) => a.toLowerCase()))];
  await kvPutBestEffort(
    env.SCAN_CACHE,
    AUTOPSY_PENDING_KEY,
    JSON.stringify(unique.slice(0, 200)),
  );
}

async function markSkipped(
  env: Env,
  address: string,
  skipReason: AutopsySkipReason,
): Promise<void> {
  const now = new Date().toISOString();
  const report: AutopsyReport = {
    schema: "basesentinel.autopsy.v1",
    address: address.toLowerCase(),
    network: resolveNetwork(env),
    status: "skipped",
    flagged_at: now,
    autopsy_at: now,
    age_hours: 0,
    risk_score: 0,
    reasons: [],
    listing: {
      source: null,
      pair: null,
      paired_with: null,
      tx_hash: null,
      block_number: null,
    },
    creator_address: null,
    owner_address: null,
    activity: {
      token_transfer_count: null,
      weth_to_pair_wei: null,
      usdc_to_pair_atomic: null,
      lp_burn_observed: null,
      caveat: AUTOPSY_ACTIVITY_CAVEAT,
    },
    explorer_url: `https://basescan.org/address/${address}`,
    facts_summary: `Skipped autopsy (${skipReason})`,
    skip_reason: skipReason,
  };
  await kvPutBestEffort(
    env.SCAN_CACHE,
    autopsyReportKey(address),
    JSON.stringify(report),
  );
  await kvPutBestEffort(
    env.SCAN_CACHE,
    autopsyDoneKey(address),
    JSON.stringify({
      autopsyAt: now,
      publishedAt: null,
      skipped: true,
      skipReason,
    }),
  );
  const pending = (await loadPendingList(env)).filter(
    (a) => a.toLowerCase() !== address.toLowerCase(),
  );
  await savePendingList(env, pending);
}

/** Admin / publisher: unpublished autopsy reports (newest first). */
export async function listPendingAutopsyReports(
  env: Env,
  limit = 20,
): Promise<AutopsyReport[]> {
  const pending = await loadPendingList(env);
  const out: AutopsyReport[] = [];
  const keep: string[] = [];
  for (const address of pending) {
    const report = (await env.SCAN_CACHE.get(
      autopsyReportKey(address),
      "json",
    )) as AutopsyReport | null;
    if (!report || report.status !== "ready") {
      continue;
    }
    const skip = getAutopsySkipReason({
      address: report.address,
      status: "SCAM",
      reasons: report.reasons,
    });
    if (skip) {
      await markSkipped(env, report.address, skip);
      continue;
    }
    keep.push(address.toLowerCase());
    if (out.length < limit) {
      out.push(report);
    }
  }
  // Drop ineligible leftovers from pending index.
  if (keep.length !== pending.length) {
    await savePendingList(env, keep);
  }
  out.sort((a, b) => Date.parse(b.autopsy_at) - Date.parse(a.autopsy_at));
  return out;
}

export async function getAutopsyReport(
  env: Env,
  address: string,
): Promise<AutopsyReport | null> {
  return (
    ((await env.SCAN_CACHE.get(
      autopsyReportKey(address),
      "json",
    )) as AutopsyReport | null) ?? null
  );
}

export async function markAutopsyPublished(
  env: Env,
  address: string,
): Promise<AutopsyReport | null> {
  const key = autopsyReportKey(address);
  const report = (await env.SCAN_CACHE.get(key, "json")) as AutopsyReport | null;
  if (!report) return null;
  const updated: AutopsyReport = {
    ...report,
    status: "published",
    published_at: new Date().toISOString(),
  };
  await kvPutBestEffort(env.SCAN_CACHE, key, JSON.stringify(updated));
  await kvPutBestEffort(
    env.SCAN_CACHE,
    autopsyDoneKey(address),
    JSON.stringify({
      publishedAt: updated.published_at,
      autopsyAt: updated.autopsy_at,
    }),
  );
  const pending = (await loadPendingList(env)).filter(
    (a) => a.toLowerCase() !== address.toLowerCase(),
  );
  await savePendingList(env, pending);
  return updated;
}

async function collectCandidates(
  env: Env,
  nowMs: number,
): Promise<ThreatRecord[]> {
  const addresses = new Set<string>();
  for (let i = 1; i <= AUTOPSY_DAY_LOOKBACK; i++) {
    const day = daysAgoUtc(i);
    const indexed = (await env.SCAN_CACHE.get(threatDayKvKey(day), "json")) as
      | string[]
      | null;
    for (const a of indexed ?? []) {
      addresses.add(a.toLowerCase());
    }
  }

  const candidates: ThreatRecord[] = [];
  for (const address of addresses) {
    const done = await env.SCAN_CACHE.get(autopsyDoneKey(address));
    if (done) continue;
    const existingReport = (await env.SCAN_CACHE.get(
      autopsyReportKey(address),
      "json",
    )) as AutopsyReport | null;
    if (existingReport) continue;

    const record = (await env.SCAN_CACHE.get(
      threatContractKvKey(address),
      "json",
    )) as ThreatRecord | null;
    if (!record) continue;
    if ((record.status ?? "SAFE") !== "SCAM") continue;

    const skip = getAutopsySkipReason({
      address: record.address,
      status: record.status,
      reasons: record.reasons,
      bytecodeLength: record.bytecodeLength,
    });
    if (skip) {
      await markSkipped(env, record.address, skip);
      continue;
    }

    const flaggedMs = Date.parse(record.timestamp);
    if (!Number.isFinite(flaggedMs)) continue;
    if (nowMs - flaggedMs < AUTOPSY_MIN_AGE_MS) continue;

    candidates.push(record);
  }

  candidates.sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
  );
  return candidates.slice(0, AUTOPSY_MAX_PER_RUN);
}

async function estimateActivity(
  env: Env,
  record: ThreatRecord,
  fromBlock: number,
  toBlock: number,
): Promise<AutopsyActivityEstimate> {
  const network = resolveNetwork(env);
  const token = record.address.toLowerCase();
  const pair = record.dossier?.listing?.pair?.toLowerCase() ?? null;
  const weth = getWethAddress(network).toLowerCase();
  const usdc = getUsdcContractAddress(network).toLowerCase();
  const fromHex = `0x${fromBlock.toString(16)}`;
  const toHex = `0x${toBlock.toString(16)}`;

  let token_transfer_count: number | null = null;
  let weth_to_pair_wei: string | null = null;
  let usdc_to_pair_atomic: string | null = null;
  let lp_burn_observed: boolean | null = null;

  try {
    const tokenLogs = await getLogs(env, {
      address: token,
      topics: [ERC20_TRANSFER_TOPIC],
      fromBlock: fromHex,
      toBlock: toHex,
    });
    token_transfer_count = tokenLogs.length;
  } catch (error) {
    console.warn(
      `[autopsy] token transfers failed ${token}:`,
      error instanceof Error ? error.message.slice(0, 120) : error,
    );
  }

  if (pair) {
    try {
      const wethLogs = await getLogs(env, {
        address: weth,
        topics: [ERC20_TRANSFER_TOPIC, null, topicAddress(pair)],
        fromBlock: fromHex,
        toBlock: toHex,
      });
      weth_to_pair_wei = sumTransferAmounts(wethLogs).toString();
    } catch (error) {
      console.warn(
        `[autopsy] weth→pair failed ${pair}:`,
        error instanceof Error ? error.message.slice(0, 120) : error,
      );
    }

    try {
      const usdcLogs = await getLogs(env, {
        address: usdc,
        topics: [ERC20_TRANSFER_TOPIC, null, topicAddress(pair)],
        fromBlock: fromHex,
        toBlock: toHex,
      });
      usdc_to_pair_atomic = sumTransferAmounts(usdcLogs).toString();
    } catch (error) {
      console.warn(
        `[autopsy] usdc→pair failed ${pair}:`,
        error instanceof Error ? error.message.slice(0, 120) : error,
      );
    }

    try {
      const burns = await getLogs(env, {
        address: pair,
        topics: [PAIR_BURN_TOPIC0],
        fromBlock: fromHex,
        toBlock: toHex,
      });
      lp_burn_observed = burns.length > 0;
    } catch (error) {
      console.warn(
        `[autopsy] pair burn failed ${pair}:`,
        error instanceof Error ? error.message.slice(0, 120) : error,
      );
      lp_burn_observed = null;
    }
  }

  return {
    token_transfer_count,
    weth_to_pair_wei,
    usdc_to_pair_atomic,
    lp_burn_observed,
    caveat: pair ? AUTOPSY_ACTIVITY_CAVEAT : AUTOPSY_NO_PAIR_CAVEAT,
  };
}

function resolveFromBlock(
  record: ThreatRecord,
  latestBlock: number,
  ageHours: number,
): number {
  const listingBlock = record.dossier?.listing?.blockNumber;
  if (
    typeof listingBlock === "number" &&
    Number.isFinite(listingBlock) &&
    listingBlock > 0
  ) {
    return Math.max(0, listingBlock);
  }
  const span = Math.min(
    AUTOPSY_MAX_BLOCK_SPAN,
    Math.ceil(ageHours * BASE_BLOCKS_PER_HOUR) + BASE_BLOCKS_PER_HOUR,
  );
  return Math.max(0, latestBlock - span);
}

async function buildReport(
  env: Env,
  record: ThreatRecord,
  latestBlock: number,
  now: Date,
): Promise<AutopsyReport> {
  const flaggedMs = Date.parse(record.timestamp);
  const ageHours = Math.max(
    1,
    Math.round((now.getTime() - flaggedMs) / 3_600_000),
  );
  const fromBlock = resolveFromBlock(record, latestBlock, ageHours);
  const toBlock = latestBlock;
  const span = Math.min(AUTOPSY_MAX_BLOCK_SPAN, Math.max(0, toBlock - fromBlock));
  const cappedFrom = toBlock - span;

  const activity = await estimateActivity(env, record, cappedFrom, toBlock);
  const network = record.network || resolveNetwork(env);
  const listing = record.dossier?.listing ?? null;
  const goplus = record.dossier?.goplus ?? null;

  const partial = {
    schema: "basesentinel.autopsy.v1" as const,
    address: record.address.toLowerCase(),
    network,
    status: "ready" as const,
    flagged_at: record.timestamp,
    autopsy_at: now.toISOString(),
    age_hours: ageHours,
    risk_score: record.riskScore,
    reasons: record.reasons ?? [],
    listing: {
      source: listing?.source ?? null,
      pair: listing?.pair?.toLowerCase() ?? null,
      paired_with: listing?.pairedWith?.toLowerCase() ?? null,
      tx_hash: listing?.txHash ?? null,
      block_number: listing?.blockNumber ?? null,
    },
    creator_address: goplus?.creatorAddress?.toLowerCase() ?? null,
    owner_address: goplus?.ownerAddress?.toLowerCase() ?? null,
    activity,
    explorer_url: explorerUrl(network, record.address),
  };

  return {
    ...partial,
    facts_summary: buildFactsSummary(partial),
  };
}

/**
 * Process up to AUTOPSY_MAX_PER_RUN aged SCAM threats into KV autopsy reports.
 */
export async function runAutopsyBatch(env: Env): Promise<AutopsyRunStats> {
  const started = Date.now();
  const stats: AutopsyRunStats = {
    candidates: 0,
    processed: 0,
    skippedDone: 0,
    skippedYoung: 0,
    skippedIneligible: 0,
    errors: 0,
    durationMs: 0,
  };

  const now = new Date();
  const candidates = await collectCandidates(env, started);
  stats.candidates = candidates.length;

  if (candidates.length === 0) {
    stats.durationMs = Date.now() - started;
    await kvPutBestEffort(
      env.SCAN_CACHE,
      AUTOPSY_STATE_KEY,
      JSON.stringify({
        lastRunAt: now.toISOString(),
        lastStats: stats,
      } satisfies AutopsyState),
    );
    return stats;
  }

  let latestBlock = 0;
  try {
    latestBlock = await getLatestBlockNumber(env);
  } catch (error) {
    console.error(
      "[autopsy] eth_blockNumber failed:",
      error instanceof Error ? error.message : error,
    );
    stats.errors += 1;
    stats.durationMs = Date.now() - started;
    return stats;
  }

  const pending = await loadPendingList(env);

  for (const record of candidates) {
    try {
      const skip = getAutopsySkipReason({
        address: record.address,
        status: record.status,
        reasons: record.reasons,
        bytecodeLength: record.bytecodeLength,
      });
      if (skip) {
        await markSkipped(env, record.address, skip);
        stats.skippedIneligible += 1;
        continue;
      }

      const report = await buildReport(env, record, latestBlock, now);
      await kvPutBestEffort(
        env.SCAN_CACHE,
        autopsyReportKey(report.address),
        JSON.stringify(report),
      );
      // Mark done for batching (report exists); publish is separate.
      await kvPutBestEffort(
        env.SCAN_CACHE,
        autopsyDoneKey(report.address),
        JSON.stringify({
          autopsyAt: report.autopsy_at,
          publishedAt: null,
        }),
      );
      if (!pending.includes(report.address)) {
        pending.unshift(report.address);
      }
      stats.processed += 1;
    } catch (error) {
      stats.errors += 1;
      console.error(
        `[autopsy] failed ${record.address}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }

  await savePendingList(env, pending);
  stats.durationMs = Date.now() - started;
  await kvPutBestEffort(
    env.SCAN_CACHE,
    AUTOPSY_STATE_KEY,
    JSON.stringify({
      lastRunAt: now.toISOString(),
      lastStats: stats,
    } satisfies AutopsyState),
  );

  console.log(
    `[autopsy] ok processed=${stats.processed} candidates=${stats.candidates} errors=${stats.errors} ms=${stats.durationMs}`,
  );
  return stats;
}
