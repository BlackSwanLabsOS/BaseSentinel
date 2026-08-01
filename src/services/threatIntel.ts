import type { Env } from "../types";
import {
  statusFromScore,
  type AnalysisStatus,
} from "./analyzer";
import { resolveNetwork } from "../config/network";
import { notifyDiscordFromEnv } from "./discord";
import { kvPutBestEffort } from "./kvSafe";
import type { ScanDossier } from "./scanTypes";
import type { AgentVerdict } from "./verdict";

/** Threat records persist without TTL. */
const DAY_INDEX_TTL_SECONDS = 90 * 86_400; // 90 days

export interface ThreatRecord {
  address: string;
  network: string;
  status: AnalysisStatus;
  reasons: string[];
  riskScore: number;
  timestamp: string;
  lastSeen: string;
  bytecodeLength?: number;
  dossier?: Pick<
    ScanDossier,
    "goplus" | "honeypotIs" | "listing" | "dualSourceConsensus"
  >;
}

export interface DailyThreatFeed {
  feed: "base-sentinel-threat-intel";
  network: string;
  date: string;
  generatedAt: string;
  count: number;
  counts: {
    scam: number;
    suspicious: number;
  };
  threats: ThreatRecord[];
}

interface ThreatScanInput {
  address: string;
  network: string;
  status: AnalysisStatus;
  reasons: string[];
  riskScore: number;
  bytecodeLength: number;
  dossier?: ScanDossier;
  verdict?: AgentVerdict;
  verdict_score?: number;
  risk_flags?: string[];
}

export interface RecordThreatOptions {
  /** Optional waitUntil so Discord I/O does not block the cron batch. */
  waitUntil?: (promise: Promise<unknown>) => void;
}

function threatContractKey(address: string): string {
  return `threat:contract:${address}`;
}

function threatDayKey(date: string): string {
  return `threat:day:${date}`;
}

export function threatContractKvKey(address: string): string {
  return threatContractKey(address.toLowerCase());
}

export function threatDayKvKey(date: string): string {
  return threatDayKey(date);
}

/** UTC calendar day YYYY-MM-DD */
export function utcDateString(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

/**
 * True for a real calendar UTC day YYYY-MM-DD, not in the future.
 * Rejects 2026-13-40-style garbage before any payment challenge.
 */
export function isValidFeedDate(date: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return false;
  }
  const [y, m, d] = date.split("-").map((part) => Number(part));
  if (!y || !m || !d) return false;
  const parsed = new Date(Date.UTC(y, m - 1, d));
  if (
    parsed.getUTCFullYear() !== y ||
    parsed.getUTCMonth() !== m - 1 ||
    parsed.getUTCDate() !== d
  ) {
    return false;
  }
  // No paying for a future UTC day that cannot have a feed yet.
  if (date > utcDateString()) {
    return false;
  }
  return true;
}

function severityRank(status: AnalysisStatus): number {
  if (status === "SCAM") return 2;
  if (status === "SUSPICIOUS") return 1;
  return 0;
}

/**
 * Persist SUSPICIOUS / SCAM into the archive and daily index.
 * First-seen and severity upgrades notify Discord and the live stream.
 */
export async function recordThreat(
  env: Env,
  scan: ThreatScanInput,
  options: RecordThreatOptions = {},
): Promise<void> {
  if (scan.status === "SAFE") {
    return;
  }

  const address = scan.address.toLowerCase();
  const now = new Date().toISOString();
  const key = threatContractKey(address);

  const existing = (await env.SCAN_CACHE.get(key, "json")) as ThreatRecord | null;
  const isNew = !existing;

  const nextScore = Math.max(existing?.riskScore ?? 0, scan.riskScore);
  const nextStatus = statusFromScore(nextScore);
  // Prefer higher severity when scores are close.
  const mergedStatus =
    severityRank(scan.status) > severityRank(nextStatus)
      ? scan.status
      : nextStatus;

  // Skip KV writes when nothing material changed (cron often re-sees known threats).
  if (
    existing &&
    severityRank(mergedStatus) <= severityRank(existing.status ?? "SAFE") &&
    nextScore <= (existing.riskScore ?? 0)
  ) {
    return;
  }

  const record: ThreatRecord = existing
    ? {
        ...existing,
        status: mergedStatus,
        reasons: scan.reasons,
        riskScore: nextScore,
        lastSeen: now,
        bytecodeLength: scan.bytecodeLength,
        dossier: {
          goplus: scan.dossier?.goplus ?? existing.dossier?.goplus ?? null,
          honeypotIs:
            scan.dossier?.honeypotIs ?? existing.dossier?.honeypotIs ?? null,
          listing: scan.dossier?.listing ?? existing.dossier?.listing ?? null,
          dualSourceConsensus:
            scan.dossier?.dualSourceConsensus ??
            existing.dossier?.dualSourceConsensus ??
            false,
        },
      }
    : {
        address,
        network: scan.network || resolveNetwork(env),
        status: scan.status,
        reasons: scan.reasons,
        riskScore: scan.riskScore,
        timestamp: now,
        lastSeen: now,
        bytecodeLength: scan.bytecodeLength,
        dossier: scan.dossier
          ? {
              goplus: scan.dossier.goplus,
              honeypotIs: scan.dossier.honeypotIs,
              listing: scan.dossier.listing,
              dualSourceConsensus: scan.dossier.dualSourceConsensus,
            }
          : undefined,
      };

  await kvPutBestEffort(env.SCAN_CACHE, key, JSON.stringify(record));

  const day = utcDateString(new Date(now));
  await appendToDayIndex(env, day, address);

  const upgraded =
    existing !== null &&
    severityRank(record.status) > severityRank(existing.status ?? "SAFE");
  const scoreUp = record.riskScore > (existing?.riskScore ?? 0);
  const shouldFanOut = isNew || upgraded || scoreUp;

  if (shouldFanOut) {
    await pushRecentThreat(env, {
      id: `${now}|${address}`,
      contract: address,
      network: record.network,
      status: record.status,
      riskScore: record.riskScore,
      timestamp: now,
      reasons: record.reasons,
      listing: record.dossier?.listing ?? null,
    });
  }

  // Notify on first detection or severity upgrade.
  if (isNew || upgraded) {
    const notifyTask = notifyDiscordFromEnv(env, {
      address: record.address,
      network: record.network,
      status: record.status === "SCAM" ? "SCAM" : "SUSPICIOUS",
      riskScore: record.riskScore,
      reasons: record.reasons,
      timestamp: record.timestamp,
      listingSource: record.dossier?.listing?.source ?? null,
      listingTx: record.dossier?.listing?.txHash ?? null,
      verdict: scan.verdict ?? null,
      verdict_score: scan.verdict_score ?? null,
      risk_flags: scan.risk_flags ?? [],
    });

    if (options.waitUntil) {
      options.waitUntil(notifyTask);
    } else {
      await notifyTask;
    }
  }
}

const RECENT_THREATS_KEY = "threat:recent";
const MAX_RECENT_THREATS = 100;

export interface RecentThreatEvent {
  id: string;
  contract: string;
  network: string;
  status: AnalysisStatus;
  riskScore: number;
  timestamp: string;
  reasons: string[];
  listing?: ScanDossier["listing"];
}

async function pushRecentThreat(
  env: Env,
  event: RecentThreatEvent,
): Promise<void> {
  const current =
    ((await env.SCAN_CACHE.get(RECENT_THREATS_KEY, "json")) as
      | RecentThreatEvent[]
      | null) ?? [];

  const next = [event, ...current.filter((e) => e.contract !== event.contract)];
  await kvPutBestEffort(
    env.SCAN_CACHE,
    RECENT_THREATS_KEY,
    JSON.stringify(next.slice(0, MAX_RECENT_THREATS)),
  );
}

/** Newest-first buffer for the live threat stream. */
export async function listRecentThreats(
  env: Env,
): Promise<RecentThreatEvent[]> {
  return (
    ((await env.SCAN_CACHE.get(RECENT_THREATS_KEY, "json")) as
      | RecentThreatEvent[]
      | null) ?? []
  );
}

async function appendToDayIndex(
  env: Env,
  day: string,
  address: string,
): Promise<void> {
  const key = threatDayKey(day);
  const current = ((await env.SCAN_CACHE.get(key, "json")) as string[] | null) ?? [];

  if (current.includes(address)) {
    return;
  }

  current.push(address);
  await kvPutBestEffort(env.SCAN_CACHE, key, JSON.stringify(current), {
    expirationTtl: DAY_INDEX_TTL_SECONDS,
  });
}

/** Build the paid daily threat package (SCAM + SUSPICIOUS). */
export async function buildDailyThreatFeed(
  env: Env,
  date: string,
): Promise<DailyThreatFeed> {
  const indexed = (await env.SCAN_CACHE.get(threatDayKey(date), "json")) as
    | string[]
    | null;

  let addresses: string[];

  if (indexed && indexed.length > 0) {
    addresses = indexed;
  } else {
    addresses = await listThreatAddressesForDate(env, date);
  }

  const threats: ThreatRecord[] = [];

  for (const address of addresses) {
    const record = (await env.SCAN_CACHE.get(
      threatContractKey(address),
      "json",
    )) as ThreatRecord | null;

    if (record) {
      // Older records may omit status.
      const status = record.status ?? statusFromScore(record.riskScore);
      threats.push({ ...record, status });
    }
  }

  threats.sort((a, b) => b.riskScore - a.riskScore);

  return {
    feed: "base-sentinel-threat-intel",
    network: resolveNetwork(env),
    date,
    generatedAt: new Date().toISOString(),
    count: threats.length,
    counts: {
      scam: threats.filter((t) => t.status === "SCAM").length,
      suspicious: threats.filter((t) => t.status === "SUSPICIOUS").length,
    },
    threats,
  };
}

async function listThreatAddressesForDate(
  env: Env,
  date: string,
): Promise<string[]> {
  const addresses: string[] = [];
  let cursor: string | undefined;

  do {
    const page = await env.SCAN_CACHE.list({
      prefix: "threat:contract:",
      cursor,
      limit: 1000,
    });

    for (const key of page.keys) {
      const record = (await env.SCAN_CACHE.get(key.name, "json")) as ThreatRecord | null;
      if (!record) continue;

      const firstSeenDay = record.timestamp?.slice(0, 10);
      const lastSeenDay = record.lastSeen?.slice(0, 10);
      if (firstSeenDay === date || lastSeenDay === date) {
        addresses.push(record.address);
      }
    }

    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return addresses;
}
