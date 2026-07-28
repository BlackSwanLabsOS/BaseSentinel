import type { Env } from "../types";
import { resolveNetwork } from "../config/network";

/** Threat records are kept without TTL (durable intel archive). */
const DAY_INDEX_TTL_SECONDS = 90 * 86_400; // 90 days

export interface ThreatRecord {
  address: string;
  network: string;
  reasons: string[];
  riskScore: number;
  timestamp: string;
  lastSeen: string;
  bytecodeLength?: number;
}

export interface DailyThreatFeed {
  feed: "base-sentinel-threat-intel";
  network: string;
  date: string;
  generatedAt: string;
  count: number;
  threats: ThreatRecord[];
}

interface ScamScanInput {
  address: string;
  network: string;
  reasons: string[];
  riskScore: number;
  bytecodeLength: number;
}

function threatContractKey(address: string): string {
  return `threat:contract:${address}`;
}

function threatDayKey(date: string): string {
  return `threat:day:${date}`;
}

/** UTC calendar day YYYY-MM-DD */
export function utcDateString(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export function isValidFeedDate(date: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(date);
}

/**
 * Persists a SCAM verdict into the threat-intel archive + daily index.
 * Idempotent per address: updates lastSeen / risk metadata if already known.
 */
export async function recordThreat(
  env: Env,
  scan: ScamScanInput,
): Promise<void> {
  if (scan.riskScore < 75) {
    return;
  }

  const address = scan.address.toLowerCase();
  const now = new Date().toISOString();
  const key = threatContractKey(address);

  const existing = (await env.SCAN_CACHE.get(key, "json")) as ThreatRecord | null;

  const record: ThreatRecord = existing
    ? {
        ...existing,
        reasons: scan.reasons,
        riskScore: Math.max(existing.riskScore, scan.riskScore),
        lastSeen: now,
        bytecodeLength: scan.bytecodeLength,
      }
    : {
        address,
        network: scan.network || resolveNetwork(env),
        reasons: scan.reasons,
        riskScore: scan.riskScore,
        timestamp: now,
        lastSeen: now,
        bytecodeLength: scan.bytecodeLength,
      };

  await env.SCAN_CACHE.put(key, JSON.stringify(record));

  const day = utcDateString(new Date(now));
  await appendToDayIndex(env, day, address);
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
  await env.SCAN_CACHE.put(key, JSON.stringify(current), {
    expirationTtl: DAY_INDEX_TTL_SECONDS,
  });
}

/**
 * Builds an exportable daily threat package.
 * Prefers the day index; falls back to prefix listing filtered by timestamp date.
 */
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
      threats.push(record);
    }
  }

  threats.sort((a, b) => b.riskScore - a.riskScore);

  return {
    feed: "base-sentinel-threat-intel",
    network: resolveNetwork(env),
    date,
    generatedAt: new Date().toISOString(),
    count: threats.length,
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
