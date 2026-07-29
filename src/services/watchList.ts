import type { Env } from "../types";
import { normalizeEthereumAddress } from "../utils/validation";
import { scanContract, type ScanResult } from "./scanner";
import { maxTax, type AgentVerdict } from "./verdict";

export const WATCH_KEY_PREFIX = "watch:";
export const WATCH_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
/** Max watch re-scans per cron tick. */
export const MAX_WATCH_SCANS_PER_RUN = 5;
const WATCH_CURSOR_KEY = "watch:cursor";
const WEBHOOK_TIMEOUT_MS = 8_000;

export interface WatchRecord {
  id: string;
  target_address: string;
  webhook_url: string;
  created_at: string;
  expires_at: string;
  last_verdict: AgentVerdict | null;
  last_tax: number | null;
  last_risk_flags: string[];
  last_checked_at: string | null;
  last_notified_at: string | null;
}

export interface WatchCreateRequest {
  target_address: string;
  webhook_url: string;
}

export interface WatchStatusChangedEvent {
  event: "STATUS_CHANGED";
  watch_id: string;
  address: string;
  previous_verdict: AgentVerdict | null;
  new_verdict: AgentVerdict;
  previous_tax: number | null;
  new_tax: number | null;
  previous_risk_flags: string[];
  new_risk_flags: string[];
  reason: string;
  checked_at: string;
}

export interface WatchRunStats {
  listed: number;
  checked: number;
  notified: number;
  errors: number;
  skippedLimit: number;
}

export class WatchValidationError extends Error {
  readonly status = 400;
  constructor(message: string) {
    super(message);
    this.name = "WatchValidationError";
  }
}

function watchKvKey(id: string): string {
  return `${WATCH_KEY_PREFIX}${id}`;
}

function isPrivateIpv4(hostname: string): boolean {
  const m = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const octets = m.slice(1).map((x) => Number(x));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = octets;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (
    host === "localhost" ||
    host === "localhost.localdomain" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan") ||
    host === "metadata.google.internal" ||
    host === "::1" ||
    host === "[::1]" ||
    host === "0.0.0.0"
  ) {
    return true;
  }
  if (host.includes(":")) {
    // IPv6 literals — block loopback / ULA / link-local prefixes.
    const bare = host.replace(/^\[|\]$/g, "");
    if (
      bare === "::1" ||
      bare.startsWith("fc") ||
      bare.startsWith("fd") ||
      bare.startsWith("fe80") ||
      bare.startsWith("::ffff:127.") ||
      bare.startsWith("::ffff:10.") ||
      bare.startsWith("::ffff:192.168.")
    ) {
      return true;
    }
  }
  return isPrivateIpv4(host);
}

/** Validate webhook URL: HTTPS only, no private/loopback hosts. */
export function assertSafeWebhookUrl(raw: unknown): string {
  if (typeof raw !== "string" || !raw.trim()) {
    throw new WatchValidationError("webhook_url is required");
  }

  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new WatchValidationError("webhook_url is not a valid URL");
  }

  if (url.protocol !== "https:") {
    throw new WatchValidationError("webhook_url must use https://");
  }
  if (url.username || url.password) {
    throw new WatchValidationError("webhook_url must not include credentials");
  }
  if (!url.hostname) {
    throw new WatchValidationError("webhook_url hostname is required");
  }
  if (isBlockedHostname(url.hostname)) {
    throw new WatchValidationError(
      "webhook_url host is not allowed (private/loopback/metadata)",
    );
  }

  return url.toString();
}

export async function webhookFingerprint(webhookUrl: string): Promise<string> {
  const data = new TextEncoder().encode(webhookUrl);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  return [...bytes]
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function snapshotFromScan(scan: ScanResult): {
  verdict: AgentVerdict;
  tax: number | null;
  risk_flags: string[];
} {
  return {
    verdict: scan.verdict,
    tax: maxTax(scan.dossier?.goplus ?? null, scan.dossier?.honeypotIs ?? null),
    risk_flags: [...scan.risk_flags].sort(),
  };
}

function flagsEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function taxEqual(a: number | null, b: number | null): boolean {
  if (a === null && b === null) return true;
  if (a === null || b === null) return false;
  return Math.abs(a - b) < 1e-9;
}

function buildChangeReason(
  previous: {
    verdict: AgentVerdict | null;
    tax: number | null;
    risk_flags: string[];
  },
  next: { verdict: AgentVerdict; tax: number | null; risk_flags: string[] },
): string {
  const parts: string[] = [];
  if (previous.verdict !== next.verdict) {
    parts.push(
      `Verdict ${previous.verdict ?? "none"} → ${next.verdict}`,
    );
  }
  if (!taxEqual(previous.tax, next.tax)) {
    const from =
      previous.tax === null ? "unknown" : `${previous.tax}%`;
    const to = next.tax === null ? "unknown" : `${next.tax}%`;
    parts.push(`Tax ${from} → ${to}`);
  }
  if (!flagsEqual(previous.risk_flags, next.risk_flags)) {
    const added = next.risk_flags.filter(
      (f) => !previous.risk_flags.includes(f),
    );
    const removed = previous.risk_flags.filter(
      (f) => !next.risk_flags.includes(f),
    );
    if (added.length) parts.push(`Flags added: ${added.join(", ")}`);
    if (removed.length) parts.push(`Flags removed: ${removed.join(", ")}`);
  }
  return parts.join("; ") || "Status changed";
}

export function parseWatchCreateBody(body: unknown): WatchCreateRequest {
  if (!body || typeof body !== "object") {
    throw new WatchValidationError("JSON body required");
  }
  const record = body as Record<string, unknown>;
  const address = normalizeEthereumAddress(record.target_address);
  if (!address) {
    throw new WatchValidationError(
      "target_address must be a valid EVM address (0x + 40 hex)",
    );
  }
  const webhook_url = assertSafeWebhookUrl(record.webhook_url);
  return { target_address: address, webhook_url };
}

export async function createWatchSubscription(
  env: Env,
  input: WatchCreateRequest,
  initial?: ScanResult | null,
): Promise<WatchRecord> {
  const id = crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + WATCH_TTL_SECONDS * 1000);
  const snap = initial ? snapshotFromScan(initial) : null;

  const record: WatchRecord = {
    id,
    target_address: input.target_address,
    webhook_url: input.webhook_url,
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
    last_verdict: snap?.verdict ?? null,
    last_tax: snap?.tax ?? null,
    last_risk_flags: snap?.risk_flags ?? [],
    last_checked_at: snap ? now.toISOString() : null,
    last_notified_at: null,
  };

  await env.SCAN_CACHE.put(watchKvKey(id), JSON.stringify(record), {
    expirationTtl: WATCH_TTL_SECONDS,
  });

  return record;
}

async function listWatchKeys(env: Env): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.SCAN_CACHE.list({
      prefix: WATCH_KEY_PREFIX,
      cursor,
      limit: 1000,
    });
    for (const key of page.keys) {
      if (key.name === WATCH_CURSOR_KEY) continue;
      // Subscription records: watch:{uuid}
      if (!/^watch:[0-9a-f-]{36}$/i.test(key.name)) continue;
      keys.push(key.name);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  keys.sort();
  return keys;
}

async function getWatchCursor(env: Env): Promise<string | null> {
  return env.SCAN_CACHE.get(WATCH_CURSOR_KEY);
}

async function setWatchCursor(env: Env, key: string | null): Promise<void> {
  if (!key) {
    await env.SCAN_CACHE.delete(WATCH_CURSOR_KEY);
    return;
  }
  await env.SCAN_CACHE.put(WATCH_CURSOR_KEY, key);
}

function rotateKeys(keys: string[], afterKey: string | null): string[] {
  if (!keys.length) return [];
  if (!afterKey) return keys;
  const idx = keys.findIndex((k) => k === afterKey);
  if (idx < 0) return keys;
  return [...keys.slice(idx + 1), ...keys.slice(0, idx + 1)];
}

async function postWebhook(
  webhookUrl: string,
  payload: WatchStatusChangedEvent,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "BaseSentinel-Watch/1.0",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`webhook HTTP ${response.status}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

async function remainingTtlSeconds(
  env: Env,
  key: string,
  fallbackExpiresAt: string,
): Promise<number> {
  // TTL derived from expires_at.
  const ms = Date.parse(fallbackExpiresAt) - Date.now();
  const seconds = Math.floor(ms / 1000);
  if (Number.isFinite(seconds) && seconds > 60) {
    return Math.min(seconds, WATCH_TTL_SECONDS);
  }
  // Missing expiry → short lease so records do not persist forever.
  void env;
  void key;
  return 3600;
}

/**
 * Re-check active watches each cron tick.
 * Webhook fires only when verdict, tax, or risk_flags change.
 */
export async function runWatchChecks(
  env: Env,
  ctx?: ExecutionContext,
): Promise<WatchRunStats> {
  const stats: WatchRunStats = {
    listed: 0,
    checked: 0,
    notified: 0,
    errors: 0,
    skippedLimit: 0,
  };

  const keys = await listWatchKeys(env);
  stats.listed = keys.length;
  if (!keys.length) return stats;

  const cursor = await getWatchCursor(env);
  const ordered = rotateKeys(keys, cursor);
  let lastProcessed: string | null = cursor;

  for (const key of ordered) {
    if (stats.checked >= MAX_WATCH_SCANS_PER_RUN) {
      stats.skippedLimit += 1;
      continue;
    }

    try {
      const record = (await env.SCAN_CACHE.get(key, "json")) as WatchRecord | null;
      if (!record) continue;

      const scan = await scanContract(record.target_address, env, {
        bypassCache: true,
        waitUntil: ctx ? (p) => ctx.waitUntil(p) : undefined,
      });
      const snap = snapshotFromScan(scan);
      const checkedAt = new Date().toISOString();
      stats.checked += 1;
      lastProcessed = key;

      const previous = {
        verdict: record.last_verdict,
        tax: record.last_tax,
        risk_flags: [...(record.last_risk_flags ?? [])].sort(),
      };

      const changed =
        record.last_checked_at !== null &&
        (previous.verdict !== snap.verdict ||
          !taxEqual(previous.tax, snap.tax) ||
          !flagsEqual(previous.risk_flags, snap.risk_flags));

      // First check seeds baseline only (no webhook).
      let notifiedAt = record.last_notified_at;
      if (changed) {
        const payload: WatchStatusChangedEvent = {
          event: "STATUS_CHANGED",
          watch_id: record.id,
          address: record.target_address,
          previous_verdict: previous.verdict,
          new_verdict: snap.verdict,
          previous_tax: previous.tax,
          new_tax: snap.tax,
          previous_risk_flags: previous.risk_flags,
          new_risk_flags: snap.risk_flags,
          reason: buildChangeReason(previous, snap),
          checked_at: checkedAt,
        };

        const notify = postWebhook(record.webhook_url, payload).catch(
          (error) => {
            console.error(
              `[watch] webhook failed ${record.id}:`,
              error instanceof Error ? error.message : error,
            );
          },
        );
        if (ctx) ctx.waitUntil(notify);
        else await notify;

        notifiedAt = checkedAt;
        stats.notified += 1;
      }

      const updated: WatchRecord = {
        ...record,
        last_verdict: snap.verdict,
        last_tax: snap.tax,
        last_risk_flags: snap.risk_flags,
        last_checked_at: checkedAt,
        last_notified_at: notifiedAt,
      };

      const ttl = await remainingTtlSeconds(env, key, record.expires_at);
      await env.SCAN_CACHE.put(key, JSON.stringify(updated), {
        expirationTtl: ttl,
      });
    } catch (error) {
      stats.errors += 1;
      lastProcessed = key;
      console.error(
        `[watch] check failed ${key}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }

  if (lastProcessed) {
    await setWatchCursor(env, lastProcessed);
  }

  console.log(
    `[watch] listed=${stats.listed} checked=${stats.checked} notified=${stats.notified} errors=${stats.errors} skipped=${stats.skippedLimit}`,
  );

  return stats;
}
