import { ErrorCode } from "../errors";

/** Max on-chain payment receipt lookups per client IP per window. */
export const PAYMENT_VERIFY_RATE_LIMIT = 40;
/** Sliding fixed window length (seconds). */
export const PAYMENT_VERIFY_RATE_WINDOW_SECONDS = 60;

export class PaymentRateLimitError extends Error {
  readonly status = 429 as const;
  readonly errorCode = ErrorCode.RATE_LIMITED;
  readonly retryAfterSeconds: number;

  constructor(
    retryAfterSeconds = PAYMENT_VERIFY_RATE_WINDOW_SECONDS,
    message = "Too many payment verification attempts. Retry after a short backoff.",
  ) {
    super(message);
    this.name = "PaymentRateLimitError";
    this.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterSeconds));
  }
}

/** Client IP as seen by Cloudflare (falls back to a shared bucket). */
export function getClientIp(request: Request): string {
  const cf =
    request.headers.get("CF-Connecting-IP")?.trim() ||
    request.headers.get("True-Client-IP")?.trim();
  if (cf) return cf;
  // Last resort — shared bucket for non-CF / local wrangler.
  return "unknown";
}

/**
 * Soft rate limit before Alchemy receipt lookups.
 * Uses Cache API (not KV) so Free-tier KV write quotas are not burned.
 */
export async function assertPaymentVerifyRateLimit(
  request: Request,
): Promise<void> {
  const ip = getClientIp(request);
  const windowSec = PAYMENT_VERIFY_RATE_WINDOW_SECONDS;
  const max = PAYMENT_VERIFY_RATE_LIMIT;
  const windowId = Math.floor(Date.now() / 1000 / windowSec);
  const url = `https://basesentinel-rl.internal/pay-verify/${encodeURIComponent(ip)}/${windowId}`;
  const cacheKey = new Request(url, { method: "GET" });

  let count = 0;
  try {
    const existing = await caches.default.match(cacheKey);
    if (existing) {
      const raw = (await existing.text()).trim();
      const n = Number.parseInt(raw, 10);
      if (Number.isFinite(n) && n >= 0) count = n;
    }
  } catch (error) {
    // Fail open on cache errors — do not block legitimate payers.
    console.warn(
      "[rate-limit] cache match failed:",
      error instanceof Error ? error.message : String(error),
    );
    return;
  }

  if (count >= max) {
    const elapsedInWindow = Math.floor(Date.now() / 1000) % windowSec;
    const retryAfter = Math.max(1, windowSec - elapsedInWindow);
    throw new PaymentRateLimitError(retryAfter);
  }

  try {
    await caches.default.put(
      cacheKey,
      new Response(String(count + 1), {
        headers: {
          "Cache-Control": `public, max-age=${windowSec}`,
          "Content-Type": "text/plain",
        },
      }),
    );
  } catch (error) {
    console.warn(
      "[rate-limit] cache put failed:",
      error instanceof Error ? error.message : String(error),
    );
  }
}
