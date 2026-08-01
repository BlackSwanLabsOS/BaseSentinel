import type { Env } from "./types";
import { scanContract } from "./services/scanner";
import { buildPremiumDossier } from "./services/premiumDossier";
import {
  build402Response,
  dailyFeedBindingKey,
  enforcePayment,
  InvalidPaymentProofError,
  liveStreamBindingKey,
  PaymentBindingMismatchError,
  PaymentBoundToOtherContractError,
  PaymentBusyError,
  PaymentReplayError,
  PaymentRequiredError,
  watchBindingKey,
} from "./middleware/payment";
import { PaymentRateLimitError } from "./middleware/rateLimit";
import {
  getAutopsyReport,
  getAutopsyState,
  listPendingAutopsyReports,
  markAutopsyPublished,
  runAutopsyBatch,
} from "./services/autopsy";
import { AUTOPSY_COPY_GUARDRAILS } from "./services/autopsyMetrics";
import { isAdminAuthorized, requireAdmin } from "./middleware/admin";
import {
  buildAiPluginManifest,
  buildOpenApiDocument,
  buildToolsDocument,
  buildX402WellKnown,
  corsPreflightResponse,
  withCors,
} from "./discovery/manifest";
import {
  buildDailyThreatFeed,
  isValidFeedDate,
  utcDateString,
} from "./services/threatIntel";
import { createThreatEventStream } from "./services/threatStream";
import { getCronState, runScheduledScan } from "./services/cronScanner";
import { normalizeEthereumAddress } from "./utils/validation";
import { isMarketingHost, landingResponse } from "./landing";
import { M2M_DOCS_MARKDOWN } from "./docs/m2mQuickstart";
import {
  apiErrorBody,
  apiErrorResponse,
  classifyInfraError,
  ErrorCode,
} from "./errors";
import {
  createWatchSubscription,
  parseWatchCreateBody,
  WatchValidationError,
  webhookFingerprint,
  WATCH_TTL_SECONDS,
} from "./services/watchList";

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function upstreamErrorResponse(message: string): Response {
  const { errorCode, status } = classifyInfraError(message);
  return apiErrorResponse(errorCode, message, status);
}

/**
 * Extracts a raw address candidate from /scan/{addr} or /dossier/{addr} or ?address=.
 */
function extractRawAddress(
  url: URL,
  productPath: "scan" | "dossier",
): string | null {
  const pathMatch = url.pathname.match(
    new RegExp(`^\\/${productPath}\\/([^/]+)\\/?$`),
  );
  if (pathMatch?.[1]) {
    try {
      return decodeURIComponent(pathMatch[1]);
    } catch {
      return pathMatch[1];
    }
  }

  if (productPath === "scan") {
    return url.searchParams.get("address");
  }
  return null;
}

/**
 * Browser / playground clients send OPTIONS before GET/POST with
 * X-Payment-Proof. Must cover paid paths too (/scan, /dossier, …),
 * not only discovery manifests.
 */
function allowsCorsPreflight(pathname: string): boolean {
  if (
    pathname === "/" ||
    pathname === "/health" ||
    pathname === "/docs" ||
    pathname === "/docs/" ||
    pathname === "/openapi.json" ||
    pathname === "/tools.json" ||
    pathname === "/watch" ||
    pathname === "/stream/threats" ||
    pathname === "/.well-known/ai-plugin.json" ||
    pathname === "/.well-known/x402.json"
  ) {
    return true;
  }
  if (pathname === "/scan" || pathname.startsWith("/scan/")) return true;
  if (pathname === "/dossier" || pathname.startsWith("/dossier/")) return true;
  if (pathname.startsWith("/api/feed/daily")) return true;
  if (pathname.startsWith("/api/admin/")) return true;
  return false;
}

async function handleWatchRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  let parsed;
  try {
    const body = await request.json();
    parsed = parseWatchCreateBody(body);
  } catch (error) {
    if (error instanceof WatchValidationError) {
      const code = /address/i.test(error.message)
        ? ErrorCode.INVALID_ADDRESS_FORMAT
        : ErrorCode.INVALID_JSON;
      return withCors(
        apiErrorResponse(code, error.message, error.status),
      );
    }
    if (error instanceof SyntaxError) {
      return withCors(
        apiErrorResponse(ErrorCode.INVALID_JSON, "Invalid JSON body", 400),
      );
    }
    throw error;
  }

  const fingerprint = await webhookFingerprint(parsed.webhook_url);
  const bindingKey = watchBindingKey(parsed.target_address, fingerprint);

  if (!isAdminAuthorized(request, env)) {
    try {
      await enforcePayment(request, env, {
        product: "watch",
        bindingKey,
        resourceUrl: request.url,
      });
    } catch (error) {
      const paidError = paymentErrorResponse(error, env, request.url);
      if (paidError) {
        return paidError;
      }
      throw error;
    }
  }

  // Seed watch baseline on create (no false STATUS_CHANGED on first tick).
  let initialScan = null;
  try {
    initialScan = await scanContract(parsed.target_address, env, {
      bypassCache: true,
    });
  } catch (error) {
    console.error(
      "[watch] initial scan failed:",
      error instanceof Error ? error.message : error,
    );
  }

  const watch = await createWatchSubscription(env, parsed, initialScan);
  return withCors(
    jsonResponse({
      ok: true,
      watch_id: watch.id,
      target_address: watch.target_address,
      webhook_url: watch.webhook_url,
      ttl_seconds: WATCH_TTL_SECONDS,
      expires_at: watch.expires_at,
      baseline: {
        verdict: watch.last_verdict,
        tax: watch.last_tax,
        risk_flags: watch.last_risk_flags,
      },
      access: isAdminAuthorized(request, env) ? "admin" : "paid",
    }),
  );
}

async function handleThreatStreamRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!isAdminAuthorized(request, env)) {
    try {
      await enforcePayment(request, env, {
        product: "live_stream",
        bindingKey: liveStreamBindingKey(),
        resourceUrl: request.url,
        allowReuse: true,
      });
    } catch (error) {
      const paidError = paymentErrorResponse(error, env, request.url);
      if (paidError) {
        return paidError;
      }
      throw error;
    }
  }

  const cursor =
    request.headers.get("Last-Event-ID")?.trim() ||
    new URL(request.url).searchParams.get("cursor");

  return withCors(createThreatEventStream(env, { cursor }));
}

function paymentErrorResponse(
  error: unknown,
  env: Env,
  requestUrl: string,
): Response | null {
  if (error instanceof PaymentRequiredError) {
    return withCors(build402Response(env, requestUrl, error.product));
  }

  if (error instanceof PaymentRateLimitError) {
    const res = apiErrorResponse(
      error.errorCode,
      error.message,
      error.status,
    );
    res.headers.set("Retry-After", String(error.retryAfterSeconds));
    return withCors(res);
  }

  if (error instanceof PaymentBusyError) {
    const res = apiErrorResponse(
      error.errorCode,
      error.message,
      error.status,
    );
    res.headers.set("Retry-After", String(error.retryAfterSeconds));
    return withCors(res);
  }

  if (
    error instanceof PaymentReplayError ||
    error instanceof PaymentBindingMismatchError ||
    error instanceof PaymentBoundToOtherContractError ||
    error instanceof InvalidPaymentProofError
  ) {
    return withCors(
      apiErrorResponse(error.errorCode, error.message, error.status),
    );
  }

  return null;
}

async function handleDailyFeedRequest(
  request: Request,
  env: Env,
  url: URL,
  dateFromPath?: string,
): Promise<Response> {
  const dateParam =
    dateFromPath ?? url.searchParams.get("date") ?? utcDateString();
  if (!isValidFeedDate(dateParam)) {
    return withCors(
      apiErrorResponse(
        ErrorCode.INVALID_JSON,
        "Invalid date. Use a real UTC calendar day YYYY-MM-DD (not in the future).",
        400,
      ),
    );
  }

  // Optional admin key unlocks creator/diagnostics access.
  if (!isAdminAuthorized(request, env)) {
    try {
      await enforcePayment(request, env, {
        product: "daily_feed",
        bindingKey: dailyFeedBindingKey(dateParam),
        resourceUrl: request.url,
        resourceDescription: "BaseSentinel daily threat intelligence feed",
      });
    } catch (error) {
      const paidError = paymentErrorResponse(error, env, request.url);
      if (paidError) {
        return paidError;
      }
      throw error;
    }
  }

  const feed = await buildDailyThreatFeed(env, dateParam);
  return withCors(
    jsonResponse({
      ...feed,
      access: isAdminAuthorized(request, env) ? "admin" : "paid",
    }),
  );
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const origin = url.origin;

    // Apex / www → landing page; api.* → JSON API.
    if (
      isMarketingHost(url.hostname) &&
      (url.pathname === "/" || url.pathname === "")
    ) {
      return landingResponse();
    }

    if (request.method === "OPTIONS" && allowsCorsPreflight(url.pathname)) {
      return corsPreflightResponse();
    }

    if (url.pathname === "/watch") {
      if (request.method === "POST") {
        try {
          return await handleWatchRequest(request, env);
        } catch (error) {
          const paidError = paymentErrorResponse(error, env, request.url);
          if (paidError) {
            return paidError;
          }
          const message =
            error instanceof Error ? error.message : "Unknown watch error";
          return withCors(upstreamErrorResponse(message));
        }
      }
      return apiErrorResponse(
        ErrorCode.METHOD_NOT_ALLOWED,
        "Method Not Allowed",
        405,
      );
    }

    // Admin autopsy publisher hooks (GET + POST) before global GET gate.
    if (url.pathname.startsWith("/api/admin/autopsy")) {
      const authError = requireAdmin(request, env);
      if (authError) {
        return withCors(authError);
      }

      if (
        url.pathname === "/api/admin/autopsy/pending" &&
        request.method === "GET"
      ) {
        const limit = Math.min(
          50,
          Math.max(1, Number(url.searchParams.get("limit") ?? "20") || 20),
        );
        const reports = await listPendingAutopsyReports(env, limit);
        return withCors(
          jsonResponse({
            count: reports.length,
            copy_guardrails: AUTOPSY_COPY_GUARDRAILS,
            reports,
          }),
        );
      }

      if (
        url.pathname === "/api/admin/autopsy/state" &&
        request.method === "GET"
      ) {
        return withCors(jsonResponse(await getAutopsyState(env)));
      }

      if (
        url.pathname === "/api/admin/autopsy/run" &&
        request.method === "POST"
      ) {
        const stats = await runAutopsyBatch(env);
        return withCors(jsonResponse({ ok: true, stats }));
      }

      if (
        url.pathname === "/api/admin/autopsy/publish" &&
        request.method === "POST"
      ) {
        let body: { address?: string };
        try {
          body = (await request.json()) as { address?: string };
        } catch {
          return withCors(
            apiErrorResponse(ErrorCode.INVALID_JSON, "Invalid JSON body", 400),
          );
        }
        const address = body.address?.trim().toLowerCase();
        if (!address || !/^0x[a-f0-9]{40}$/.test(address)) {
          return withCors(
            apiErrorResponse(
              ErrorCode.INVALID_ADDRESS_FORMAT,
              "Invalid address",
              400,
            ),
          );
        }
        const updated = await markAutopsyPublished(env, address);
        if (!updated) {
          return withCors(
            apiErrorResponse(ErrorCode.NOT_FOUND, "Autopsy report not found", 404),
          );
        }
        return withCors(jsonResponse({ ok: true, report: updated }));
      }

      const one = url.pathname.match(
        /^\/api\/admin\/autopsy\/(0x[a-fA-F0-9]{40})$/,
      );
      if (one && request.method === "GET") {
        const report = await getAutopsyReport(env, one[1]);
        if (!report) {
          return withCors(
            apiErrorResponse(ErrorCode.NOT_FOUND, "Autopsy report not found", 404),
          );
        }
        return withCors(jsonResponse(report));
      }

      return withCors(
        apiErrorResponse(ErrorCode.NOT_FOUND, "Not Found", 404),
      );
    }

    if (request.method !== "GET") {
      return apiErrorResponse(
        ErrorCode.METHOD_NOT_ALLOWED,
        "Method Not Allowed",
        405,
      );
    }

    if (url.pathname === "/.well-known/ai-plugin.json") {
      return withCors(jsonResponse(buildAiPluginManifest(origin, env)));
    }

    if (url.pathname === "/.well-known/x402.json") {
      return withCors(jsonResponse(buildX402WellKnown(origin, env)));
    }

    if (url.pathname === "/openapi.json") {
      return withCors(jsonResponse(buildOpenApiDocument(origin, env)));
    }

    if (url.pathname === "/tools.json") {
      return withCors(jsonResponse(buildToolsDocument(origin, env)));
    }

    if (url.pathname === "/docs" || url.pathname === "/docs/") {
      return withCors(
        new Response(M2M_DOCS_MARKDOWN, {
          status: 200,
          headers: {
            "Content-Type": "text/markdown; charset=utf-8",
            "Cache-Control": "public, max-age=300",
          },
        }),
      );
    }

    if (url.pathname === "/health") {
      const cron = await getCronState(env);
      const staleMs = cron.lastSuccessAt
        ? Date.now() - Date.parse(cron.lastSuccessAt)
        : null;

      return withCors(
        jsonResponse({
          status: "ok",
          service: "base-sentinel",
          timestamp: new Date().toISOString(),
          cron: {
            ...cron,
            healthy:
              Boolean(cron.lastSuccessAt) &&
              !cron.lastError &&
              staleMs !== null &&
              staleMs < 15 * 60 * 1000,
            staleMs,
          },
        }),
      );
    }

    if (url.pathname === "/api/admin/cron-status") {
      const authError = requireAdmin(request, env);
      if (authError) {
        return authError;
      }
      return jsonResponse(await getCronState(env));
    }

    // Paid daily feed (HTTP 402). Preferred path: /api/feed/daily/YYYY-MM-DD
    const dailyFeedPath = url.pathname.match(
      /^\/api\/feed\/daily\/(\d{4}-\d{2}-\d{2})$/,
    );
    if (dailyFeedPath) {
      return handleDailyFeedRequest(request, env, url, dailyFeedPath[1]);
    }
    if (url.pathname === "/api/feed/daily") {
      return handleDailyFeedRequest(request, env, url);
    }

    // Live threat stream (SSE; short sessions with client reconnect).
    if (url.pathname === "/stream/threats") {
      return handleThreatStreamRequest(request, env);
    }

    // Admin-only daily feed (diagnostics).
    if (url.pathname === "/api/admin/daily-feed") {
      const authError = requireAdmin(request, env);
      if (authError) {
        return authError;
      }

      const dateParam = url.searchParams.get("date") ?? utcDateString();
      if (!isValidFeedDate(dateParam)) {
        return apiErrorResponse(
          ErrorCode.INVALID_JSON,
          "Invalid date. Use a real UTC calendar day YYYY-MM-DD (not in the future).",
          400,
        );
      }

      const feed = await buildDailyThreatFeed(env, dateParam);
      return jsonResponse({ ...feed, access: "admin" });
    }

    if (url.pathname === "/" && !url.searchParams.has("address")) {
      return jsonResponse({
        status: "ok",
        service: "base-sentinel",
        timestamp: new Date().toISOString(),
        discovery: {
          ai_plugin: `${origin}/.well-known/ai-plugin.json`,
          x402: `${origin}/.well-known/x402.json`,
          openapi: `${origin}/openapi.json`,
          tools: `${origin}/tools.json`,
          docs: `${origin}/docs`,
        },
        products: {
          scan: `${origin}/scan/{address}`,
          dossier: `${origin}/dossier/{address}`,
          watch: `${origin}/watch`,
          daily_feed: `${origin}/api/feed/daily/YYYY-MM-DD`,
          live_stream: `${origin}/stream/threats`,
        },
        health: `${origin}/health`,
        docs: `${origin}/docs`,
        tools: `${origin}/tools.json`,
      });
    }

    const isDossierPath =
      url.pathname === "/dossier" || url.pathname.startsWith("/dossier/");
    if (isDossierPath) {
      const rawAddress = extractRawAddress(url, "dossier");
      if (!rawAddress) {
        return withCors(
          jsonResponse(
            {
              ...apiErrorBody(
                ErrorCode.INVALID_ADDRESS_FORMAT,
                "Missing or invalid address",
              ),
              usage: ["GET /dossier/0xYourContractAddress"],
            },
            400,
          ),
        );
      }
      const address = normalizeEthereumAddress(rawAddress);
      if (!address) {
        return withCors(
          apiErrorResponse(
            ErrorCode.INVALID_ADDRESS_FORMAT,
            "Invalid smart contract address format",
            400,
          ),
        );
      }
      try {
        await enforcePayment(request, env, {
          product: "dossier",
          bindingKey: address,
          resourceUrl: request.url,
        });
        const result = await buildPremiumDossier(address, env, {
          bypassCache: isAdminAuthorized(request, env),
        });
        return withCors(
          jsonResponse({
            ...result,
            access: isAdminAuthorized(request, env) ? "admin" : "paid",
          }),
        );
      } catch (error) {
        const paidError = paymentErrorResponse(error, env, request.url);
        if (paidError) {
          return paidError;
        }
        const message =
          error instanceof Error ? error.message : "Unknown dossier error";
        if (message === "Invalid smart contract address format") {
          return withCors(
            apiErrorResponse(
              ErrorCode.INVALID_ADDRESS_FORMAT,
              message,
              400,
            ),
          );
        }
        return withCors(upstreamErrorResponse(message));
      }
    }

    const isScanPath =
      url.pathname === "/scan" || url.pathname.startsWith("/scan/");
    const isAddressQuery =
      url.pathname === "/" && url.searchParams.has("address");

    if (isScanPath || isAddressQuery) {
      const rawAddress = extractRawAddress(url, "scan");

      if (!rawAddress) {
        return withCors(
          jsonResponse(
            {
              ...apiErrorBody(
                ErrorCode.INVALID_ADDRESS_FORMAT,
                "Missing or invalid address",
              ),
              usage: [
                "GET /scan/0xYourContractAddress",
                "GET /?address=0xYourContractAddress",
              ],
            },
            400,
          ),
        );
      }

      const address = normalizeEthereumAddress(rawAddress);
      if (!address) {
        return withCors(
          apiErrorResponse(
            ErrorCode.INVALID_ADDRESS_FORMAT,
            "Invalid smart contract address format",
            400,
          ),
        );
      }

      try {
        await enforcePayment(request, env, {
          product: "scan",
          bindingKey: address,
          resourceUrl: request.url,
        });
        const result = await scanContract(address, env, {
          bypassCache: isAdminAuthorized(request, env),
        });
        return withCors(
          jsonResponse({
            ...result,
            access: isAdminAuthorized(request, env) ? "admin" : "paid",
          }),
        );
      } catch (error) {
        const paidError = paymentErrorResponse(error, env, request.url);
        if (paidError) {
          return paidError;
        }

        const message =
          error instanceof Error ? error.message : "Unknown scan error";

        if (message === "Invalid smart contract address format") {
          return withCors(
            apiErrorResponse(
              ErrorCode.INVALID_ADDRESS_FORMAT,
              message,
              400,
            ),
          );
        }

        return withCors(upstreamErrorResponse(message));
      }
    }

    return apiErrorResponse(ErrorCode.NOT_FOUND, "Not Found", 404);
  },

  async scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    await runScheduledScan(env, ctx);
  },
} satisfies ExportedHandler<Env>;

export { PaymentLockDO } from "./durable/paymentLock";
