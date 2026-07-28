import type { Env } from "./types";
import { scanContract } from "./services/scanner";
import {
  build402Response,
  dailyFeedBindingKey,
  enforcePayment,
  InvalidPaymentProofError,
  PaymentBindingMismatchError,
  PaymentBoundToOtherContractError,
  PaymentReplayError,
  PaymentRequiredError,
} from "./middleware/payment";
import { isAdminAuthorized, requireAdmin } from "./middleware/admin";
import {
  buildAiPluginManifest,
  buildOpenApiDocument,
  corsPreflightResponse,
  withCors,
} from "./discovery/manifest";
import {
  buildDailyThreatFeed,
  isValidFeedDate,
  utcDateString,
} from "./services/threatIntel";
import { getCronState, runScheduledScan } from "./services/cronScanner";
import { normalizeEthereumAddress } from "./utils/validation";

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

/**
 * Extracts a raw address candidate from path or query.
 * Does NOT validate — call normalizeEthereumAddress before use.
 */
function extractRawScanAddress(url: URL): string | null {
  const pathMatch = url.pathname.match(/^\/scan\/([^/]+)\/?$/);
  if (pathMatch?.[1]) {
    try {
      return decodeURIComponent(pathMatch[1]);
    } catch {
      return pathMatch[1];
    }
  }

  return url.searchParams.get("address");
}

function isDiscoveryPath(pathname: string): boolean {
  return (
    pathname === "/.well-known/ai-plugin.json" || pathname === "/openapi.json"
  );
}

function paymentErrorResponse(
  error: unknown,
  env: Env,
  requestUrl: string,
): Response | null {
  if (error instanceof PaymentRequiredError) {
    return withCors(build402Response(env, requestUrl, error.product));
  }

  if (
    error instanceof PaymentReplayError ||
    error instanceof PaymentBindingMismatchError ||
    error instanceof PaymentBoundToOtherContractError ||
    error instanceof InvalidPaymentProofError
  ) {
    return withCors(jsonResponse({ error: error.message }, error.status));
  }

  return null;
}

async function handleDailyFeedRequest(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  const dateParam = url.searchParams.get("date") ?? utcDateString();
  if (!isValidFeedDate(dateParam)) {
    return jsonResponse(
      { error: "Invalid date. Use YYYY-MM-DD (UTC)." },
      400,
    );
  }

  // Creators / diagnostics: free with admin key.
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

    if (request.method === "OPTIONS" && isDiscoveryPath(url.pathname)) {
      return corsPreflightResponse();
    }

    if (request.method !== "GET") {
      return jsonResponse({ error: "Method Not Allowed" }, 405);
    }

    if (url.pathname === "/.well-known/ai-plugin.json") {
      return withCors(jsonResponse(buildAiPluginManifest(origin, env)));
    }

    if (url.pathname === "/openapi.json") {
      return withCors(jsonResponse(buildOpenApiDocument(origin, env)));
    }

    if (url.pathname === "/health") {
      const cron = await getCronState(env);
      const staleMs = cron.lastSuccessAt
        ? Date.now() - Date.parse(cron.lastSuccessAt)
        : null;

      return jsonResponse({
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
      });
    }

    if (url.pathname === "/api/admin/cron-status") {
      const authError = requireAdmin(request, env);
      if (authError) {
        return authError;
      }
      return jsonResponse(await getCronState(env));
    }

    // Public commercial feed (402) + optional admin bypass.
    if (url.pathname === "/api/feed/daily") {
      return handleDailyFeedRequest(request, env, url);
    }

    // Legacy admin-only feed (diagnostics).
    if (url.pathname === "/api/admin/daily-feed") {
      const authError = requireAdmin(request, env);
      if (authError) {
        return authError;
      }

      const dateParam = url.searchParams.get("date") ?? utcDateString();
      if (!isValidFeedDate(dateParam)) {
        return jsonResponse(
          { error: "Invalid date. Use YYYY-MM-DD (UTC)." },
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
          openapi: `${origin}/openapi.json`,
        },
        products: {
          scan: `${origin}/scan/{address}`,
          daily_feed: `${origin}/api/feed/daily?date=YYYY-MM-DD`,
        },
        health: `${origin}/health`,
      });
    }

    const isScanPath =
      url.pathname === "/scan" || url.pathname.startsWith("/scan/");
    const isAddressQuery =
      url.pathname === "/" && url.searchParams.has("address");

    if (isScanPath || isAddressQuery) {
      const rawAddress = extractRawScanAddress(url);

      if (!rawAddress) {
        return withCors(
          jsonResponse(
            {
              error: "Missing or invalid address",
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
          jsonResponse(
            { error: "Invalid smart contract address format" },
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
        const result = await scanContract(address, env);
        return withCors(jsonResponse(result));
      } catch (error) {
        const paidError = paymentErrorResponse(error, env, request.url);
        if (paidError) {
          return paidError;
        }

        const message =
          error instanceof Error ? error.message : "Unknown scan error";

        const status =
          message === "Invalid smart contract address format" ? 400 : 502;

        return withCors(jsonResponse({ error: message }, status));
      }
    }

    return jsonResponse({ error: "Not Found" }, 404);
  },

  async scheduled(
    _event: ScheduledEvent,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<void> {
    await runScheduledScan(env);
  },
} satisfies ExportedHandler<Env>;
