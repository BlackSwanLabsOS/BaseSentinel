import type { Env } from "../types";
import {
  getUsdcContractAddress,
  resolveNetwork,
} from "../config/network";
import { ErrorCode } from "../errors";
import { PAYMENT_PRODUCTS } from "../middleware/payment";
import {
  PUBLIC_INTEL_CAPABILITIES,
  PUBLIC_INTEL_SHORT,
  PUBLIC_INTEL_SUMMARY,
} from "./publicIntel";

const API_ERROR_SCHEMA = {
  type: "object",
  required: ["error_code", "message", "error"],
  properties: {
    error_code: {
      type: "string",
      enum: Object.values(ErrorCode),
      description: "Stable machine code — branch on this, not on message text",
    },
    message: { type: "string" },
    error: {
      type: "string",
      description: "Alias of message (backward compatible)",
    },
  },
} as const;

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, X-Payment-Proof, X-Payment-Signature, PAYMENT-SIGNATURE, X-Admin-Key, X-Admin-Secret",
  "Access-Control-Expose-Headers":
    "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-Payment-Required, X-Payment-Amount, X-Payment-Amount-Display, X-Payment-Network, X-Payment-Address, X-Payment-Recipient, X-Payment-Asset, X-Payment-Token, X-Payment-Product",
  "Access-Control-Max-Age": "86400",
};

export function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function corsPreflightResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: CORS_HEADERS,
  });
}

/**
 * AI Plugin-style discovery manifest for agentic clients.
 *
 * Note: OpenAI's ChatGPT plugin ecosystem is largely deprecated, but
 * `/.well-known/ai-plugin.json` remains a common discovery convention.
 * `api.url` MUST point to an OpenAPI document — not the scan endpoint itself.
 * Payment is HTTP 402 M2M (not a standard AI Plugin auth type).
 */
export function buildAiPluginManifest(origin: string, env: Env) {
  const network = resolveNetwork(env);
  const usdcContract = getUsdcContractAddress(network);

  return {
    schema_version: "v1",
    name_for_human: "BaseSentinel",
    name_for_model: "base_sentinel_scanner",
    description_for_human:
      "Base smart-contract threat intel: bytecode + GoPlus + honeypot.is, pay-per-call USDC.",
    description_for_model:
      `${PUBLIC_INTEL_SUMMARY} Returns SAFE/SUSPICIOUS/SCAM plus agent verdict CLEAR/CAUTION/AVOID. Scan=${PAYMENT_PRODUCTS.scan.amountDisplay}; premium dossier=${PAYMENT_PRODUCTS.dossier.amountDisplay}; 7-day watch=${PAYMENT_PRODUCTS.watch.amountDisplay}. HTTP 402 USDC.`,
    auth: {
      type: "none",
    },
    api: {
      type: "openapi",
      url: `${origin}/openapi.json`,
      has_user_authentication: false,
    },
    x_basesentinel_capabilities: PUBLIC_INTEL_CAPABILITIES,
    // Custom extension for M2M / agent payment discovery (not part of classic AI Plugin auth enum).
    x_m2m_payment: {
      type: "http_402_pay_per_call",
      products: {
        scan: {
          price: PAYMENT_PRODUCTS.scan.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.scan.amountAtomic,
          url_template: `${origin}/scan/{address}`,
        },
        dossier: {
          price: PAYMENT_PRODUCTS.dossier.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.dossier.amountAtomic,
          url_template: `${origin}/dossier/{address}`,
        },
        watch: {
          price: PAYMENT_PRODUCTS.watch.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.watch.amountAtomic,
          url_template: `${origin}/watch`,
          method: "POST",
          ttl_seconds: 604800,
        },
        daily_feed: {
          price: PAYMENT_PRODUCTS.daily_feed.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.daily_feed.amountAtomic,
          url_template: `${origin}/api/feed/daily/YYYY-MM-DD`,
        },
        live_stream: {
          price: PAYMENT_PRODUCTS.live_stream.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.live_stream.amountAtomic,
          url_template: `${origin}/stream/threats`,
        },
      },
      price: PAYMENT_PRODUCTS.scan.amountDisplay,
      amount_atomic: PAYMENT_PRODUCTS.scan.amountAtomic,
      network,
      caip2_network:
        network === "base" ? "eip155:8453" : "eip155:84532",
      payment_address: env.PAYMENT_ADDRESS,
      asset: "USDC",
      usdc_contract: usdcContract,
      proof_header: "X-Payment-Proof",
      x402_header: "PAYMENT-REQUIRED",
      scan_url_template: `${origin}/scan/{address}`,
      binding: "one_tx_hash_per_product_resource",
    },
  };
}

export function buildOpenApiDocument(origin: string, env: Env) {
  const network = resolveNetwork(env);

  return {
    openapi: "3.1.0",
    info: {
      title: "BaseSentinel",
      version: "0.1.0",
      description:
        `${PUBLIC_INTEL_SUMMARY} Pay-per-call via HTTP 402 + USDC tx proof bound to the target resource.`,
    },
    servers: [{ url: origin }],
    paths: {
      "/scan/{address}": {
        get: {
          operationId: "scanContract",
          summary: "Scan a smart contract address",
          description:
            `${PUBLIC_INTEL_SHORT} Requires X-Payment-Proof (USDC tx hash bound to this address). Without payment proof returns HTTP 402.`,
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              schema: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{40}$",
              },
              description: "EVM contract address to scan",
            },
            {
              name: "X-Payment-Proof",
              in: "header",
              required: true,
              schema: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
              description:
                `Transaction hash proving transfer of ${PAYMENT_PRODUCTS.scan.amountDisplay} to the payment address. Bound to this contract — cannot be reused for another address.`,
            },
          ],
          responses: {
            "200": {
              description: "Scan result with agent verdict",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string" },
                      network: { type: "string", example: network },
                      status: {
                        type: "string",
                        enum: ["SAFE", "SUSPICIOUS", "SCAM"],
                      },
                      riskScore: {
                        type: "integer",
                        minimum: 0,
                        maximum: 100,
                        description: "Internal risk 0=clean … 100=deadly",
                      },
                      verdict: {
                        type: "string",
                        enum: ["CLEAR", "CAUTION", "AVOID"],
                      },
                      verdict_score: {
                        type: "integer",
                        minimum: 0,
                        maximum: 100,
                        description: "Agent score 100=clean … 0=deadly",
                      },
                      risk_flags: {
                        type: "array",
                        items: { type: "string" },
                      },
                      reasons: {
                        type: "array",
                        items: { type: "string" },
                      },
                      bytecodeLength: { type: "integer" },
                      cachedAt: { type: "string", format: "date-time" },
                      dossier: {
                        type: "object",
                        description:
                          "Buyer dossier: GoPlus + honeypot.is simulation + optional listing context",
                        properties: {
                          goplus: {
                            type: ["object", "null"],
                            additionalProperties: true,
                          },
                          honeypotIs: {
                            type: ["object", "null"],
                            additionalProperties: true,
                          },
                          listing: {
                            type: ["object", "null"],
                            properties: {
                              source: { type: "string" },
                              pair: { type: "string" },
                              pairedWith: { type: "string" },
                              txHash: { type: "string" },
                              blockNumber: { type: "integer" },
                            },
                          },
                          ageHintSeconds: { type: ["integer", "null"] },
                          dualSourceConsensus: { type: "boolean" },
                        },
                      },
                    },
                  },
                },
              },
            },
            "402": {
              description: "PAYMENT_REQUIRED — pay USDC then retry with X-Payment-Proof",
              headers: {
                "X-Payment-Address": {
                  schema: { type: "string" },
                  description: env.PAYMENT_ADDRESS,
                },
                "X-Payment-Amount": {
                  schema: { type: "string" },
                  description: PAYMENT_PRODUCTS.scan.amountDisplay,
                },
                "X-Payment-Network": {
                  schema: { type: "string" },
                  description: network,
                },
              },
              content: {
                "application/json": {
                  schema: {
                    allOf: [
                      { $ref: "#/components/schemas/ApiError" },
                      {
                        type: "object",
                        properties: {
                          payment_info: { type: "object" },
                          x402: { type: "object" },
                        },
                      },
                    ],
                  },
                },
              },
            },
            "400": {
              description:
                "INVALID_ADDRESS_FORMAT or INVALID_PROOF_FORMAT",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiError" },
                },
              },
            },
            "409": {
              description: "TX_HASH_CONSUMED or TX_HASH_BOUND_OTHER",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiError" },
                },
              },
            },
            "422": {
              description: "INSUFFICIENT_USDC or PAYMENT_INVALID",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiError" },
                },
              },
            },
            "502": {
              description: "UPSTREAM_TIMEOUT",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/ApiError" },
                },
              },
            },
          },
        },
      },
      "/tools.json": {
        get: {
          operationId: "listAgentTools",
          summary: "OpenAI-compatible tool schemas for LLM agents",
          responses: {
            "200": {
              description: "Tool definitions + payment notes",
            },
          },
        },
      },
      "/dossier/{address}": {
        get: {
          operationId: "getPremiumDossier",
          summary: "Premium security + market-structure dossier",
          description:
            `Security scan plus deployer/top-holder concentration and LP lock heuristics. Requires ${PAYMENT_PRODUCTS.dossier.amountDisplay} via X-Payment-Proof.`,
          parameters: [
            {
              name: "address",
              in: "path",
              required: true,
              schema: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{40}$",
              },
              description: "EVM contract address",
            },
            {
              name: "X-Payment-Proof",
              in: "header",
              required: true,
              schema: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
              description: `USDC tx hash for ${PAYMENT_PRODUCTS.dossier.amountDisplay}, bound to this address`,
            },
          ],
          responses: {
            "200": {
              description: "Premium dossier",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string" },
                      network: { type: "string" },
                      verdict: {
                        type: "string",
                        enum: ["CLEAR", "CAUTION", "AVOID"],
                      },
                      verdict_score: { type: "integer" },
                      risk_flags: {
                        type: "array",
                        items: { type: "string" },
                      },
                      market_structure: {
                        type: "object",
                        properties: {
                          deployer_balance_pct: {
                            type: ["number", "null"],
                          },
                          top_5_holders_pct: { type: ["number", "null"] },
                          lp_status: {
                            type: "string",
                            enum: ["LOCKED", "BURNED", "UNLOCKED", "UNKNOWN"],
                          },
                          is_whale_concentrated: { type: "boolean" },
                          notes: {
                            type: "array",
                            items: { type: "string" },
                          },
                        },
                      },
                      security: {
                        type: "object",
                        description: "Full /scan payload",
                        additionalProperties: true,
                      },
                    },
                  },
                },
              },
            },
            "402": { description: "Payment required" },
            "400": { description: "Invalid address or payment proof" },
          },
        },
      },
      "/watch": {
        post: {
          operationId: "createWatchSubscription",
          summary: "7-day watchdog webhook subscription",
          description:
            `Pay ${PAYMENT_PRODUCTS.watch.amountDisplay} to watch a Base address. Cron re-scans (batched) and POSTs STATUS_CHANGED to webhook_url when verdict, tax, or risk_flags change. Auto-expires after 7 days.`,
          parameters: [
            {
              name: "X-Payment-Proof",
              in: "header",
              required: true,
              schema: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
              description: `USDC tx hash for ${PAYMENT_PRODUCTS.watch.amountDisplay}, bound to target_address + webhook_url`,
            },
          ],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["target_address", "webhook_url"],
                  properties: {
                    target_address: {
                      type: "string",
                      pattern: "^0x[a-fA-F0-9]{40}$",
                    },
                    webhook_url: {
                      type: "string",
                      format: "uri",
                      description: "HTTPS webhook URL (no private/loopback hosts)",
                    },
                  },
                },
              },
            },
          },
          responses: {
            "200": {
              description: "Watch created",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      ok: { type: "boolean" },
                      watch_id: { type: "string" },
                      target_address: { type: "string" },
                      webhook_url: { type: "string" },
                      ttl_seconds: { type: "integer", example: 604800 },
                      expires_at: { type: "string", format: "date-time" },
                      baseline: {
                        type: "object",
                        properties: {
                          verdict: {
                            type: ["string", "null"],
                            enum: ["CLEAR", "CAUTION", "AVOID", null],
                          },
                          tax: { type: ["number", "null"] },
                          risk_flags: {
                            type: "array",
                            items: { type: "string" },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
            "402": { description: "Payment required" },
            "400": { description: "Invalid body, address, webhook, or payment" },
          },
        },
      },
      "/.well-known/ai-plugin.json": {
        get: {
          operationId: "getAiPluginManifest",
          summary: "Agent discovery manifest",
          responses: {
            "200": { description: "AI plugin / agent discovery JSON" },
          },
        },
      },
      "/.well-known/x402.json": {
        get: {
          operationId: "getX402Discovery",
          summary: "x402 / Bazaar discovery catalog",
          responses: {
            "200": { description: "x402 discovery JSON for agents" },
          },
        },
      },
    },
    components: {
      schemas: {
        ApiError: API_ERROR_SCHEMA,
      },
    },
  };
}

/**
 * OpenAI / LangChain-style tool schemas for agent integrators (copy-paste).
 */
export function buildToolsDocument(origin: string, env: Env) {
  const network = resolveNetwork(env);
  const usdc = getUsdcContractAddress(network);

  return {
    schema_version: "1.0",
    name: "BaseSentinel",
    description:
      "Pay-per-call Base threat intel. Transfer USDC on Base, then call with X-Payment-Proof: <tx_hash>.",
    api_base: origin,
    payment: {
      network,
      caip2: network === "base" ? "eip155:8453" : "eip155:84532",
      asset: "USDC",
      usdc_contract: usdc,
      pay_to: env.PAYMENT_ADDRESS,
      proof_header: "X-Payment-Proof",
      settlement: "tx_hash_proof",
      error_contract:
        "Errors return { error_code, message, error }. Branch on error_code.",
      error_codes: Object.values(ErrorCode),
    },
    docs: `${origin}/docs`,
    openapi: `${origin}/openapi.json`,
    tools: [
      {
        type: "function",
        function: {
          name: "basesentinel_scan",
          description: `Scan a Base contract for honeypot/scam risk. Cost ${PAYMENT_PRODUCTS.scan.amountDisplay}. Returns verdict CLEAR|CAUTION|AVOID and verdict_score 0-100 (100=clean).`,
          parameters: {
            type: "object",
            additionalProperties: false,
            required: ["address", "payment_proof"],
            properties: {
              address: {
                type: "string",
                description: "EVM contract address 0x + 40 hex",
                pattern: "^0x[a-fA-F0-9]{40}$",
              },
              payment_proof: {
                type: "string",
                description:
                  "Base USDC transfer tx hash to treasury (X-Payment-Proof)",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
            },
          },
          x_basesentinel: {
            method: "GET",
            url_template: `${origin}/scan/{address}`,
            price: PAYMENT_PRODUCTS.scan.amountDisplay,
            amount_atomic: PAYMENT_PRODUCTS.scan.amountAtomic,
            response: {
              verdict: { type: "string", enum: ["CLEAR", "CAUTION", "AVOID"] },
              verdict_score: {
                type: "integer",
                minimum: 0,
                maximum: 100,
                description: "100=clean, 0=high risk",
              },
              status: {
                type: "string",
                enum: ["SAFE", "SUSPICIOUS", "SCAM"],
              },
              risk_flags: { type: "array", items: { type: "string" } },
            },
          },
        },
      },
      {
        type: "function",
        function: {
          name: "basesentinel_dossier",
          description: `Premium dossier: scan + holder/LP structure. Cost ${PAYMENT_PRODUCTS.dossier.amountDisplay}.`,
          parameters: {
            type: "object",
            additionalProperties: false,
            required: ["address", "payment_proof"],
            properties: {
              address: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{40}$",
              },
              payment_proof: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
            },
          },
          x_basesentinel: {
            method: "GET",
            url_template: `${origin}/dossier/{address}`,
            price: PAYMENT_PRODUCTS.dossier.amountDisplay,
            amount_atomic: PAYMENT_PRODUCTS.dossier.amountAtomic,
          },
        },
      },
      {
        type: "function",
        function: {
          name: "basesentinel_watch",
          description: `7-day watch: webhook on verdict/tax/flag changes. Cost ${PAYMENT_PRODUCTS.watch.amountDisplay}.`,
          parameters: {
            type: "object",
            additionalProperties: false,
            required: ["target_address", "webhook_url", "payment_proof"],
            properties: {
              target_address: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{40}$",
              },
              webhook_url: {
                type: "string",
                description: "HTTPS webhook for STATUS_CHANGED events",
              },
              payment_proof: {
                type: "string",
                pattern: "^0x[a-fA-F0-9]{64}$",
              },
            },
          },
          x_basesentinel: {
            method: "POST",
            url: `${origin}/watch`,
            price: PAYMENT_PRODUCTS.watch.amountDisplay,
            amount_atomic: PAYMENT_PRODUCTS.watch.amountAtomic,
            ttl_seconds: 604800,
          },
        },
      },
    ],
  };
}

/**
 * Machine-readable x402 discovery catalog for agent directories / Bazaar crawlers.
 */
export function buildX402WellKnown(origin: string, env: Env) {
  const network = resolveNetwork(env);
  const usdc = getUsdcContractAddress(network);
  const caip2 = network === "base" ? "eip155:8453" : "eip155:84532";
  const now = new Date().toISOString();

  return {
    x402Version: 2,
    name: "BaseSentinel",
    description: PUBLIC_INTEL_SUMMARY,
    network: caip2,
    payTo: env.PAYMENT_ADDRESS,
    asset: usdc,
    /** Settlement: USDC transfer on Base + X-Payment-Proof tx hash. */
    settlement: "tx_hash_proof",
    proofHeader: "X-Payment-Proof",
    generated_at: now,
    updated_at: now,
    openapi: `${origin}/openapi.json`,
    tools: `${origin}/tools.json`,
    ai_plugin: `${origin}/.well-known/ai-plugin.json`,
    owner_url: "https://blackswanlabs.pl",
    owner_contact: "blackswanlabsos@gmail.com",
    category: "trust",
    tags: [
      "x402",
      "base",
      "security",
      "threat-intel",
      "risk-scoring",
      "honeypot",
      "scam-detection",
    ],
    capabilities: PUBLIC_INTEL_CAPABILITIES,
    extensions: {
      bazaar: {
        discoverable: true,
        name: "BaseSentinel",
        description: PUBLIC_INTEL_SHORT,
        category: "trust",
        tags: [
          "x402",
          "base",
          "security",
          "threat-intel",
          "risk-scoring",
          "honeypot",
          "scam-detection",
        ],
        owner_url: "https://blackswanlabs.pl",
        owner_contact: "blackswanlabsos@gmail.com",
        settlement: "tx_hash_proof",
        proofHeader: "X-Payment-Proof",
      },
      baseSentinel: {
        settlement: "tx_hash_proof",
        proofHeader: "X-Payment-Proof",
        binding: "one_tx_hash_per_product_resource",
        humanNetwork: network,
      },
    },
    services: [
      {
        name: "scan",
        method: "GET",
        path: "/scan/:address",
        url: `${origin}/scan/{address}`,
        description: PAYMENT_PRODUCTS.scan.description,
        amount: PAYMENT_PRODUCTS.scan.amountAtomic,
        amountDisplay: PAYMENT_PRODUCTS.scan.amountDisplay,
        scheme: "exact",
        proofHeader: "X-Payment-Proof",
        settlement: "tx_hash_proof",
      },
      {
        name: "dossier",
        method: "GET",
        path: "/dossier/:address",
        url: `${origin}/dossier/{address}`,
        description: PAYMENT_PRODUCTS.dossier.description,
        amount: PAYMENT_PRODUCTS.dossier.amountAtomic,
        amountDisplay: PAYMENT_PRODUCTS.dossier.amountDisplay,
        scheme: "exact",
        proofHeader: "X-Payment-Proof",
        settlement: "tx_hash_proof",
      },
      {
        name: "watch",
        method: "POST",
        path: "/watch",
        url: `${origin}/watch`,
        description: PAYMENT_PRODUCTS.watch.description,
        amount: PAYMENT_PRODUCTS.watch.amountAtomic,
        amountDisplay: PAYMENT_PRODUCTS.watch.amountDisplay,
        scheme: "exact",
        proofHeader: "X-Payment-Proof",
        settlement: "tx_hash_proof",
        ttlSeconds: 604800,
      },
      {
        name: "daily_feed",
        method: "GET",
        path: "/api/feed/daily/:date",
        url: `${origin}/api/feed/daily/YYYY-MM-DD`,
        description: PAYMENT_PRODUCTS.daily_feed.description,
        amount: PAYMENT_PRODUCTS.daily_feed.amountAtomic,
        amountDisplay: PAYMENT_PRODUCTS.daily_feed.amountDisplay,
        scheme: "exact",
        proofHeader: "X-Payment-Proof",
        settlement: "tx_hash_proof",
      },
      {
        name: "live_stream",
        method: "GET",
        path: "/stream/threats",
        url: `${origin}/stream/threats`,
        description: PAYMENT_PRODUCTS.live_stream.description,
        amount: PAYMENT_PRODUCTS.live_stream.amountAtomic,
        amountDisplay: PAYMENT_PRODUCTS.live_stream.amountDisplay,
        scheme: "exact",
        proofHeader: "X-Payment-Proof",
        settlement: "tx_hash_proof",
        output: "text/event-stream",
      },
    ],
  };
}
