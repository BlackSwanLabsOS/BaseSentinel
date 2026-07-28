import type { Env } from "../types";
import {
  getUsdcContractAddress,
  resolveNetwork,
} from "../config/network";
import { PAYMENT_AMOUNT, PAYMENT_PRODUCTS } from "../middleware/payment";

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, X-Payment-Proof, X-Payment-Signature, PAYMENT-SIGNATURE",
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
      "Fast smart-contract security scanner for Base with pay-per-call USDC access.",
    description_for_model:
      "Ultraszybki skaner bezpieczeństwa smart kontraktów i wykrywacz honeypotów na sieci Base. Przyjmuje adres kontraktu, sprawdza jego bytecode i zwraca status SAFE lub SCAM. Wymaga płatności 0.001 USDC przez HTTP 402.",
    auth: {
      type: "none",
    },
    api: {
      type: "openapi",
      url: `${origin}/openapi.json`,
      has_user_authentication: false,
    },
    // Custom extension for M2M / agent payment discovery (not part of classic AI Plugin auth enum).
    x_m2m_payment: {
      type: "http_402_pay_per_call",
      products: {
        scan: {
          price: PAYMENT_PRODUCTS.scan.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.scan.amountAtomic,
          url_template: `${origin}/scan/{address}`,
        },
        daily_feed: {
          price: PAYMENT_PRODUCTS.daily_feed.amountDisplay,
          amount_atomic: PAYMENT_PRODUCTS.daily_feed.amountAtomic,
          url_template: `${origin}/api/feed/daily?date=YYYY-MM-DD`,
        },
      },
      price: PAYMENT_AMOUNT,
      amount_atomic: "1000",
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
        "Smart-contract bytecode scanner on Base. Pay-per-call via HTTP 402 + USDC tx proof bound to target contract.",
    },
    servers: [{ url: origin }],
    paths: {
      "/scan/{address}": {
        get: {
          operationId: "scanContract",
          summary: "Scan a smart contract address",
          description:
            "Returns a cached or freshly computed scan result. Requires X-Payment-Proof (USDC tx hash bound to this address). Without payment proof returns HTTP 402.",
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
                "Transaction hash proving transfer of 0.001 USDC to the payment address. Bound to this contract — cannot be reused for another address.",
            },
          ],
          responses: {
            "200": {
              description: "Scan result",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      address: { type: "string" },
                      network: { type: "string", example: network },
                      status: { type: "string", enum: ["SAFE", "SCAM"] },
                      riskScore: {
                        type: "integer",
                        minimum: 0,
                        maximum: 100,
                      },
                      reasons: {
                        type: "array",
                        items: { type: "string" },
                      },
                      bytecodeLength: { type: "integer" },
                      cachedAt: { type: "string", format: "date-time" },
                    },
                  },
                },
              },
            },
            "402": {
              description: "Payment required before scanning",
              headers: {
                "X-Payment-Address": {
                  schema: { type: "string" },
                  description: env.PAYMENT_ADDRESS,
                },
                "X-Payment-Amount": {
                  schema: { type: "string" },
                  description: PAYMENT_AMOUNT,
                },
                "X-Payment-Network": {
                  schema: { type: "string" },
                  description: network,
                },
              },
            },
            "400": {
              description:
                "Invalid address / invalid, reused, or rebound payment proof",
            },
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
    },
  };
}
