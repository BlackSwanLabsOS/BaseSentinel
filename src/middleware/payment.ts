import type { Env } from "../types";
import {
  getAlchemyRpcBase,
  getCaip2Network,
  getUsdcContractAddress,
  resolveNetwork,
  type NetworkId,
} from "../config/network";
import { getTransactionReceipt } from "../services/alchemy";
import type { TransactionReceipt } from "../services/alchemy";

export const PAYMENT_DECIMALS = 6;
export const PAYMENT_PROOF_TTL_SECONDS = 86_400; // 24 hours
export const PAYMENT_MAX_TIMEOUT_SECONDS = 300;

/** Legacy export — prefer getUsdcContractAddress(resolveNetwork(env)). */
export const USDC_CONTRACT_ADDRESS = getUsdcContractAddress("base-sepolia");
/** Legacy export — prefer resolveNetwork(env). */
export const PAYMENT_NETWORK: NetworkId = "base-sepolia";

export type PaymentProductId =
  | "scan"
  | "daily_feed"
  | "live_stream"
  | "dossier"
  | "watch";

export interface PaymentProduct {
  id: PaymentProductId;
  /** Minimum accepted USDC transfer in atomic units (6 decimals). */
  minAmount: bigint;
  amountAtomic: string;
  amountDisplay: string;
  description: string;
  /** Human label for binding mismatches. */
  bindingLabel: string;
}

export const PAYMENT_PRODUCTS: Record<PaymentProductId, PaymentProduct> = {
  scan: {
    id: "scan",
    minAmount: 5_000n, // 0.005 USDC
    amountAtomic: "5000",
    amountDisplay: "0.005 USDC",
    description:
      "On-demand Base contract scan (bytecode + GoPlus + honeypot.is) with CLEAR/CAUTION/AVOID verdict",
    bindingLabel: "contract",
  },
  daily_feed: {
    id: "daily_feed",
    minAmount: 10_000n, // 0.01 USDC
    amountAtomic: "10000",
    amountDisplay: "0.01 USDC",
    description:
      "Daily Base threat pack (SCAM + SUSPICIOUS) from watched DEX/launcher coverage",
    bindingLabel: "feed date",
  },
  live_stream: {
    id: "live_stream",
    minAmount: 5_000n, // 0.005 USDC per UTC day of streaming
    amountAtomic: "5000",
    amountDisplay: "0.005 USDC",
    description:
      "Live SSE stream of newly flagged Base threats (SCAM/SUSPICIOUS)",
    bindingLabel: "stream day",
  },
  dossier: {
    id: "dossier",
    minAmount: 250_000n, // 0.25 USDC
    amountAtomic: "250000",
    amountDisplay: "0.25 USDC",
    description:
      "Premium Base dossier: security verdict + market structure (deployer %, top holders, LP status)",
    bindingLabel: "contract",
  },
  watch: {
    id: "watch",
    minAmount: 500_000n, // 0.50 USDC
    amountAtomic: "500000",
    amountDisplay: "0.50 USDC",
    description:
      "7-day watchdog: re-scan a Base address on cron and POST webhook on verdict/tax/flag changes",
    bindingLabel: "watch subscription",
  },
};

/** Legacy alias of PAYMENT_PRODUCTS.scan.amountDisplay. */
export const PAYMENT_AMOUNT = PAYMENT_PRODUCTS.scan.amountDisplay;
/** Legacy alias of PAYMENT_PRODUCTS.scan.amountAtomic. */
export const PAYMENT_AMOUNT_ATOMIC = PAYMENT_PRODUCTS.scan.amountAtomic;
/** Legacy alias of PAYMENT_PRODUCTS.scan.minAmount. */
export const REQUIRED_USDC_AMOUNT = PAYMENT_PRODUCTS.scan.minAmount;

/** keccak256("Transfer(address,address,uint256)") */
const ERC20_TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const PAYMENT_PROOF_HEADER = "X-Payment-Proof";
const PAYMENT_SIGNATURE_HEADER = "X-Payment-Signature";
/** Official x402 v2 client payment header (Base64 PaymentPayload). */
const X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";

/** Ethereum tx hash: 0x + 64 hex chars */
const TX_HASH_RE = /^0x[a-fA-F0-9]{64}$/;

interface ConsumedPaymentRecord {
  product: PaymentProductId;
  /** Contract address or feed binding key (e.g. daily-feed:2026-07-28). */
  bindingKey: string;
  /** Older records may store the binding here. */
  contractAddress?: string;
  usedAt: string;
  status: "consumed";
  network: NetworkId;
}

export interface PaymentInfo {
  product: PaymentProductId;
  network: NetworkId;
  caip2_network: string;
  token: string;
  recipient: string;
  amount: string;
  amount_display: string;
  decimals: number;
  asset: string;
  proof_header: string;
  scheme: "exact";
}

export interface EnforcePaymentOptions {
  product: PaymentProductId;
  /** What this payment unlocks (contract address or daily-feed:YYYY-MM-DD). */
  bindingKey: string;
  resourceUrl?: string;
  resourceDescription?: string;
  /** Allow the same proof again for this product+binding (e.g. SSE reconnect). */
  allowReuse?: boolean;
}

export class PaymentRequiredError extends Error {
  readonly status = 402 as const;
  readonly product: PaymentProductId;

  constructor(product: PaymentProductId = "scan", message = "Payment Required") {
    super(message);
    this.name = "PaymentRequiredError";
    this.product = product;
  }
}

export class PaymentReplayError extends Error {
  readonly status = 400 as const;

  constructor(message = "Payment proof already used") {
    super(message);
    this.name = "PaymentReplayError";
  }
}

export class PaymentBindingMismatchError extends Error {
  readonly status = 400 as const;

  constructor(message: string) {
    super(message);
    this.name = "PaymentBindingMismatchError";
  }
}

/** Alias of PaymentBindingMismatchError. */
export class PaymentBoundToOtherContractError extends PaymentBindingMismatchError {
  constructor(
    message = "Payment proof already used for a different contract",
  ) {
    super(message);
    this.name = "PaymentBoundToOtherContractError";
  }
}

export class InvalidPaymentProofError extends Error {
  readonly status = 400 as const;

  constructor(message: string) {
    super(message);
    this.name = "InvalidPaymentProofError";
  }
}

function paymentProofCacheKey(
  product: PaymentProductId,
  paymentProof: string,
): string {
  // Product-scoped keys: a scan proof cannot unlock another product.
  return `tx:${product}:${paymentProof.toLowerCase()}`;
}

function normalizeAddress(address: string): string {
  return address.toLowerCase();
}

/** Decode indexed address from a 32-byte topic. */
function addressFromTopic(topic: string): string {
  return normalizeAddress(`0x${topic.slice(-40)}`);
}

function parseHexBigInt(hex: string): bigint {
  const cleaned = hex === "0x" || hex === "" ? "0x0" : hex;
  return BigInt(cleaned);
}

function toBase64Json(value: unknown): string {
  return btoa(JSON.stringify(value));
}

function buildPaymentInfo(
  env: Env,
  product: PaymentProduct = PAYMENT_PRODUCTS.scan,
): PaymentInfo {
  const network = resolveNetwork(env);
  return {
    product: product.id,
    network,
    caip2_network: getCaip2Network(network),
    token: getUsdcContractAddress(network),
    recipient: env.PAYMENT_ADDRESS,
    amount: product.amountAtomic,
    amount_display: product.amountDisplay,
    decimals: PAYMENT_DECIMALS,
    asset: "USDC",
    proof_header: PAYMENT_PROOF_HEADER,
    scheme: "exact",
  };
}

/**
 * x402 v2 Bazaar discovery extension ({ info, schema }).
 * Spec: https://github.com/coinbase/x402/blob/main/specs/extensions/bazaar.md
 */
function buildBazaarDiscoveryExtension(product: PaymentProduct) {
  const isWatch = product.id === "watch";
  const outputExample = isWatch
    ? {
        ok: true,
        watch_id: "849e3c0d-cd32-4b62-9240-b4db1c7322fc",
        target_address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        ttl_seconds: 604800,
        expires_at: "2026-08-05T17:53:31.546Z",
        baseline: {
          verdict: "CAUTION",
          tax: 0,
          risk_flags: ["UNVERIFIED_SOURCE"],
        },
      }
    : product.id === "dossier"
      ? {
          address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
          network: "base",
          verdict: "CLEAR",
          verdict_score: 88,
          risk_flags: [],
          market_structure: {
            deployer_balance_pct: null,
            top_5_holders_pct: null,
            lp_status: "UNKNOWN",
            is_whale_concentrated: false,
            notes: [],
          },
        }
      : {
          status: "SAFE",
          riskScore: 12,
          verdict: "CLEAR",
          verdict_score: 88,
          risk_flags: [],
          reasons: ["None"],
        };

  if (isWatch) {
    return {
      info: {
        input: {
          type: "http" as const,
          method: "POST" as const,
          bodyType: "json" as const,
          body: {
            target_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            webhook_url: "https://webhook.site/example",
          },
          headers: {
            "Content-Type": "application/json",
            "X-Payment-Proof": "<base_usdc_tx_hash>",
          },
        },
        output: {
          type: "json",
          example: outputExample,
        },
      },
      schema: {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        properties: {
          input: {
            type: "object",
            properties: {
              type: { type: "string", const: "http" },
              method: {
                type: "string",
                enum: ["POST", "PUT", "PATCH"],
              },
              bodyType: {
                type: "string",
                enum: ["json", "form-data", "text"],
              },
              body: { type: "object" },
              queryParams: {
                type: "object",
                additionalProperties: { type: "string" },
              },
              headers: {
                type: "object",
                additionalProperties: { type: "string" },
              },
            },
            required: ["type", "method", "bodyType", "body"],
            additionalProperties: false,
          },
          output: {
            type: "object",
            properties: {
              type: { type: "string" },
              example: { type: "object" },
            },
            required: ["type"],
          },
        },
        required: ["input"],
      },
    };
  }

  return {
    info: {
      input: {
        type: "http" as const,
        method: "GET" as const,
        headers: {
          "X-Payment-Proof": "<base_usdc_tx_hash>",
        },
      },
      output: {
        type: "json",
        example: outputExample,
      },
    },
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      properties: {
        input: {
          type: "object",
          properties: {
            type: { type: "string", const: "http" },
            method: {
              type: "string",
              enum: ["GET", "HEAD", "DELETE"],
            },
            queryParams: {
              type: "object",
              additionalProperties: { type: "string" },
            },
            headers: {
              type: "object",
              additionalProperties: { type: "string" },
            },
          },
          required: ["type", "method"],
          additionalProperties: false,
        },
        output: {
          type: "object",
          properties: {
            type: { type: "string" },
            example: { type: "object" },
          },
          required: ["type"],
        },
      },
      required: ["input"],
    },
  };
}

/**
 * x402 v2 PaymentRequired envelope (decoded form of PAYMENT-REQUIRED header).
 */
function buildX402PaymentRequired(
  env: Env,
  resourceUrl: string,
  product: PaymentProduct,
) {
  const info = buildPaymentInfo(env, product);

  return {
    x402Version: 2,
    error: "PAYMENT-SIGNATURE or X-Payment-Proof header is required",
    resource: {
      url: resourceUrl,
      description: product.description,
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: info.caip2_network,
        amount: info.amount,
        asset: info.token,
        payTo: info.recipient,
        maxTimeoutSeconds: PAYMENT_MAX_TIMEOUT_SECONDS,
        extra: {
          name: "USDC",
          version: "2",
        },
      },
    ],
    extensions: {
      bazaar: buildBazaarDiscoveryExtension(product),
      baseSentinel: {
        product: product.id,
        proofHeader: PAYMENT_PROOF_HEADER,
        binding: `one_tx_hash_per_${product.bindingLabel.replace(/\s+/g, "_")}`,
        humanNetwork: info.network,
        settlement: "tx_hash_proof",
      },
    },
  };
}

/**
 * Extracts payment proof from request headers.
 */
export function extractPaymentProof(request: Request): string | null {
  const direct =
    request.headers.get(PAYMENT_PROOF_HEADER)?.trim() ||
    request.headers.get(PAYMENT_SIGNATURE_HEADER)?.trim() ||
    null;

  if (direct) {
    return direct;
  }

  const x402Sig = request.headers.get(X402_PAYMENT_SIGNATURE_HEADER)?.trim();
  if (x402Sig && TX_HASH_RE.test(x402Sig)) {
    return x402Sig;
  }

  return null;
}

export function build402Response(
  env: Env,
  resourceUrl?: string,
  productId: PaymentProductId = "scan",
): Response {
  const product = PAYMENT_PRODUCTS[productId];
  const info = buildPaymentInfo(env, product);
  const resource =
    resourceUrl ??
    (productId === "daily_feed"
      ? "https://basesentinel.local/api/feed/daily"
      : productId === "live_stream"
        ? "https://basesentinel.local/stream/threats"
        : productId === "watch"
          ? "https://basesentinel.local/watch"
          : productId === "dossier"
            ? "https://basesentinel.local/dossier/{address}"
            : "https://basesentinel.local/scan/{address}");
  const x402 = buildX402PaymentRequired(env, resource, product);

  const body = {
    error: "Payment Required",
    message: `Pay ${product.amountDisplay} on-chain, then retry with X-Payment-Proof set to the transaction hash.`,
    payment_info: info,
    x402,
  };

  return Response.json(body, {
    status: 402,
    headers: {
      "PAYMENT-REQUIRED": toBase64Json(x402),
      "X-Payment-Required": "true",
      "X-Payment-Network": info.network,
      "X-Payment-Token": info.token,
      "X-Payment-Recipient": info.recipient,
      "X-Payment-Address": info.recipient,
      "X-Payment-Amount": info.amount,
      "X-Payment-Asset": info.asset,
      "X-Payment-Amount-Display": info.amount_display,
      "X-Payment-Product": product.id,
    },
  });
}

function assertValidUsdcPayment(
  receipt: TransactionReceipt,
  paymentAddress: string,
  usdcContract: string,
  product: PaymentProduct,
): void {
  if (receipt.status !== "0x1") {
    throw new InvalidPaymentProofError("Transaction failed on-chain");
  }

  const expectedTo = normalizeAddress(paymentAddress);
  const usdc = normalizeAddress(usdcContract);

  const matchingTransfer = (receipt.logs ?? []).find((log) => {
    if (normalizeAddress(log.address) !== usdc) return false;
    if (!log.topics || log.topics.length < 3) return false;
    if (normalizeAddress(log.topics[0]) !== ERC20_TRANSFER_TOPIC) return false;

    const transferTo = addressFromTopic(log.topics[2]);
    if (transferTo !== expectedTo) return false;

    const amount = parseHexBigInt(log.data);
    return amount >= product.minAmount;
  });

  if (!matchingTransfer) {
    throw new InvalidPaymentProofError(
      `No valid USDC transfer of at least ${product.amountDisplay} to ${paymentAddress} found in transaction`,
    );
  }
}

async function verifyPaymentOnChain(
  txHash: string,
  env: Env,
  product: PaymentProduct,
): Promise<void> {
  const network = resolveNetwork(env);
  const usdcContract = getUsdcContractAddress(network);

  let receipt: TransactionReceipt | null;

  try {
    receipt = await getTransactionReceipt(txHash, env);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new InvalidPaymentProofError(
      `Failed to verify transaction on-chain: ${message}`,
    );
  }

  if (!receipt) {
    throw new InvalidPaymentProofError("Transaction not found");
  }

  assertValidUsdcPayment(
    receipt,
    env.PAYMENT_ADDRESS,
    usdcContract,
    product,
  );
}

/**
 * Enforces M2M payment for a product + binding key (contract or feed date).
 */
export async function enforcePayment(
  request: Request,
  env: Env,
  contractAddressOrOptions: string | EnforcePaymentOptions,
): Promise<void> {
  if (!env.PAYMENT_ADDRESS) {
    throw new Error("PAYMENT_ADDRESS is not configured");
  }

  const options: EnforcePaymentOptions =
    typeof contractAddressOrOptions === "string"
      ? {
          product: "scan",
          bindingKey: normalizeAddress(contractAddressOrOptions),
        }
      : {
          ...contractAddressOrOptions,
          bindingKey: contractAddressOrOptions.bindingKey.toLowerCase(),
        };

  const product = PAYMENT_PRODUCTS[options.product];
  const bindingKey = options.bindingKey;
  const network = resolveNetwork(env);
  const paymentProof = extractPaymentProof(request);

  if (!paymentProof) {
    throw new PaymentRequiredError(product.id);
  }

  if (!TX_HASH_RE.test(paymentProof)) {
    throw new InvalidPaymentProofError(
      "Invalid payment proof format. Expected a transaction hash (0x + 64 hex characters).",
    );
  }

  await verifyPaymentOnChain(paymentProof, env, product);

  const key = paymentProofCacheKey(product.id, paymentProof);
  const existing = (await env.SCAN_CACHE.get(key, "json")) as
    | ConsumedPaymentRecord
    | null;

  if (existing) {
    const boundTo = (
      existing.bindingKey ?? existing.contractAddress ?? ""
    ).toLowerCase();

    if (boundTo && boundTo !== bindingKey) {
      throw new PaymentBindingMismatchError(
        `Payment proof already used for a different ${product.bindingLabel}`,
      );
    }

    if (options.allowReuse && boundTo === bindingKey) {
      return;
    }

    throw new PaymentReplayError();
  }

  const record: ConsumedPaymentRecord = {
    product: product.id,
    bindingKey,
    // Include contractAddress for older clients reading scan proofs.
    contractAddress: product.id === "scan" ? bindingKey : undefined,
    usedAt: new Date().toISOString(),
    status: "consumed",
    network,
  };

  await env.SCAN_CACHE.put(key, JSON.stringify(record), {
    expirationTtl: PAYMENT_PROOF_TTL_SECONDS,
  });
}

export function dailyFeedBindingKey(date: string): string {
  return `daily-feed:${date}`;
}

export function liveStreamBindingKey(date = utcDateForBinding()): string {
  return `live-stream:${date}`;
}

/** Stable payment binding for a watch (address + webhook fingerprint). */
export function watchBindingKey(
  targetAddress: string,
  webhookFingerprint: string,
): string {
  return `watch:${targetAddress.toLowerCase()}:${webhookFingerprint}`;
}

function utcDateForBinding(date = new Date()): string {
  return date.toISOString().slice(0, 10);
}

export { getAlchemyRpcBase, getUsdcContractAddress, resolveNetwork };
