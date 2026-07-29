/**
 * Ontario Protocol — PAID service listing (0.50 USDC on Base).
 *
 * Flow:
 *  1) POST /api/x402/list-service  → HTTP 402 + PAYMENT-REQUIRED
 *  2) Sign EIP-3009 TransferWithAuthorization (USDC domain name = "USD Coin", version "2")
 *  3) Retry with PAYMENT-SIGNATURE (base64 JSON)
 *
 * Usage:
 *   cd scripts/ontario-paid-listing
 *   npm install
 *   copy .env.example → .env  (fill X402_PRIVATE_KEY)
 *   node list.mjs            # production (spends 0.50 USDC)
 *   node list.mjs --sandbox  # rehearsal, no spend
 *
 * Free pending is already submitted separately (lst_ef8ac7ad7e86).
 * This script upgrades / submits the paid discoverable path.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { privateKeyToAccount } from "viem/accounts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ONTARIO = "https://ontarioprotocol.com";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/** Listing payload for BaseSentinel scan product. */
const LISTING = {
  name: "BaseSentinel",
  description:
    "Pay-per-call Base threat intel: bytecode + GoPlus + honeypot.is, CLEAR/CAUTION/AVOID. HTTP 402 USDC on Base.",
  category: "trust",
  endpoint:
    "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  method: "GET",
  price_usdc: "0.005",
  network: "base",
  asset: USDC_BASE,
  owner_url: "https://blackswanlabs.pl",
  owner_contact: "blackswanlabsos@gmail.com",
  tags: [
    "x402",
    "base",
    "security",
    "threat-intel",
    "sniper-alpha",
    "honeypot",
    "scam-detection",
  ],
};

function loadEnv() {
  const envPath = resolve(__dirname, ".env");
  if (!existsSync(envPath)) return;
  const text = readFileSync(envPath, "utf8");
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = val;
  }
}

function b64Json(obj) {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64");
}

function decodePaymentRequired(headerValue) {
  if (!headerValue) return null;
  return JSON.parse(Buffer.from(headerValue, "base64").toString("utf8"));
}

/** Normalize Ontario challenge (flat v1-style or nested accepts[]). */
function pickRequirements(decoded, bodyJson) {
  if (decoded?.payTo && decoded?.maxAmountRequired) return decoded;
  if (decoded?.accepts?.[0]) return decoded.accepts[0];
  if (bodyJson?.accepts?.[0]) return bodyJson.accepts[0];
  throw new Error("Could not find payment requirements in 402 response");
}

function toBytes32Nonce(raw) {
  let hex = String(raw || "").replace(/^0x/i, "");
  if (!hex) {
    // Fallback random 32 bytes if challenge omitted nonce.
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  if (hex.length > 64) {
    throw new Error(`nonce too long (${hex.length} hex chars)`);
  }
  return `0x${hex.padStart(64, "0")}`;
}

async function postListing(url, payload, headers = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      "user-agent": "BaseSentinel-OntarioPaidListing/1.0",
      ...headers,
    },
    body: JSON.stringify(payload),
  });
  const contentType = res.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await res.json()
    : await res.text();
  return { status: res.status, headers: res.headers, body };
}

async function signEip3009({ account, requirements }) {
  const to = requirements.payTo;
  const value = BigInt(requirements.maxAmountRequired);
  const extra = requirements.extra || {};
  const validBefore = BigInt(
    extra.validUntil ?? extra.quote_expires_at ?? Math.floor(Date.now() / 1000) + 60,
  );
  const validAfter = 0n;
  const nonce = toBytes32Nonce(extra.nonce);

  // USDC on Base mainnet EIP-712 domain (Ontario docs: name MUST be "USD Coin").
  const domain = {
    name: extra.name || "USD Coin",
    version: String(extra.version || "2"),
    chainId: 8453,
    verifyingContract: USDC_BASE,
  };

  const types = {
    TransferWithAuthorization: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "value", type: "uint256" },
      { name: "validAfter", type: "uint256" },
      { name: "validBefore", type: "uint256" },
      { name: "nonce", type: "bytes32" },
    ],
  };

  const message = {
    from: account.address,
    to,
    value,
    validAfter,
    validBefore,
    nonce,
  };

  const signature = await account.signTypedData({
    domain,
    types,
    primaryType: "TransferWithAuthorization",
    message,
  });

  return {
    signature,
    authorization: {
      from: account.address,
      to,
      value: value.toString(),
      validAfter: validAfter.toString(),
      validBefore: validBefore.toString(),
      nonce,
    },
  };
}

async function main() {
  loadEnv();
  const sandbox = process.argv.includes("--sandbox");
  const endpoint = sandbox
    ? `${ONTARIO}/sandbox/api/x402/list-service`
    : `${ONTARIO}/api/x402/list-service`;

  console.log(sandbox ? "Mode: SANDBOX (no spend)" : "Mode: PRODUCTION (0.50 USDC)");
  console.log("Target:", endpoint);

  // 1) Validate (free)
  const validated = await postListing(
    `${ONTARIO}/api/x402/list-service/validate`,
    LISTING,
  );
  if (validated.status !== 200 || !validated.body?.ok) {
    throw new Error(
      `validate failed HTTP ${validated.status}: ${JSON.stringify(validated.body)}`,
    );
  }
  const payload = validated.body.normalized || LISTING;
  console.log("Validated OK");

  // 2) Challenge
  const first = await postListing(endpoint, payload);
  if (first.status !== 402) {
    throw new Error(
      `expected HTTP 402, got ${first.status}: ${JSON.stringify(first.body)}`,
    );
  }

  const requiredHeader =
    first.headers.get("payment-required") ||
    first.headers.get("x-payment-required");
  const decoded = decodePaymentRequired(requiredHeader);
  const requirements = pickRequirements(decoded, first.body);

  console.log("Challenge:", {
    payTo: requirements.payTo,
    amountAtomic: requirements.maxAmountRequired,
    network: requirements.network,
    asset: requirements.asset,
    quote_id: requirements.extra?.quote_id,
  });

  if (sandbox) {
    // Official Ontario sandbox accepts a simulated signature (their TS example).
    const fake = {
      x402Version: 1,
      scheme: requirements.scheme || "exact",
      network: requirements.network || "base-sandbox",
      payload: {
        signature: "sandbox-valid",
        authorization: {
          from: "0xSandboxAgent",
          to: requirements.payTo,
          value: requirements.maxAmountRequired,
          nonce: "ontario-list-service-sandbox",
        },
      },
    };
    const second = await postListing(endpoint, payload, {
      "payment-signature": b64Json(fake),
    });
    console.log("Sandbox result HTTP", second.status);
    console.log(JSON.stringify(second.body, null, 2));
    return;
  }

  // 3) Real EIP-3009 signature
  const pk = process.env.X402_PRIVATE_KEY?.trim();
  if (!pk || !pk.startsWith("0x") || pk.includes("YOUR_PRIVATE")) {
    throw new Error(
      "Set X402_PRIVATE_KEY in scripts/ontario-paid-listing/.env (0x… dedicated wallet)",
    );
  }
  const account = privateKeyToAccount(/** @type {`0x${string}`} */ (pk));
  console.log("Signer:", account.address);

  const { signature, authorization } = await signEip3009({
    account,
    requirements,
  });

  const paymentPayload = {
    x402Version: 1,
    scheme: requirements.scheme || "exact",
    network: requirements.network || "base",
    payload: {
      signature,
      authorization,
    },
  };

  const second = await postListing(endpoint, payload, {
    "payment-signature": b64Json(paymentPayload),
    // Some stacks also accept PAYMENT-SIGNATURE casing via fetch normalization.
  });

  console.log("Paid listing HTTP", second.status);
  console.log(JSON.stringify(second.body, null, 2));

  if (second.status !== 200) {
    process.exitCode = 1;
    console.error(
      "\nIf settle failed: check USDC balance on signer, domain name 'USD Coin'/version '2', and quote expiry (retry quickly).",
    );
  } else {
    console.log("\nSuccess — check https://ontarioprotocol.com/listings and /discover");
  }
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exitCode = 1;
});
