/**
 * Paid resubmit to x402-list ($0.50 USDC on Base via x402 PAYMENT-SIGNATURE).
 *
 * Easiest (PowerShell-friendly):
 *   1) Create file `.x402-list.local` in repo root (gitignored) with:
 *        X402_LIST_PRIVATE_KEY=0x...
 *        X402_LIST_EMAIL=you@example.com
 *   2) npm run x402-list:resubmit
 *   3) Delete `.x402-list.local` after success
 *
 * NEVER commit the key. NEVER paste it into chat.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const SUBMIT_URL = "https://x402-list.com/api/v1/submit";
const LOCAL_FILE = resolve(process.cwd(), ".x402-list.local");

function loadLocalFile() {
  if (!existsSync(LOCAL_FILE)) return {};
  const out = {};
  for (const line of readFileSync(LOCAL_FILE, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function normalizePrivateKey(raw) {
  if (!raw) return null;
  let key = raw.trim().replace(/^["']|["']$/g, "");
  if (/^[0-9a-fA-F]{64}$/.test(key)) key = `0x${key}`;
  return key;
}

const local = loadLocalFile();
const privateKey = normalizePrivateKey(
  process.env.X402_LIST_PRIVATE_KEY || local.X402_LIST_PRIVATE_KEY,
);
const email = (process.env.X402_LIST_EMAIL || local.X402_LIST_EMAIL || "").trim();

if (!privateKey || !/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
  console.error("Missing/invalid private key.");
  console.error(
    `  source file exists: ${existsSync(LOCAL_FILE)} (${LOCAL_FILE})`,
  );
  console.error(`  env set: ${Boolean(process.env.X402_LIST_PRIVATE_KEY)}`);
  console.error(`  length after normalize: ${privateKey?.length ?? 0} (want 66)`);
  console.error(`  starts with 0x: ${privateKey?.startsWith("0x") ?? false}`);
  console.error(
    "Create .x402-list.local in the repo root with X402_LIST_PRIVATE_KEY=0x... and X402_LIST_EMAIL=...",
  );
  process.exit(1);
}
if (!email || !email.includes("@")) {
  console.error("Missing/invalid X402_LIST_EMAIL (env or .x402-list.local)");
  process.exit(1);
}

const account = privateKeyToAccount(privateKey);
const fetchPaid = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [
    {
      network: "eip155:8453",
      client: new ExactEvmScheme(account),
    },
  ],
});

const body = {
  url: "https://api.blackswanlabs.pl",
  email,
  service_name: "BaseSentinel",
  description:
    "Base threat-intel API for AI agents (M2M). HTTP 402 + USDC on Base. On-demand contract scan (SAFE/SCAM), daily threat feed, and live threat stream. Settlement via X-Payment-Proof (USDC tx hash).",
  website_url: "https://blackswanlabs.pl",
  category: "Blockchain",
  endpoints: [
    "/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "/api/feed/daily/2026-07-30",
    "/stream/threats",
  ],
  notes:
    "Fixed since last review: Bot Fight Mode off (no CF challenge on probes). Daily feed validates real UTC calendar dates before charging — invalid/future dates return 400, not 402. Scan at 0.005 USDC is intentional (live 402).",
};

console.log("Payer:", account.address);
console.log("Email:", email);
console.log("POST", SUBMIT_URL);
console.log("(If rejected recently, client will auto-pay ~0.50 USDC on Base and retry.)\n");

const res = await fetchPaid(SUBMIT_URL, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const text = await res.text();
let json;
try {
  json = JSON.parse(text);
} catch {
  json = text;
}

console.log("HTTP", res.status);
console.log(JSON.stringify(json, null, 2));

if (res.headers.get("PAYMENT-RESPONSE")) {
  console.log("\nPAYMENT-RESPONSE header present (settlement receipt).");
}

if (res.status !== 201) {
  process.exit(1);
}

console.log("\nOK — submission pending review. Check email for outcome.");
console.log("Delete .x402-list.local now (contains your private key).");
