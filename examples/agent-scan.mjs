/**
 * Minimal M2M agent client for BaseSentinel /scan.
 *
 * - No secrets in this file.
 * - You pay USDC on Base yourself, then pass the tx hash.
 *
 * Usage:
 *   BASE_URL=https://api.blackswanlabs.pl \
 *   TARGET_ADDRESS=0x... \
 *   PAYMENT_PROOF=0x... \
 *   node examples/agent-scan.mjs
 *
 * Omit PAYMENT_PROOF to only probe HTTP 402 + payment_info.
 */

const BASE_URL = (process.env.BASE_URL || "https://api.blackswanlabs.pl").replace(
  /\/$/,
  "",
);
const TARGET_ADDRESS = (
  process.env.TARGET_ADDRESS || "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
).trim();
const PAYMENT_PROOF = process.env.PAYMENT_PROOF?.trim() || "";

function log(title, value) {
  console.log(`\n=== ${title} ===`);
  if (typeof value === "string") {
    console.log(value);
  } else {
    console.log(JSON.stringify(value, null, 2));
  }
}

async function fetchTools() {
  const res = await fetch(`${BASE_URL}/tools.json`);
  const body = await res.json();
  log("tools.json", {
    status: res.status,
    tool_names: (body.tools || []).map((t) => t.function?.name),
    error_codes: body.payment?.error_codes,
  });
  return body;
}

async function scan(address, paymentProof) {
  const headers = {};
  if (paymentProof) {
    headers["X-Payment-Proof"] = paymentProof;
  }

  const res = await fetch(`${BASE_URL}/scan/${address}`, { headers });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }

  log(`scan HTTP ${res.status}`, body);

  if (res.status === 402 || body.error_code === "PAYMENT_REQUIRED") {
    console.log(
      "\nNext: transfer payment_info.amount_display USDC on Base to payment_info.recipient,",
    );
    console.log("then re-run with PAYMENT_PROOF=<tx_hash>.");
    return { ok: false, stage: "payment_required", body };
  }

  if (!res.ok) {
    const code = body.error_code || "UNKNOWN";
    if (code === "TX_HASH_CONSUMED" || code === "TX_HASH_BOUND_OTHER") {
      console.log(`\nBreak: ${code} — do not retry with the same proof.`);
    } else if (code === "INSUFFICIENT_USDC" || code === "PAYMENT_INVALID") {
      console.log(`\nFix payment and retry with a new proof (${code}).`);
    } else if (code === "UPSTREAM_TIMEOUT") {
      console.log("\nRetry after short backoff (UPSTREAM_TIMEOUT).");
    } else {
      console.log(`\nAgent branch on error_code=${code}`);
    }
    return { ok: false, stage: "error", body };
  }

  const verdict = body.verdict;
  const score = body.verdict_score;
  console.log(`\nVerdict: ${verdict} (score=${score})`);
  if (verdict === "AVOID") {
    console.log("Policy example: do not buy.");
  } else if (verdict === "CAUTION") {
    console.log("Policy example: reduce size / require more checks.");
  } else if (verdict === "CLEAR") {
    console.log("Policy example: proceed within your own risk limits.");
  }

  return { ok: true, stage: "scanned", body };
}

async function main() {
  log("config", {
    BASE_URL,
    TARGET_ADDRESS,
    has_payment_proof: Boolean(PAYMENT_PROOF),
  });

  await fetchTools();
  await scan(TARGET_ADDRESS, PAYMENT_PROOF);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
