/**
 * Simulates an M2M buyer bot against /api/feed/daily.
 *
 * IMPORTANT:
 * - Payment TX must be on the SAME chain as Worker NETWORK (wrangler.toml).
 * - Currently production is NETWORK=base → need Base mainnet USDC (0.01) to PAYMENT_ADDRESS.
 * - For cheap faucet tests, temporarily set NETWORK=base-sepolia and pay on Sepolia.
 *
 * Usage (PowerShell):
 *   $env:BASE_URL="http://127.0.0.1:8787"
 *   $env:FEED_DATE="2026-07-28"
 *   $env:PAYMENT_PROOF="0xYourTxHash..."
 *   npm run test:buyer
 *
 * Optional admin-only (no payment):
 *   $env:ADMIN_API_KEY="twoj-sekret"
 *   npm run test:buyer
 */

const BASE_URL = (process.env.BASE_URL || "http://127.0.0.1:8787").replace(/\/$/, "");
const FEED_DATE = process.env.FEED_DATE || new Date().toISOString().slice(0, 10);
const PAYMENT_PROOF = process.env.PAYMENT_PROOF?.trim() || "";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY?.trim() || "";

const feedUrl = `${BASE_URL}/api/feed/daily?date=${encodeURIComponent(FEED_DATE)}`;

function log(step, message, extra) {
  console.log(`\n=== ${step} ===`);
  console.log(message);
  if (extra !== undefined) {
    console.log(typeof extra === "string" ? extra : JSON.stringify(extra, null, 2));
  }
}

async function request(url, headers = {}) {
  const res = await fetch(url, { method: "GET", headers });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // non-json
  }
  return { res, text, json };
}

function pickPaymentInfo(res, json) {
  return {
    fromHeaders: {
      "X-Payment-Required": res.headers.get("X-Payment-Required"),
      "X-Payment-Network": res.headers.get("X-Payment-Network"),
      "X-Payment-Token": res.headers.get("X-Payment-Token"),
      "X-Payment-Recipient": res.headers.get("X-Payment-Recipient"),
      "X-Payment-Amount": res.headers.get("X-Payment-Amount"),
      "X-Payment-Amount-Display": res.headers.get("X-Payment-Amount-Display"),
      "X-Payment-Product": res.headers.get("X-Payment-Product"),
      "PAYMENT-REQUIRED": res.headers.get("PAYMENT-REQUIRED") ? "<base64 present>" : null,
    },
    fromBody: json?.payment_info ?? json?.x402 ?? json,
  };
}

async function main() {
  console.log("BaseSentinel buyer simulation");
  console.log(`URL:  ${feedUrl}`);
  console.log(`Date: ${FEED_DATE}`);

  // Admin-only mode: free access, no payment steps.
  if (ADMIN_API_KEY && !PAYMENT_PROOF) {
    const admin = await request(feedUrl, { "X-Admin-Key": ADMIN_API_KEY });
    log(
      "Admin bypass (free)",
      `status=${admin.res.status} (expect 200)`,
      {
        feed: admin.json?.feed,
        network: admin.json?.network,
        date: admin.json?.date,
        access: admin.json?.access,
        count: admin.json?.count,
        threatsPreview: (admin.json?.threats ?? []).slice(0, 3),
      },
    );
    if (admin.res.status !== 200) {
      throw new Error(
        `Admin feed failed (${admin.res.status}). Set the same ADMIN_API_KEY in .dev.vars / wrangler secret.`,
      );
    }
    console.log("\n✅ Admin feed OK (no payment needed)");
    return;
  }

  // 1) Unpaid request → 402
  const unpaid = await request(feedUrl);
  log("1) Unpaid request", `status=${unpaid.res.status} (expect 402)`);
  if (unpaid.res.status !== 402) {
    throw new Error(`Expected 402, got ${unpaid.res.status}: ${unpaid.text}`);
  }
  const paymentInfo = pickPaymentInfo(unpaid.res, unpaid.json);
  log("1) Payment challenge", "Extracted payment details:", paymentInfo);

  if (!PAYMENT_PROOF) {
    console.log(`
ℹ️  Step 1 OK — Worker correctly returned 402.

Next:
  1) Send ${paymentInfo.fromHeaders["X-Payment-Amount-Display"] || "0.01 USDC"}
     to ${paymentInfo.fromHeaders["X-Payment-Recipient"]}
     on network ${paymentInfo.fromHeaders["X-Payment-Network"]}
     (token ${paymentInfo.fromHeaders["X-Payment-Token"]})
  2) Re-run with:
       $env:PAYMENT_PROOF="0xYourTxHash"
       npm run test:buyer
`);
    return;
  }

  // 2) Paid request → 200 feed
  const paid = await request(feedUrl, { "X-Payment-Proof": PAYMENT_PROOF });
  log("2) Paid request", `status=${paid.res.status} (expect 200)`);
  if (paid.res.status !== 200) {
    throw new Error(`Expected 200 after payment, got ${paid.res.status}: ${paid.text}`);
  }
  log("2) Feed payload", `count=${paid.json?.count ?? "?"}`, {
    feed: paid.json?.feed,
    network: paid.json?.network,
    date: paid.json?.date,
    access: paid.json?.access,
    threatsPreview: (paid.json?.threats ?? []).slice(0, 3),
  });

  // 3) Replay → 400
  const replay = await request(feedUrl, { "X-Payment-Proof": PAYMENT_PROOF });
  log("3) Replay attack", `status=${replay.res.status} (expect 400)`);
  if (replay.res.status !== 400) {
    throw new Error(`Expected 400 on replay, got ${replay.res.status}: ${replay.text}`);
  }
  log("3) Replay body", replay.json?.error || replay.text);

  console.log("\n✅ Buyer flow OK: 402 → paid 200 → replay 400");
}

main().catch((err) => {
  console.error("\n❌ Buyer test failed:", err.message || err);
  process.exitCode = 1;
});
