/**
 * Live probe: count PairCreated / launch events per factory over a recent window.
 * Uses a public/logs RPC (default https://mainnet.base.org) — does NOT burn Alchemy CU.
 *
 *   node scripts/analyze-factory-activity.mjs
 *   node scripts/analyze-factory-activity.mjs --hours=24
 *   node scripts/analyze-factory-activity.mjs --hours=6 --rpc=https://mainnet.base.org
 *
 * Note: KV only stores last cron tick bySource — we have no multi-day event DB yet.
 */
const FACTORIES = [
  {
    id: "uniswap_v2",
    address: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
    topic: "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9",
  },
  {
    id: "aerodrome",
    address: "0x420DD381b31aEf6683db6B902084cB0FFECe40Da",
    topic: "0x2128d88d14c80cb081c1252a5acff7a264671bf199ce226b53788fb26065005e",
  },
  {
    id: "uniswap_v3",
    address: "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
    topic: "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118",
  },
  {
    id: "clanker_v4",
    address: "0xE85A59c628F7d27878ACeB4bf3b35733630083a9",
    topic: "0x9299d1d1a88d8e1abdc591ae7a167a6bc63a8f17d695804e9091ee33aa89fb67",
  },
  {
    id: "virtuals_launched",
    address: "0xF66DeA7b3e897cD44A5a231c61B6B4423d613259",
    topic: "0x714aa39317ad9a7a7a99db52b44490da5d068a0b2710fffb1a1282ad3cadae1f",
  },
  {
    id: "virtuals_graduated",
    address: "0xF66DeA7b3e897cD44A5a231c61B6B4423d613259",
    topic: "0x381d54fa425631e6266af114239150fae1d5db67bb65b4fa9ecc65013107e07e",
  },
  {
    id: "zora_coin_v4",
    address: "0x777777751622c0d3258f214F9DF38E35BF45baF3",
    topic: "0x2de436107c2096e039c98bbcc3c5a2560583738ce15c234557eecb4d3221aa81",
  },
  {
    id: "zora_creator_coin",
    address: "0x777777751622c0d3258f214F9DF38E35BF45baF3",
    topic: "0x74b670d628e152daa36ca95dda7cb0002d6ea7a37b55afe4593db7abd1515781",
  },
  {
    id: "zora_coin_legacy",
    address: "0x777777751622c0d3258f214F9DF38E35BF45baF3",
    topic: "0x3d1462491f7fa8396808c230d95c3fa60fd09ef59506d0b9bd1cf072d2a03f56",
  },
];

/** ~2s blocks on Base → 1800 blocks/hour */
const BLOCKS_PER_HOUR = 1800;
/** Public Base RPC usually tolerates larger spans than Alchemy Free (10). */
const CHUNK = 2000;

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
}

async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) {
    throw new Error(`${method}: ${body.error.message || JSON.stringify(body.error)}`);
  }
  return body.result;
}

async function countLogs(url, factory, fromBlock, toBlock) {
  let total = 0;
  let calls = 0;
  for (let start = fromBlock; start <= toBlock; start += CHUNK) {
    const end = Math.min(toBlock, start + CHUNK - 1);
    calls += 1;
    try {
      const logs = await rpc(url, "eth_getLogs", [
        {
          address: factory.address,
          topics: [factory.topic],
          fromBlock: `0x${start.toString(16)}`,
          toBlock: `0x${end.toString(16)}`,
        },
      ]);
      total += Array.isArray(logs) ? logs.length : 0;
    } catch (err) {
      // Halve on range/size errors (public nodes vary).
      if (CHUNK > 200 && end > start) {
        const mid = Math.floor((start + end) / 2);
        const left = await countLogs(url, factory, start, mid);
        const right = await countLogs(url, factory, mid + 1, end);
        return { total: left.total + right.total, calls: left.calls + right.calls + 1 };
      }
      throw err;
    }
  }
  return { total, calls };
}

const hours = Number(arg("hours", "6"));
const rpcUrl = arg("rpc", process.env.LOGS_RPC_URL || "https://mainnet.base.org");

console.log(`RPC: ${rpcUrl}`);
console.log(`Window: last ${hours}h (~${hours * BLOCKS_PER_HOUR} blocks), chunk=${CHUNK}`);
console.log("(No multi-day bySource in KV — this is a live chain probe.)\n");

const latestHex = await rpc(rpcUrl, "eth_blockNumber", []);
const latest = Number.parseInt(latestHex, 16);
const lookback = Math.max(1, Math.floor(hours * BLOCKS_PER_HOUR));
const fromBlock = Math.max(0, latest - lookback);

const rows = [];
for (const factory of FACTORIES) {
  process.stdout.write(`… ${factory.id} `);
  const started = Date.now();
  try {
    const { total, calls } = await countLogs(rpcUrl, factory, fromBlock, latest);
    const perHour = total / hours;
    rows.push({
      id: factory.id,
      events: total,
      perHour: Number(perHour.toFixed(2)),
      rpcCalls: calls,
      ms: Date.now() - started,
      error: null,
    });
    console.log(`→ ${total} events`);
  } catch (err) {
    rows.push({
      id: factory.id,
      events: null,
      perHour: null,
      rpcCalls: null,
      ms: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    });
    console.log(`→ ERROR ${err instanceof Error ? err.message : err}`);
  }
}

rows.sort((a, b) => (b.events ?? -1) - (a.events ?? -1));

console.log("\n=== Results ===");
console.log(
  "source".padEnd(22),
  "events".padStart(8),
  "per_hour".padStart(10),
  "verdict",
);
for (const r of rows) {
  if (r.error) {
    console.log(r.id.padEnd(22), "ERR".padStart(8), "".padStart(10), r.error.slice(0, 60));
    continue;
  }
  let verdict = "KEEP";
  if (r.events === 0) verdict = "CANDIDATE OFF (0 events)";
  else if (r.perHour < 0.5) verdict = "LOW — review";
  else if (r.perHour < 2) verdict = "MODERATE";
  else verdict = "HOT — keep";
  console.log(
    r.id.padEnd(22),
    String(r.events).padStart(8),
    String(r.perHour).padStart(10),
    verdict,
  );
}

console.log(`\nblocks ${fromBlock} → ${latest}`);
console.log("After you pick which to disable, we add enabled flags in dexFactories config.");
