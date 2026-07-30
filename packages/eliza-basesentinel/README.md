# @blackswanlabs/eliza-basesentinel

Eliza OS plugin that lets an agent **scan Base contracts** via [BaseSentinel](https://api.blackswanlabs.pl).

Payment is **M2M under the hood** (USDC transfer on Base → `X-Payment-Proof`). The LLM only sees a short risk summary.

## Install (in an Eliza agent project)

```bash
# from this repo (local path) until published to npm:
npm install ../path/to/BaseSentinel/packages/eliza-basesentinel
# after npm org publish:
# npm install @blackswanlabs/eliza-basesentinel
```

Peer: `@elizaos/core` (optional at build time; required at agent runtime).

## Register

```ts
import { AgentRuntime } from "@elizaos/core";
import baseSentinelPlugin from "@blackswanlabs/eliza-basesentinel";

const runtime = new AgentRuntime({
  // ...character, models
  plugins: [baseSentinelPlugin],
});
```

## Runtime secrets (never chat these to the LLM)

| Env | Required | Purpose |
|-----|----------|---------|
| `BASESENTINEL_PRIVATE_KEY` | yes* | Base wallet private key (`0x` + 64 hex) with USDC |
| `BASESENTINEL_PAYMENT_PROOF` | no | Existing tx hash — skips the spend (ops/smoke) |
| `BASESENTINEL_RPC_URL` | no | Base RPC (default `https://mainnet.base.org`) |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

\*Required unless `BASESENTINEL_PAYMENT_PROOF` is set.

Cost per scan: **0.005 USDC** to treasury `0x21360A04853b85a8d2E918b73f97C8ccf5939946`.

## Action

- **Name:** `SCAN_CONTRACT`
- **Input:** a `0x` contract address in the user message (or `options.address`)
- **Output (LLM):**  
  `Contract 0x… is SAFE (CLEAR). Score: 100/100. Reasons: Bluechip_Allowlist:USDC`

## Errors

Failures surface as `BaseSentinelError` with stable `errorCode` (same as the API):

- `PAYMENT_REQUIRED`, `TX_HASH_CONSUMED`, `TX_HASH_BOUND_OTHER`
- `INSUFFICIENT_USDC`, `PAYMENT_INVALID`, `INVALID_ADDRESS_FORMAT`
- `UPSTREAM_TIMEOUT`, …

HTTP **402** is `PAYMENT_REQUIRED` only. Other `error_code` values arrive on other status codes — branch on `errorCode`, not on “402 + enum”.

## Programmatic use (no Eliza)

```ts
import {
  payForScan,
  scanContract,
  summarizeScanResult,
} from "@blackswanlabs/eliza-basesentinel";

const { txHash } = await payForScan({
  contractAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
});
const result = await scanContract(
  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  txHash,
);
console.log(summarizeScanResult(result));
```

## Build

```bash
cd packages/eliza-basesentinel
npm install
npm run build
```
