# @basesentinel/eliza

Eliza OS plugin for [BaseSentinel](https://api.blackswanlabs.pl) — scan Base contracts for honeypot / scam risk.

Each scan pays **0.005 USDC** on Base (tx-hash proof). The model sees only a short risk summary.

**API:** https://api.blackswanlabs.pl · **Docs:** https://api.blackswanlabs.pl/docs

## Install

```bash
npm install @basesentinel/eliza
```

Requires `@elizaos/core` at agent runtime (peer dependency).

## Register

```ts
import { AgentRuntime } from "@elizaos/core";
import baseSentinelPlugin from "@basesentinel/eliza";

const runtime = new AgentRuntime({
  // character, models, …
  plugins: [baseSentinelPlugin],
});
```

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `BASESENTINEL_PRIVATE_KEY` | yes | Base wallet private key (`0x` + 64 hex) with USDC |
| `BASESENTINEL_RPC_URL` | no | Default `https://mainnet.base.org` |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

Treasury (scan): `0x21360A04853b85a8d2E918b73f97C8ccf5939946` · **0.005 USDC** per call.

## Action

| | |
|--|--|
| **Name** | `SCAN_CONTRACT` |
| **Input** | Contract address (`0x…`) in the user message, or `options.address` |
| **Output** | e.g. `Contract 0x… is SAFE (CLEAR). Score: 100/100. Reasons: …` |

## Errors

Failures raise `BaseSentinelError` with stable `errorCode` values matching the HTTP API, including:

`PAYMENT_REQUIRED`, `TX_HASH_CONSUMED`, `TX_HASH_BOUND_OTHER`, `INSUFFICIENT_USDC`, `PAYMENT_INVALID`, `INVALID_ADDRESS_FORMAT`, `UPSTREAM_TIMEOUT`

Branch on `errorCode`. HTTP `402` is only `PAYMENT_REQUIRED`; other codes use other status codes.

## Programmatic use (without Eliza)

```ts
import {
  payForScan,
  scanContract,
  summarizeScanResult,
} from "@basesentinel/eliza";

const address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const { txHash } = await payForScan({ contractAddress: address });
const result = await scanContract(address, txHash);
console.log(summarizeScanResult(result));
```

## Build

```bash
cd packages/eliza-basesentinel
npm install
npm run build
```

## License

MIT · [BlackSwan Labs](https://blackswanlabs.pl)
