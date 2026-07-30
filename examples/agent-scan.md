# Agent scan example (M2M)

Copy-paste guide for wiring BaseSentinel into an agent loop.  
No API keys. Pay with USDC on Base, prove with `X-Payment-Proof`.

## Endpoints

| Resource | URL |
|----------|-----|
| Tools | https://api.blackswanlabs.pl/tools.json |
| Docs | https://api.blackswanlabs.pl/docs |
| Scan | `GET https://api.blackswanlabs.pl/scan/{address}` |
| Treasury | `0x21360A04853b85a8d2E918b73f97C8ccf5939946` |
| USDC (Base) | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Scan price | **0.005 USDC** |

## Flow

```
GET /tools.json  →  register tools
GET /scan/{addr} →  402 PAYMENT_REQUIRED + payment_info
transfer USDC on Base to payment_info.recipient
GET /scan/{addr} + X-Payment-Proof: <tx_hash>
branch on verdict / error_code
```

## Run the sample client

Requires Node 18+ (global `fetch`). You supply a real Base USDC tx hash after paying.

```bash
# bash / mac / linux
export BASE_URL="https://api.blackswanlabs.pl"
export TARGET_ADDRESS="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
export PAYMENT_PROOF="0xYOUR_TX_HASH"
node examples/agent-scan.mjs
```

```powershell
$env:BASE_URL="https://api.blackswanlabs.pl"
$env:TARGET_ADDRESS="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
$env:PAYMENT_PROOF="0xYOUR_TX_HASH"
node examples/agent-scan.mjs
```

Without `PAYMENT_PROOF`, the script only probes (expects 402) and prints `payment_info`.

## LLM tool wiring

1. Fetch `tools.json`.
2. Register `tools` with your model (OpenAI tools / LangChain).
3. When the model calls `basesentinel_scan`:
   - ensure a fresh USDC payment for that address (0.005),
   - HTTP GET `/scan/{address}` with header `X-Payment-Proof`,
   - return JSON to the model; let it branch on `verdict` and `error_code`.

## Error codes (branch here)

| error_code | Meaning |
|------------|---------|
| `PAYMENT_REQUIRED` | Pay, then retry |
| `TX_HASH_CONSUMED` | Proof burned — new payment |
| `TX_HASH_BOUND_OTHER` | Proof for another resource |
| `INSUFFICIENT_USDC` | Amount too low |
| `PAYMENT_INVALID` | Wrong asset / recipient / network |
| `UPSTREAM_TIMEOUT` | Retry with backoff |

## Verdict policy (example)

| verdict | Policy |
|---------|--------|
| `CLEAR` | Allow trade within your limits |
| `CAUTION` | Downsize / extra checks |
| `AVOID` | Skip buy |

Do not put private keys or Alchemy keys in this example flow — payment can be any wallet you control; the API only needs the public tx hash.
