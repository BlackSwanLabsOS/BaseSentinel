# BaseSentinel

M2M threat intelligence for **Base** (`eip155:8453`).  
Pay per call with **USDC** — no API keys.

**Live API:** https://api.blackswanlabs.pl  
**Landing:** https://blackswanlabs.pl

---

## How payment works (2 steps)

1. Send USDC on **Base** to the treasury wallet (exact product amount).
2. Call the endpoint with header:

```http
X-Payment-Proof: 0xYOUR_TX_HASH
```

The tx-hash is bound to the resource (e.g. contract address). Reuse on another address is rejected. Same hash cannot be replayed for a new paid call (KV anti-replay).

### Treasury (Base)

```
0x21360A04853b85a8d2E918b73f97C8ccf5939946
```

Asset: native USDC on Base — `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

---

## Products & prices

| Product | Method | Path | Price |
|--------|--------|------|-------|
| Contract scan | `GET` | `/scan/{address}` | **0.005 USDC** |
| Premium dossier | `GET` | `/dossier/{address}` | **0.25 USDC** |
| Watchdog (7 days) | `POST` | `/watch` | **0.50 USDC** |
| Daily threat feed | `GET` | `/api/feed/daily/YYYY-MM-DD` | **0.01 USDC** |
| Live threat stream | `GET` | `/stream/threats` | **0.005 USDC** / UTC day |

Machine catalogs:  
- https://api.blackswanlabs.pl/.well-known/x402.json  
- https://api.blackswanlabs.pl/openapi.json  
- https://api.blackswanlabs.pl/tools.json (OpenAI-style tool schemas)  
- Human docs: https://api.blackswanlabs.pl/docs  

Errors: `{ "error_code": "...", "message": "...", "error": "..." }` — branch on `error_code`.

Settlement: **`tx_hash_proof`** (USDC transfer + hash).

**Agent cookbook:** https://api.blackswanlabs.pl/docs (402 → pay → retry → branch)  
**Example client:** [examples/agent-scan.md](examples/agent-scan.md) · `npm run example:agent-scan`

Discovery is via catalogs (`/tools.json`, OpenAPI, x402) — not on-chain spam or honeypot traps.

---

## Example: scan a contract

### 1) Pay 0.005 USDC on Base to the treasury

Send exactly **0.005 USDC** (or more) to:

`0x21360A04853b85a8d2E918b73f97C8ccf5939946`

Copy the transaction hash.

### 2) Call `/scan` with the proof

PowerShell:

```powershell
curl.exe -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" `
  -H "X-Payment-Proof: 0xPASTE_YOUR_TX_HASH_HERE"
```

bash:

```bash
curl -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" \
  -H "X-Payment-Proof: 0xPASTE_YOUR_TX_HASH_HERE"
```

Without payment you get **HTTP 402** with `payment_info` (amount, payTo, network).

Response includes `status` (SAFE / SUSPICIOUS / SCAM), agent `verdict` (CLEAR / CAUTION / AVOID), `verdict_score`, `risk_flags`, and enrichment dossier.

---

## Example: premium dossier (0.25 USDC)

```powershell
curl.exe -s "https://api.blackswanlabs.pl/dossier/0xYourContract" `
  -H "X-Payment-Proof: 0xPASTE_YOUR_TX_HASH_HERE"
```

---

## Example: 7-day watch (0.50 USDC)

```powershell
curl.exe -s -X POST "https://api.blackswanlabs.pl/watch" `
  -H "Content-Type: application/json" `
  -H "X-Payment-Proof: 0xPASTE_YOUR_TX_HASH_HERE" `
  -d '{"target_address":"0xYourContract","webhook_url":"https://your.https.endpoint/hook"}'
```

On verdict / tax / risk_flag changes, BaseSentinel POSTs JSON `STATUS_CHANGED` to your `webhook_url` (HTTPS only).

---

## Where to find us

Machine catalogs on our host (always current):

- https://api.blackswanlabs.pl/.well-known/x402.json
- https://api.blackswanlabs.pl/openapi.json
- https://api.blackswanlabs.pl/tools.json
- https://api.blackswanlabs.pl/docs

External directories (status as of 2026-07-30):

| Directory | Status | Notes |
|-----------|--------|--------|
| [Ontario Protocol](https://ontarioprotocol.com/discover) | **Listed** (`ready`, paid listing) | Scan @ `0.005 USDC`. Integrity still “pending” because buyers settle with our **tx-hash proof**, not Coinbase facilitator / EIP-3009. |
| [Virtuals ACP](https://app.virtuals.io/acp/agent/019faeb2-bed1-7699-9aa0-6899796a223d) | **Agent registered** | BaseSentinel offerings point at `api.blackswanlabs.pl`. |
| [x402-list](https://x402-list.com/) | **Submitted — awaiting manual approval** | Probe accepted 3 endpoints; not in the public directory API yet. |
| Coinbase x402 Bazaar | **Blocked on settlement model** | Validate/readiness can pass; full Bazaar indexing expects facilitator settle. We intentionally settle via **`tx_hash_proof`** (`X-Payment-Proof`), so we do not complete that payment path. |

Settlement for buyers of BaseSentinel remains: send USDC on Base → retry with `X-Payment-Proof: <tx_hash>`.

### Eliza OS plugin (local package)

Agent integration lives in [`packages/eliza-basesentinel`](packages/eliza-basesentinel) (`@blackswanlabs/eliza-basesentinel`).  
Action `SCAN_CONTRACT` pays 0.005 USDC under the hood and returns a short verdict string to the LLM. See that package README — **not published to npm yet**.

### LangChain tool (local package)

Python tool lives in [`packages/langchain-basesentinel`](packages/langchain-basesentinel) (`blackswanlabs-langchain-basesentinel`).  
`BaseSentinelScanTool` auto-pays on Base and returns a risk summary (or `BASESENTINEL_ERROR …` without crashing the agent). **Not on PyPI yet.**

---

## Contact

BlackSwan Labs — https://blackswanlabs.pl  
blackswanlabsos@gmail.com
