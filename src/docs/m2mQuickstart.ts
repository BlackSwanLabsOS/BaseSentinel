/** Public M2M quickstart + agent cookbook served at GET /docs. */
export const M2M_DOCS_MARKDOWN = `# BaseSentinel — M2M quickstart

Pay-per-call threat intel on **Base** (\`eip155:8453\`). No API keys.

**API:** https://api.blackswanlabs.pl  
**OpenAPI:** https://api.blackswanlabs.pl/openapi.json  
**Agent tools:** https://api.blackswanlabs.pl/tools.json  
**x402 catalog:** https://api.blackswanlabs.pl/.well-known/x402.json

Errors return \`{ "error_code": "...", "message": "...", "error": "..." }\`. Branch on \`error_code\` (e.g. \`TX_HASH_CONSUMED\`, \`INSUFFICIENT_USDC\`, \`PAYMENT_REQUIRED\`).

---

## Treasury (Base)

\`\`\`
0x21360A04853b85a8d2E918b73f97C8ccf5939946
\`\`\`

USDC (Base): \`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\`

---

## Prices

| Product | Endpoint | Price |
|--------|----------|-------|
| Scan | \`GET /scan/{address}\` | **0.005 USDC** |
| Dossier | \`GET /dossier/{address}\` | **0.25 USDC** |
| Watch (7d) | \`POST /watch\` | **0.50 USDC** |
| Daily feed | \`GET /api/feed/daily/YYYY-MM-DD\` | **0.01 USDC** |
| Live stream | \`GET /stream/threats\` | **0.005 USDC** / UTC day |

Settlement: transfer USDC on Base → retry with header \`X-Payment-Proof: <tx_hash>\`.

---

## Agent cookbook (M2M loop)

Machines should discover BaseSentinel via catalogs (\`/tools.json\`, OpenAPI, x402), not via unsolicited on-chain messages.

### Loop

1. **Discover** — \`GET /tools.json\` (or OpenAPI / x402 catalog).
2. **Call** — \`GET /scan/{address}\` without payment → expect **402** + \`error_code: PAYMENT_REQUIRED\` + \`payment_info\`.
3. **Pay** — transfer exact USDC on Base to \`payment_info.recipient\` (amount from \`payment_info\`).
4. **Retry** — same URL with \`X-Payment-Proof: <tx_hash>\`.
5. **Branch** on HTTP + \`error_code\` / \`verdict\`.

### Branch on \`error_code\`

| HTTP | error_code | Agent action |
|------|------------|--------------|
| 402 | \`PAYMENT_REQUIRED\` | Pay USDC, then retry with proof |
| 400 | \`INVALID_ADDRESS_FORMAT\` | Fix address; do not retry same input |
| 400 | \`INVALID_PROOF_FORMAT\` | Fix tx hash format |
| 409 | \`TX_HASH_CONSUMED\` | Stop — proof already used; new payment required |
| 409 | \`TX_HASH_BOUND_OTHER\` | Stop — proof bound to another resource |
| 422 | \`INSUFFICIENT_USDC\` | Pay again with correct amount |
| 422 | \`PAYMENT_INVALID\` | Fix payTo / USDC asset / network |
| 502 | \`UPSTREAM_TIMEOUT\` | Retry after a short backoff |

### Branch on \`verdict\` (200 OK)

| verdict | Typical agent policy |
|---------|----------------------|
| \`CLEAR\` | Proceed (still use your own risk limits) |
| \`CAUTION\` | Reduce size / require more checks |
| \`AVOID\` | Do not buy / exit path |

\`verdict_score\`: integer **0–100** (100 = clean, 0 = high risk).  
Also read \`status\` (\`SAFE\` / \`SUSPICIOUS\` / \`SCAM\`) and \`risk_flags\` (string array).

### Minimal scan (curl)

\`\`\`bash
# 1) Probe (expect 402)
curl -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# 2) After paying 0.005 USDC on Base to the treasury:
curl -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" \\
  -H "X-Payment-Proof: 0xYOUR_TX_HASH"
\`\`\`

PowerShell:

\`\`\`powershell
curl.exe -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" \`
  -H "X-Payment-Proof: 0xYOUR_TX_HASH"
\`\`\`

### Load tools into an LLM agent

1. \`GET https://api.blackswanlabs.pl/tools.json\`
2. Pass \`tools\` array into your OpenAI/LangChain tool registry.
3. Implement a thin wrapper: on tool call → ensure USDC payment → HTTP GET/POST with \`X-Payment-Proof\`.

Example client (no secrets in repo): [examples/agent-scan.md](https://github.com/BlackSwanLabsOS/BaseSentinel/blob/main/examples/agent-scan.md)

---

## Watch example

\`\`\`bash
curl -s -X POST "https://api.blackswanlabs.pl/watch" \\
  -H "Content-Type: application/json" \\
  -H "X-Payment-Proof: 0xYOUR_TX_HASH" \\
  -d '{"target_address":"0xYourContract","webhook_url":"https://your.endpoint/hook"}'
\`\`\`

---

## Discovery (where agents find us)

- \`/tools.json\` — OpenAI-style function schemas
- \`/openapi.json\` — full HTTP contract
- \`/.well-known/x402.json\` — payment / catalog metadata
- Ontario Protocol, Virtuals ACP, x402-list

Integrate through catalogs and the payment loop above.

---

BlackSwan Labs · https://blackswanlabs.pl · blackswanlabsos@gmail.com
`;
