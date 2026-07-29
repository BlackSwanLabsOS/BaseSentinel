/** Public M2M quickstart served at GET /docs. */
export const M2M_DOCS_MARKDOWN = `# BaseSentinel — M2M quickstart

Pay-per-call threat intel on **Base** (\`eip155:8453\`). No API keys.

**API:** https://api.blackswanlabs.pl  
**OpenAPI:** https://api.blackswanlabs.pl/openapi.json  
**x402 catalog:** https://api.blackswanlabs.pl/.well-known/x402.json

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

## 2-step usage (scan)

### 1) Transfer 0.005 USDC to the treasury on Base

### 2) Call the API

\`\`\`bash
curl -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" \\
  -H "X-Payment-Proof: 0xYOUR_TX_HASH"
\`\`\`

PowerShell:

\`\`\`powershell
curl.exe -s "https://api.blackswanlabs.pl/scan/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" \`
  -H "X-Payment-Proof: 0xYOUR_TX_HASH"
\`\`\`

No proof → **HTTP 402** with \`payment_info\`.

---

## Watch example

\`\`\`bash
curl -s -X POST "https://api.blackswanlabs.pl/watch" \\
  -H "Content-Type: application/json" \\
  -H "X-Payment-Proof: 0xYOUR_TX_HASH" \\
  -d '{"target_address":"0xYourContract","webhook_url":"https://your.endpoint/hook"}'
\`\`\`

---

BlackSwan Labs · https://blackswanlabs.pl · blackswanlabsos@gmail.com
`;
