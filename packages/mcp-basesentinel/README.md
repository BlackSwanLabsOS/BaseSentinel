# @basesentinel/mcp

MCP (Model Context Protocol) server for [BaseSentinel](https://api.blackswanlabs.pl).

Exposes tool **`scan_contract`**. Payment (0.005 USDC on Base → `X-Payment-Proof`) stays in the runtime — the model only sees a risk summary.

## Install

```bash
npm install -g @basesentinel/mcp
# or one-shot:
npx @basesentinel/mcp
```

Local build from this repo:

```bash
cd packages/mcp-basesentinel
npm install
npm run build
```

## Cursor / Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "basesentinel": {
      "command": "npx",
      "args": ["-y", "@basesentinel/mcp"],
      "env": {
        "BASESENTINEL_PRIVATE_KEY": "0xYOUR_BASE_WALLET_KEY",
        "BASESENTINEL_RPC_URL": "https://mainnet.base.org"
      }
    }
  }
}
```

Optional local testing: set `BASESENTINEL_PAYMENT_PROOF` to a tx hash you already paid (API still enforces one redeem — not a free bypass).

## Tool

| Name | Input | Output |
|------|--------|--------|
| `scan_contract` | `contract_address` (0x…) | Text summary + structured status/verdict/score/reasons |

On failure returns `BASESENTINEL_ERROR error_code=…` (stable API codes).

## Runtime secrets

| Env | Required | Purpose |
|-----|----------|---------|
| `BASESENTINEL_PRIVATE_KEY` | yes* | Base wallet with USDC |
| `BASESENTINEL_PAYMENT_PROOF` | no | Already-paid tx hash (local test; not free scans) |
| `BASESENTINEL_RPC_URL` | no | Default public Base RPC |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

\*Unless payment-proof override is set.
