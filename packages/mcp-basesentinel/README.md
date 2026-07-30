# @blackswanlabs/mcp-basesentinel

MCP (Model Context Protocol) server for [BaseSentinel](https://api.blackswanlabs.pl).

Exposes tool **`scan_contract`**. Payment (0.005 USDC on Base → `X-Payment-Proof`) stays in the runtime — the model only sees a risk summary.

## Install / build

```bash
cd packages/mcp-basesentinel
npm install
npm run build
```

## Cursor / Claude Desktop (stdio)

Example MCP config entry:

```json
{
  "mcpServers": {
    "basesentinel": {
      "command": "node",
      "args": ["C:/Users/CAD-CAM/BaseSentinel/packages/mcp-basesentinel/dist/index.js"],
      "env": {
        "BASESENTINEL_PRIVATE_KEY": "0xYOUR_BASE_WALLET_KEY",
        "BASESENTINEL_RPC_URL": "https://mainnet.base.org"
      }
    }
  }
}
```

Ops smoke without spending: set `BASESENTINEL_PAYMENT_PROOF` to an existing USDC tx hash instead of the private key.

## Tool

| Name | Input | Output |
|------|--------|--------|
| `scan_contract` | `contract_address` (0x…) | Text summary + structured status/verdict/score/reasons |

On failure returns `BASESENTINEL_ERROR error_code=…` (stable API codes).

## Runtime secrets

| Env | Required | Purpose |
|-----|----------|---------|
| `BASESENTINEL_PRIVATE_KEY` | yes* | Base wallet with USDC |
| `BASESENTINEL_PAYMENT_PROOF` | no | Skip spend |
| `BASESENTINEL_RPC_URL` | no | Default public Base RPC |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

\*Unless payment-proof override is set.

Not published to npm yet — use the local path above. After org publish:

```bash
npm install @blackswanlabs/mcp-basesentinel
```
