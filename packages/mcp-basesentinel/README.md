# @basesentinel/mcp

MCP server for [BaseSentinel](https://api.blackswanlabs.pl) — scan Base contracts for honeypot / scam risk.

Exposes tool `scan_contract`. The runtime pays **0.005 USDC** on Base and attaches `X-Payment-Proof`; the model receives only a risk summary.

**API:** https://api.blackswanlabs.pl · **Docs:** https://api.blackswanlabs.pl/docs

## Install

```bash
npm install -g @basesentinel/mcp
# or:
npx -y @basesentinel/mcp
```

From this repository:

```bash
cd packages/mcp-basesentinel
npm install
npm run build
```

## MCP client config

Example for Cursor or Claude Desktop (`mcpServers`):

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

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `BASESENTINEL_PRIVATE_KEY` | yes | Base wallet private key with USDC |
| `BASESENTINEL_RPC_URL` | no | Base RPC (default: public Base endpoint) |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

Treasury (scan): `0x21360A04853b85a8d2E918b73f97C8ccf5939946` · **0.005 USDC** per call.

## Tool

| Name | Input | Result |
|------|--------|--------|
| `scan_contract` | `contract_address` (`0x…`) | Text summary plus status / verdict / score / reasons |

Failures return a stable line: `BASESENTINEL_ERROR error_code=…` (same codes as the HTTP API).

## License

MIT · [BlackSwan Labs](https://blackswanlabs.pl)
