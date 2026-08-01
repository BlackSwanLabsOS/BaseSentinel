# basesentinel-langchain

LangChain tool for [BaseSentinel](https://api.blackswanlabs.pl) — scan Base contracts for honeypot / scam risk from Python agents.

Each call pays **0.005 USDC** on Base (tx-hash proof). The tool returns a short risk summary, or a machine-readable `BASESENTINEL_ERROR …` string on failure.

**API:** https://api.blackswanlabs.pl · **Docs:** https://api.blackswanlabs.pl/docs

## Install

```bash
pip install basesentinel-langchain
# optional agent example extras:
pip install "basesentinel-langchain[agents]"
```

From this repository:

```bash
cd packages/langchain-basesentinel
python -m pip install -e .
```

## Usage

```python
from basesentinel_langchain import BaseSentinelScanTool

tool = BaseSentinelScanTool(
    private_key="0xYOUR_BASE_WALLET_KEY",  # or set BASESENTINEL_PRIVATE_KEY
)
print(tool.invoke({"contract_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}))
```

ReAct-style example: [`examples/react_agent_example.py`](examples/react_agent_example.py).

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `BASESENTINEL_PRIVATE_KEY` | yes | Base wallet private key with USDC |
| `BASESENTINEL_RPC_URL` | no | Default `https://mainnet.base.org` |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

Treasury (scan): `0x21360A04853b85a8d2E918b73f97C8ccf5939946` · **0.005 USDC** per call.

## Errors

On failure the tool returns a string such as:

```text
BASESENTINEL_ERROR error_code=INSUFFICIENT_USDC http_status=422 message=...
```

Branch on `error_code`, not HTTP status alone. `402` is only `PAYMENT_REQUIRED`; codes like `TX_HASH_CONSUMED` or `INSUFFICIENT_USDC` use other statuses. The API exposes `reasons[]` (plural).

Common codes: `PAYMENT_REQUIRED`, `TX_HASH_CONSUMED`, `TX_HASH_BOUND_OTHER`, `INSUFFICIENT_USDC`, `PAYMENT_INVALID`.

## License

MIT · [BlackSwan Labs](https://blackswanlabs.pl)
