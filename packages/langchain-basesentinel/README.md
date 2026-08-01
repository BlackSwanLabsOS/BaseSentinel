# LangChain tool for BaseSentinel

Python / LangChain integration that lets an agent **scan Base contracts** via [BaseSentinel](https://api.blackswanlabs.pl).

Payment is **M2M under the hood** (USDC transfer on Base → `X-Payment-Proof`). The LLM only sees a short risk summary (or a machine-readable `BASESENTINEL_ERROR …` line on failure — the agent loop does not crash).

> Gemini note (corrected here): HTTP **402** means `PAYMENT_REQUIRED` only. Codes like `TX_HASH_CONSUMED` / `INSUFFICIENT_USDC` arrive on other statuses — we branch on `error_code`. We wait for a **successful receipt** before calling `/scan`. API field is `reasons[]`, not `reason`.

## Install

```bash
pip install basesentinel-langchain
# optional ReAct example deps:
pip install "basesentinel-langchain[agents]"
```

From this repo (editable):

```bash
cd packages/langchain-basesentinel
python -m pip install -e .
```

## Tool

```python
from basesentinel_langchain import BaseSentinelScanTool

tool = BaseSentinelScanTool(
    private_key="0xYOUR_BASE_WALLET_KEY",  # or set BASESENTINEL_PRIVATE_KEY
)
print(tool.invoke({"contract_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"}))
# -> Contract 0x… is SAFE (CLEAR). Score: 100/100. Reasons: …
```

## Runtime secrets

| Env | Required | Purpose |
|-----|----------|---------|
| `BASESENTINEL_PRIVATE_KEY` | yes* | Base wallet key with USDC |
| `BASESENTINEL_PAYMENT_PROOF` | no | Already-paid tx hash (local test; not free scans) |
| `BASESENTINEL_RPC_URL` | no | Default `https://mainnet.base.org` |
| `BASESENTINEL_API_BASE_URL` | no | Default `https://api.blackswanlabs.pl` |

\*Required unless `BASESENTINEL_PAYMENT_PROOF` is set.

Cost per scan: **0.005 USDC** → treasury `0x21360A04853b85a8d2E918b73f97C8ccf5939946`.

## Errors (agent-safe)

On failure the tool returns a string like:

```text
BASESENTINEL_ERROR error_code=INSUFFICIENT_USDC http_status=422 message=...
```

Stable codes match the API: `PAYMENT_REQUIRED`, `TX_HASH_CONSUMED`, `TX_HASH_BOUND_OTHER`, `INSUFFICIENT_USDC`, `PAYMENT_INVALID`, …

## ReAct example

See [`examples/react_agent_example.py`](examples/react_agent_example.py).
