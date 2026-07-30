"""LangChain BaseTool for BaseSentinel contract scans."""

from __future__ import annotations

from typing import Any, Type

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field, PrivateAttr

from basesentinel_langchain.client import scan_contract
from basesentinel_langchain.errors import BaseSentinelError
from basesentinel_langchain.payer import (
    get_api_base_url,
    get_payment_proof_override,
    pay_for_scan,
)
from basesentinel_langchain.summary import summarize_scan_result


class BaseSentinelScanInput(BaseModel):
    """Input schema for BaseSentinelScanTool."""

    contract_address: str = Field(
        ...,
        description=(
            "The Base network smart-contract address to analyze "
            "(0x-prefixed, 40 hex characters)."
        ),
    )


class BaseSentinelScanTool(BaseTool):
    """Analyze scam / honeypot risk for a Base smart contract via BaseSentinel.

    Use this tool when you need to know whether a Base (eip155:8453) token or
    contract looks SAFE, SUSPICIOUS, or SCAM before interacting with it.
    Provide a single 0x contract address. The tool returns status, agent
    verdict (CLEAR / CAUTION / AVOID), verdict_score (0-100), and reasons.

    Payment (0.005 USDC on Base) is handled automatically by the runtime —
    do not ask the user for transaction hashes or API keys.
    """

    name: str = "basesentinel_scan_contract"
    description: str = (
        "Analyze smart-contract risk on the Base network using BaseSentinel. "
        "Input: a Base contract address (0x…). "
        "Output: status (SAFE/SUSPICIOUS/SCAM), verdict (CLEAR/CAUTION/AVOID), "
        "verdict_score 0-100, and reasons. "
        "Use before buying, approving, or interacting with an unknown Base token."
    )
    args_schema: Type[BaseModel] = BaseSentinelScanInput

    # Runtime config (not for the LLM)
    private_key: str | None = None
    rpc_url: str | None = None
    api_base_url: str | None = None
    skip_probe: bool = False

    _last_error: BaseSentinelError | None = PrivateAttr(default=None)

    def _run(
        self,
        contract_address: str,
        run_manager: CallbackManagerForToolRun | None = None,
    ) -> str:
        """Sync tool entrypoint used by ReAct / LangGraph agents."""
        del run_manager  # unused; kept for BaseTool signature
        self._last_error = None
        try:
            api = get_api_base_url(self.api_base_url)
            proof = get_payment_proof_override()
            if not proof:
                settlement = pay_for_scan(
                    contract_address,
                    private_key=self.private_key,
                    rpc_url=self.rpc_url,
                    api_base_url=api,
                    skip_probe=self.skip_probe,
                )
                proof = settlement.tx_hash

            result = scan_contract(
                contract_address,
                proof,
                api_base_url=api,
            )
            return summarize_scan_result(result)
        except BaseSentinelError as exc:
            self._last_error = exc
            # Do not crash the agent loop — return a clear, branchable string.
            return exc.to_agent_message()
        except Exception as exc:  # noqa: BLE001
            return (
                "BASESENTINEL_ERROR error_code=UNKNOWN "
                f"http_status=0 message={exc}"
            )

    async def _arun(
        self,
        contract_address: str,
        run_manager: Any = None,
    ) -> str:
        # Payment + HTTP are sync web3/httpx; offload via default sync path.
        return self._run(contract_address, run_manager=run_manager)
