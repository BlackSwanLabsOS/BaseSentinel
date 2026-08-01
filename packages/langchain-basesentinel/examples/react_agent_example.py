"""
Minimal LangChain ReAct-style usage for BaseSentinelScanTool.

Requires:
  pip install -e ".[agents]"
  BASESENTINEL_PRIVATE_KEY=0x...   # Base wallet with USDC
  OPENAI_API_KEY=...               # or swap the LLM

Does not print secrets. Each scan spends 0.005 USDC on Base.
"""

from __future__ import annotations

import os

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI

from basesentinel_langchain import BaseSentinelScanTool


def main() -> None:
    tool = BaseSentinelScanTool(
        private_key=os.environ.get("BASESENTINEL_PRIVATE_KEY"),
        rpc_url=os.environ.get("BASESENTINEL_RPC_URL"),
        api_base_url=os.environ.get("BASESENTINEL_API_BASE_URL"),
    )

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You are a Base-chain risk assistant. "
                "When the user asks about a contract or token address, "
                "call basesentinel_scan_contract. "
                "Summarize the tool result; never invent payment steps.",
            ),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ]
    )
    agent = create_tool_calling_agent(llm, [tool], prompt)
    executor = AgentExecutor(agent=agent, tools=[tool], verbose=True)

    address = os.environ.get(
        "TARGET_ADDRESS",
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    result = executor.invoke(
        {"input": f"Is this Base contract safe to interact with? {address}"}
    )
    print(result.get("output", result))


if __name__ == "__main__":
    main()
