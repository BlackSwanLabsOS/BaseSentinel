#!/usr/bin/env node
/**
 * BaseSentinel MCP server (stdio).
 * Logs only to stderr — stdout is the MCP JSON-RPC channel.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scanContract } from "./client.js";
import { BaseSentinelError } from "./errors.js";
import {
  getApiBaseUrl,
  getPaymentProofOverride,
  payForScan,
} from "./payer.js";
import { summarizeScanResult } from "./summary.js";

const server = new McpServer({
  name: "basesentinel",
  version: "0.1.0",
});

server.registerTool(
  "scan_contract",
  {
    title: "Scan Base contract",
    description:
      "Analyze smart-contract risk on the Base network via BaseSentinel. " +
      "Input a Base contract address (0x…). Returns status (SAFE/SUSPICIOUS/SCAM), " +
      "verdict (CLEAR/CAUTION/AVOID), verdict_score 0-100, and reasons. " +
      "Use before buying, approving, or interacting with an unknown Base token. " +
      "Payment (0.005 USDC) is handled by the runtime — do not ask for tx hashes.",
    inputSchema: {
      contract_address: z
        .string()
        .regex(/^0x[a-fA-F0-9]{40}$/, "Must be 0x + 40 hex characters")
        .describe("Base smart-contract address to scan"),
    },
  },
  async ({ contract_address }) => {
    try {
      const apiBaseUrl = getApiBaseUrl();
      const override = getPaymentProofOverride();
      const paymentProof =
        override ??
        (
          await payForScan({
            contractAddress: contract_address,
            apiBaseUrl,
          })
        ).txHash;

      const result = await scanContract(contract_address, paymentProof, {
        apiBaseUrl,
      });
      const text = summarizeScanResult(result);
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: {
          address: result.address,
          status: result.status,
          verdict: result.verdict,
          verdict_score: result.verdict_score,
          reasons: result.reasons,
          risk_flags: result.risk_flags,
        },
      };
    } catch (error) {
      if (error instanceof BaseSentinelError) {
        const text =
          `BASESENTINEL_ERROR error_code=${error.errorCode} ` +
          `http_status=${error.httpStatus} message=${error.message}`;
        return {
          content: [{ type: "text" as const, text }],
          isError: true,
        };
      }
      const message =
        error instanceof Error ? error.message : "Unknown scan failure";
      return {
        content: [
          {
            type: "text" as const,
            text: `BASESENTINEL_ERROR error_code=UNKNOWN http_status=0 message=${message}`,
          },
        ],
        isError: true,
      };
    }
  },
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[mcp-basesentinel] ready on stdio");
}

main().catch((error) => {
  console.error("[mcp-basesentinel] fatal:", error);
  process.exit(1);
});
