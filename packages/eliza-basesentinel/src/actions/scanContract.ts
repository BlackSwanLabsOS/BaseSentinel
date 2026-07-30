import { normalizeAddress, scanContract } from "../client.js";
import { BaseSentinelError, ErrorCode } from "../errors.js";
import {
  getApiBaseUrl,
  getPaymentProofOverride,
  payForScan,
} from "../payer.js";
import { summarizeScanResult } from "../summary.js";
import type { ElizaAction, ElizaMemory, HandlerCallback } from "../elizaTypes.js";

const ADDRESS_RE = /0x[a-fA-F0-9]{40}/;

function extractAddress(
  message: ElizaMemory,
  options?: Record<string, unknown>,
): string | null {
  const fromOptions =
    (typeof options?.address === "string" && options.address) ||
    (typeof options?.contractAddress === "string" && options.contractAddress) ||
    (typeof options?.contract_address === "string" &&
      options.contract_address) ||
    "";
  if (fromOptions) {
    const match = fromOptions.match(ADDRESS_RE);
    if (match) return match[0];
  }

  const text = message.content?.text ?? "";
  const match = text.match(ADDRESS_RE);
  return match ? match[0] : null;
}

/**
 * SCAN_CONTRACT — LLM sees only the risk summary.
 * Payment (USDC transfer + X-Payment-Proof) stays in the runtime.
 */
export const scanContractAction: ElizaAction = {
  name: "SCAN_CONTRACT",
  similes: [
    "CHECK_CONTRACT",
    "SCAN_TOKEN",
    "BASE_THREAT_SCAN",
    "CONTRACT_RISK_CHECK",
    "HONEYPOT_CHECK",
  ],
  description:
    "Scan a Base smart-contract address for scam / honeypot risk via BaseSentinel. Provide a 0x contract address. Returns status, verdict, score, and reasons.",
  validate: async (_runtime, message, _state) => {
    const text = message.content?.text ?? "";
    if (ADDRESS_RE.test(text)) return true;
    return /scan|honeypot|scam|risk|contract|token|safe\?/i.test(text);
  },
  handler: async (_runtime, message, _state, options, callback) => {
    const respond = async (payload: {
      text: string;
      success: boolean;
      error?: string;
      data?: unknown;
    }) => {
      if (callback) {
        await callback({
          text: payload.text,
          actions: ["SCAN_CONTRACT"],
          error: payload.error,
        });
      }
      return payload;
    };

    let address: string;
    try {
      const raw = extractAddress(message, options);
      if (!raw) {
        throw new BaseSentinelError(
          ErrorCode.INVALID_ADDRESS_FORMAT,
          "No Base contract address found. Include a 0x…40-hex address.",
          { httpStatus: 400 },
        );
      }
      address = normalizeAddress(raw);
    } catch (error) {
      const err =
        error instanceof BaseSentinelError
          ? error
          : new BaseSentinelError(
              ErrorCode.UNKNOWN,
              error instanceof Error ? error.message : "Invalid address",
            );
      return respond({
        success: false,
        text: `Scan failed: ${err.message}`,
        error: err.errorCode,
      });
    }

    try {
      const apiBaseUrl = getApiBaseUrl();
      const override = getPaymentProofOverride();
      const paymentProof =
        override ??
        (
          await payForScan({
            contractAddress: address,
            apiBaseUrl,
          })
        ).txHash;

      const result = await scanContract(address, paymentProof, { apiBaseUrl });
      const text = summarizeScanResult(result);
      return respond({ success: true, text, data: { result } });
    } catch (error) {
      if (error instanceof BaseSentinelError) {
        // Typed error_code for agent logic; LLM gets a short failure line (no secrets).
        return respond({
          success: false,
          text: `Scan failed (${error.errorCode}): ${error.message}`,
          error: error.errorCode,
          data: { error_code: error.errorCode, httpStatus: error.httpStatus },
        });
      }
      const messageText =
        error instanceof Error ? error.message : "Unknown scan failure";
      return respond({
        success: false,
        text: `Scan failed: ${messageText}`,
        error: ErrorCode.UNKNOWN,
      });
    }
  },
  examples: [
    [
      {
        name: "{{user1}}",
        content: {
          text: "Scan this Base contract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        },
      },
      {
        name: "{{agentName}}",
        content: {
          text: "Contract 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913 is SAFE (CLEAR). Score: 100/100. Reasons: Bluechip_Allowlist:USDC",
          actions: ["SCAN_CONTRACT"],
        },
      },
    ],
  ],
};

/** Re-export for tests / direct calls. */
export type { HandlerCallback };
