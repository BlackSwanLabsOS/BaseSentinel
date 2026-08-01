import { scanContractAction } from "./actions/scanContract.js";
import type { ElizaPlugin } from "./elizaTypes.js";

export {
  DEFAULT_API_BASE_URL,
  USDC_ADDRESS,
  TREASURY_ADDRESS,
  SCAN_AMOUNT_ATOMIC,
  SCAN_AMOUNT_DISPLAY,
  ENV,
} from "./constants.js";

export {
  BaseSentinelError,
  ErrorCode,
  type ApiErrorBody,
  type PaymentInfo,
} from "./errors.js";

export {
  scanContract,
  probePaymentRequired,
  normalizeAddress,
  type ScanResult,
} from "./client.js";

export {
  payForScan,
  resolvePaymentTerms,
  getPaymentProofOverride,
  getApiBaseUrl,
  type PaymentSettlement,
} from "./payer.js";

export { summarizeScanResult } from "./summary.js";
export { scanContractAction } from "./actions/scanContract.js";

/**
 * Eliza OS plugin — register on AgentRuntime.plugins.
 *
 * Runtime secrets (not for the LLM):
 * - BASESENTINEL_PRIVATE_KEY — Base wallet with USDC
 * - BASESENTINEL_PAYMENT_PROOF — optional existing tx hash (skip spend)
 * - BASESENTINEL_RPC_URL — optional Base RPC
 * - BASESENTINEL_API_BASE_URL — optional API override
 */
export const baseSentinelPlugin: ElizaPlugin = {
  name: "basesentinel",
  description:
    "Scan Base smart contracts for scam/honeypot risk via BaseSentinel (0.005 USDC per scan).",
  actions: [scanContractAction],
  providers: [],
  evaluators: [],
  services: [],
};

export default baseSentinelPlugin;
