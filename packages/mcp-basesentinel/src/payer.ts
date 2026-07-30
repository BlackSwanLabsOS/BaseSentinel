import {
  DEFAULT_API_BASE_URL,
  ENV,
  SCAN_AMOUNT_ATOMIC,
  TREASURY_ADDRESS,
  USDC_ADDRESS,
} from "./constants.js";
import { BaseSentinelError, ErrorCode, type PaymentInfo } from "./errors.js";
import { probePaymentRequired } from "./client.js";

export interface PayForScanOptions {
  /** 0x-prefixed private key (runtime secret). */
  privateKey?: string;
  /** Override API base for payment_info probe. */
  apiBaseUrl?: string;
  /** Optional custom Base RPC (Alchemy / public). */
  rpcUrl?: string;
  /** Skip probe and use fallbacks. */
  skipProbe?: boolean;
  /** Contract being scanned — used for probe URL. */
  contractAddress: string;
}

export interface PaymentSettlement {
  txHash: `0x${string}`;
  recipient: `0x${string}`;
  token: `0x${string}`;
  amountAtomic: bigint;
}

function readEnv(name: string): string | undefined {
  if (typeof process === "undefined" || !process.env) return undefined;
  const value = process.env[name]?.trim();
  return value || undefined;
}

function normalizePrivateKey(raw: string): `0x${string}` {
  const key = raw.trim();
  if (!/^0x[a-fA-F0-9]{64}$/.test(key)) {
    throw new BaseSentinelError(
      ErrorCode.PAYMENT_INVALID,
      "BASESENTINEL_PRIVATE_KEY must be 0x + 64 hex characters",
      { httpStatus: 400 },
    );
  }
  return key as `0x${string}`;
}

function asAddress(value: string, label: string): `0x${string}` {
  if (!/^0x[a-fA-F0-9]{40}$/.test(value)) {
    throw new BaseSentinelError(
      ErrorCode.PAYMENT_INVALID,
      `Invalid ${label} address from payment_info`,
      { httpStatus: 422 },
    );
  }
  return value as `0x${string}`;
}

function termsFromPaymentInfo(info: PaymentInfo | null): {
  recipient: `0x${string}`;
  token: `0x${string}`;
  amountAtomic: bigint;
  paymentInfo: PaymentInfo | null;
} {
  const recipient = asAddress(info?.recipient ?? TREASURY_ADDRESS, "recipient");
  const token = asAddress(info?.token ?? USDC_ADDRESS, "token");
  const amountAtomic =
    info?.amount && /^\d+$/.test(info.amount)
      ? BigInt(info.amount)
      : SCAN_AMOUNT_ATOMIC;
  if (amountAtomic < SCAN_AMOUNT_ATOMIC) {
    throw new BaseSentinelError(
      ErrorCode.INSUFFICIENT_USDC,
      `payment_info.amount ${amountAtomic} below scan minimum ${SCAN_AMOUNT_ATOMIC}`,
      { httpStatus: 422, paymentInfo: info },
    );
  }
  return { recipient, token, amountAtomic, paymentInfo: info };
}

/**
 * Resolve payTo / amount from live 402 payment_info, else known constants.
 */
export async function resolvePaymentTerms(
  contractAddress: string,
  options: { apiBaseUrl?: string; skipProbe?: boolean } = {},
): Promise<{
  recipient: `0x${string}`;
  token: `0x${string}`;
  amountAtomic: bigint;
  paymentInfo: PaymentInfo | null;
}> {
  if (!options.skipProbe) {
    try {
      const info = await probePaymentRequired(contractAddress, {
        apiBaseUrl: options.apiBaseUrl,
      });
      return termsFromPaymentInfo(info);
    } catch {
      // Fall back to hardcoded production constants.
    }
  }

  return termsFromPaymentInfo(null);
}

/**
 * Transfer USDC on Base to treasury and wait for a successful receipt.
 * Returns the tx hash for X-Payment-Proof.
 */
export async function payForScan(
  options: PayForScanOptions,
): Promise<PaymentSettlement> {
  const { createPublicClient, createWalletClient, erc20Abi, http } =
    await import("viem");
  const { privateKeyToAccount } = await import("viem/accounts");
  const { base } = await import("viem/chains");

  const privateKeyRaw =
    options.privateKey?.trim() || readEnv(ENV.privateKey) || "";
  if (!privateKeyRaw) {
    throw new BaseSentinelError(
      ErrorCode.PAYMENT_INVALID,
      `Missing ${ENV.privateKey} (runtime wallet for M2M payment)`,
      { httpStatus: 400 },
    );
  }

  const privateKey = normalizePrivateKey(privateKeyRaw);
  const account = privateKeyToAccount(privateKey);
  const rpcUrl =
    options.rpcUrl?.trim() ||
    readEnv(ENV.rpcUrl) ||
    "https://mainnet.base.org";

  const terms = await resolvePaymentTerms(options.contractAddress, {
    apiBaseUrl: options.apiBaseUrl,
    skipProbe: options.skipProbe,
  });

  const publicClient = createPublicClient({
    chain: base,
    transport: http(rpcUrl),
  });

  const walletClient = createWalletClient({
    account,
    chain: base,
    transport: http(rpcUrl),
  });

  let txHash: `0x${string}`;
  try {
    txHash = await walletClient.writeContract({
      address: terms.token,
      abi: erc20Abi,
      functionName: "transfer",
      args: [terms.recipient, terms.amountAtomic],
      account,
      chain: base,
    });
  } catch (cause) {
    const message =
      cause instanceof Error ? cause.message : "USDC transfer failed";
    const code = /insufficient|exceeds balance|transfer amount exceeds/i.test(
      message,
    )
      ? ErrorCode.INSUFFICIENT_USDC
      : ErrorCode.PAYMENT_INVALID;
    throw new BaseSentinelError(code, message, {
      httpStatus: 422,
      cause,
      paymentInfo: terms.paymentInfo,
    });
  }

  const receipt = await publicClient.waitForTransactionReceipt({
    hash: txHash,
    confirmations: 1,
  });

  if (receipt.status !== "success") {
    throw new BaseSentinelError(
      ErrorCode.PAYMENT_INVALID,
      `USDC transfer reverted: ${txHash}`,
      { httpStatus: 422, paymentInfo: terms.paymentInfo },
    );
  }

  return {
    txHash,
    recipient: terms.recipient,
    token: terms.token,
    amountAtomic: terms.amountAtomic,
  };
}

/** Ops override: use an existing tx hash and skip the wallet spend. */
export function getPaymentProofOverride(): string | null {
  return readEnv(ENV.paymentProof) ?? null;
}

export function getApiBaseUrl(): string {
  return readEnv(ENV.apiBaseUrl) ?? DEFAULT_API_BASE_URL;
}
