/**
 * Stable BaseSentinel API error_code values (mirror of Worker contract).
 * Branch on these — do not invent aliases.
 */
export const ErrorCode = {
  PAYMENT_REQUIRED: "PAYMENT_REQUIRED",
  INVALID_ADDRESS_FORMAT: "INVALID_ADDRESS_FORMAT",
  INVALID_PROOF_FORMAT: "INVALID_PROOF_FORMAT",
  TX_HASH_CONSUMED: "TX_HASH_CONSUMED",
  TX_HASH_BOUND_OTHER: "TX_HASH_BOUND_OTHER",
  INSUFFICIENT_USDC: "INSUFFICIENT_USDC",
  PAYMENT_INVALID: "PAYMENT_INVALID",
  UPSTREAM_TIMEOUT: "UPSTREAM_TIMEOUT",
  KV_LIMIT_EXCEEDED: "KV_LIMIT_EXCEEDED",
  INVALID_JSON: "INVALID_JSON",
  METHOD_NOT_ALLOWED: "METHOD_NOT_ALLOWED",
  NOT_FOUND: "NOT_FOUND",
  UNKNOWN: "UNKNOWN",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export interface ApiErrorBody {
  error_code?: string;
  message?: string;
  error?: string;
  payment_info?: PaymentInfo;
}

export interface PaymentInfo {
  product?: string;
  network?: string;
  token?: string;
  recipient?: string;
  amount?: string;
  amount_display?: string;
  decimals?: number;
}

/** Typed client/runtime failure for agent catch branches. */
export class BaseSentinelError extends Error {
  readonly errorCode: ErrorCode;
  readonly httpStatus: number;
  readonly paymentInfo: PaymentInfo | null;
  readonly body: unknown;

  constructor(
    errorCode: ErrorCode,
    message: string,
    options: {
      httpStatus?: number;
      paymentInfo?: PaymentInfo | null;
      body?: unknown;
      cause?: unknown;
    } = {},
  ) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "BaseSentinelError";
    this.errorCode = errorCode;
    this.httpStatus = options.httpStatus ?? 0;
    this.paymentInfo = options.paymentInfo ?? null;
    this.body = options.body ?? null;
  }
}

export function normalizeErrorCode(raw: unknown): ErrorCode {
  if (typeof raw !== "string") return ErrorCode.UNKNOWN;
  const values = Object.values(ErrorCode) as string[];
  return (values.includes(raw) ? raw : ErrorCode.UNKNOWN) as ErrorCode;
}
