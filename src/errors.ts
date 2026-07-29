/**
 * Stable machine-readable API error codes (M2M contract).
 * Do not rename existing values — agents branch on these strings.
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
  INVALID_JSON: "INVALID_JSON",
  METHOD_NOT_ALLOWED: "METHOD_NOT_ALLOWED",
  NOT_FOUND: "NOT_FOUND",
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

export interface ApiErrorBody {
  error_code: ErrorCode;
  /** Human-readable explanation (optional for machines). */
  message: string;
  /** Backward-compatible alias of `message`. */
  error: string;
}

export function apiErrorBody(
  errorCode: ErrorCode,
  message: string,
): ApiErrorBody {
  return {
    error_code: errorCode,
    message,
    error: message,
  };
}

export function apiErrorResponse(
  errorCode: ErrorCode,
  message: string,
  status: number,
): Response {
  return Response.json(apiErrorBody(errorCode, message), { status });
}

/** True when an upstream/RPC failure looks like a timeout. */
export function isTimeoutMessage(message: string): boolean {
  return /timeout|timed out|aborted|deadline/i.test(message);
}
