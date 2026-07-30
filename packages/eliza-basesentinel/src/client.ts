import {
  DEFAULT_API_BASE_URL,
  PAYMENT_PROOF_HEADER,
} from "./constants.js";
import {
  BaseSentinelError,
  ErrorCode,
  normalizeErrorCode,
  type ApiErrorBody,
  type PaymentInfo,
} from "./errors.js";

export interface ScanResult {
  address: string;
  network: string;
  status: string;
  riskScore: number;
  reasons: string[];
  verdict: string;
  verdict_score: number;
  risk_flags: string[];
  [key: string]: unknown;
}

export interface ScanClientOptions {
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
}

function stripSlash(url: string): string {
  return url.replace(/\/$/, "");
}

function isAddressLike(value: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(value);
}

export function normalizeAddress(raw: string): string {
  const trimmed = raw.trim();
  if (!isAddressLike(trimmed)) {
    throw new BaseSentinelError(
      ErrorCode.INVALID_ADDRESS_FORMAT,
      `Invalid smart contract address: ${raw}`,
      { httpStatus: 400 },
    );
  }
  return trimmed.toLowerCase();
}

async function parseJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new BaseSentinelError(
      ErrorCode.INVALID_JSON,
      "API returned non-JSON body",
      { httpStatus: res.status, body: text },
    );
  }
}

/**
 * Probe /scan without proof — expect HTTP 402 + payment_info.
 * Useful to discover recipient/amount from the live API.
 */
export async function probePaymentRequired(
  address: string,
  options: ScanClientOptions = {},
): Promise<PaymentInfo> {
  const normalized = normalizeAddress(address);
  const base = stripSlash(options.apiBaseUrl ?? DEFAULT_API_BASE_URL);
  const fetchImpl = options.fetchImpl ?? fetch;
  const res = await fetchImpl(`${base}/scan/${normalized}`, { method: "GET" });
  const body = (await parseJson(res)) as ApiErrorBody | null;

  if (res.status === 402 || body?.error_code === ErrorCode.PAYMENT_REQUIRED) {
    if (body?.payment_info) return body.payment_info;
    throw new BaseSentinelError(
      ErrorCode.PAYMENT_REQUIRED,
      "Payment required but payment_info missing",
      { httpStatus: res.status, body },
    );
  }

  throw new BaseSentinelError(
    normalizeErrorCode(body?.error_code),
    body?.message ?? body?.error ?? `Unexpected probe status ${res.status}`,
    { httpStatus: res.status, body, paymentInfo: body?.payment_info ?? null },
  );
}

/**
 * Paid scan: GET /scan/{address} with X-Payment-Proof.
 */
export async function scanContract(
  address: string,
  paymentProof: string,
  options: ScanClientOptions = {},
): Promise<ScanResult> {
  const normalized = normalizeAddress(address);
  const proof = paymentProof.trim();
  if (!/^0x[a-fA-F0-9]{64}$/.test(proof)) {
    throw new BaseSentinelError(
      ErrorCode.INVALID_PROOF_FORMAT,
      "Invalid payment proof format. Expected a transaction hash (0x + 64 hex).",
      { httpStatus: 400 },
    );
  }

  const base = stripSlash(options.apiBaseUrl ?? DEFAULT_API_BASE_URL);
  const fetchImpl = options.fetchImpl ?? fetch;

  let res: Response;
  try {
    res = await fetchImpl(`${base}/scan/${normalized}`, {
      method: "GET",
      headers: { [PAYMENT_PROOF_HEADER]: proof },
    });
  } catch (cause) {
    throw new BaseSentinelError(
      ErrorCode.UPSTREAM_TIMEOUT,
      "Failed to reach BaseSentinel API",
      { httpStatus: 502, cause },
    );
  }

  const body = await parseJson(res);

  if (!res.ok) {
    const err = (body ?? {}) as ApiErrorBody;
    const code =
      res.status === 402
        ? ErrorCode.PAYMENT_REQUIRED
        : normalizeErrorCode(err.error_code);
    throw new BaseSentinelError(
      code,
      err.message ?? err.error ?? `BaseSentinel scan failed (HTTP ${res.status})`,
      {
        httpStatus: res.status,
        body,
        paymentInfo: err.payment_info ?? null,
      },
    );
  }

  const result = body as ScanResult;
  if (!result || typeof result !== "object" || !result.status) {
    throw new BaseSentinelError(
      ErrorCode.INVALID_JSON,
      "Scan response missing status",
      { httpStatus: res.status, body },
    );
  }
  return result;
}
