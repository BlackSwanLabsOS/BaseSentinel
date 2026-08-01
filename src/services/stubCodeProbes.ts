import type { Env } from "../types";
import { logsRpc } from "./alchemy";
import {
  MIN_BYTECODE_HEX_LENGTH,
  RISK_SCAM,
  type AnalysisResult,
  statusFromScore,
} from "./analyzer";

/** ERC-20 / AccessControl view selectors used for stub probes. */
const SEL = {
  name: "0x06fdde03",
  symbol: "0x95d89b41",
  totalSupply: "0x18160ddd",
  /** PAUSE_ROLE() — AccessControl role constant (MoonBase-style kits). */
  pauseRole: "0x389ed267",
  /** OPERATOR_ROLE() */
  operatorRole: "0xf5b541a6",
  /** isPaused(uint8 feature) with feature=0 */
  isPaused0:
    "0xbc61e7330000000000000000000000000000000000000000000000000000000000000000",
} as const;

export interface StubAdminProbeResult {
  /** getCode is empty / below threshold / only reserved prefix. */
  minimalBytecode: boolean;
  /** Deployed code is exactly or starts with EIP-3541 / EOF magic 0xef. */
  reservedEofPrefix: boolean;
  nameOk: boolean;
  symbolOk: boolean;
  totalSupplyOk: boolean;
  /** True when name+symbol+totalSupply all answered without revert. */
  erc20ViewsLive: boolean;
  pauseRoleOk: boolean;
  operatorRoleOk: boolean;
  isPausedOk: boolean;
  /** Any admin/policy constant or isPaused answered. */
  adminPolicySurface: boolean;
}

export function normalizeCodeHex(bytecode: string): string {
  return (bytecode ?? "").trim().toLowerCase().replace(/^0x/, "");
}

export function isMinimalBytecode(bytecode: string): boolean {
  const hex = normalizeCodeHex(bytecode);
  return !hex || hex === "0" || hex.length < MIN_BYTECODE_HEX_LENGTH;
}

export function hasReservedEofPrefix(bytecode: string): boolean {
  const hex = normalizeCodeHex(bytecode);
  return hex === "ef" || hex.startsWith("ef");
}

function callSucceeded(raw: string | null | undefined): boolean {
  if (!raw || raw === "0x" || raw === "0x0") return false;
  // Reverts sometimes come back as short payloads; require ≥32 bytes of data.
  return raw.length >= 66;
}

async function ethCall(
  env: Env,
  to: string,
  data: string,
): Promise<string | null> {
  try {
    return await logsRpc<string>(env, "eth_call", [{ to, data }, "latest"]);
  } catch {
    return null;
  }
}

/**
 * When getCode looks empty/minimal, probe whether the address still behaves
 * like a live token / AccessControl kit (hidden / stub bytecode pattern).
 * Cheap: only runs for minimal code; a handful of eth_calls in parallel.
 */
export async function probeStubAndAdminSurface(
  env: Env,
  contractAddress: string,
  bytecode: string,
): Promise<StubAdminProbeResult | null> {
  const minimalBytecode = isMinimalBytecode(bytecode);
  const reservedEofPrefix = hasReservedEofPrefix(bytecode);
  if (!minimalBytecode && !reservedEofPrefix) {
    return null;
  }

  const address = contractAddress.toLowerCase();
  const [nameRaw, symbolRaw, supplyRaw, pauseRaw, operatorRaw, pausedRaw] =
    await Promise.all([
      ethCall(env, address, SEL.name),
      ethCall(env, address, SEL.symbol),
      ethCall(env, address, SEL.totalSupply),
      ethCall(env, address, SEL.pauseRole),
      ethCall(env, address, SEL.operatorRole),
      ethCall(env, address, SEL.isPaused0),
    ]);

  const nameOk = callSucceeded(nameRaw);
  const symbolOk = callSucceeded(symbolRaw);
  const totalSupplyOk = callSucceeded(supplyRaw);
  const pauseRoleOk = callSucceeded(pauseRaw);
  const operatorRoleOk = callSucceeded(operatorRaw);
  const isPausedOk = callSucceeded(pausedRaw);

  return {
    minimalBytecode,
    reservedEofPrefix,
    nameOk,
    symbolOk,
    totalSupplyOk,
    erc20ViewsLive: nameOk && symbolOk && totalSupplyOk,
    pauseRoleOk,
    operatorRoleOk,
    isPausedOk,
    adminPolicySurface: pauseRoleOk || operatorRoleOk || isPausedOk,
  };
}

/**
 * Merge stub / admin-policy probes into local bytecode analysis.
 * True empty EOA stays yellow; live views behind 0xef → hard risk.
 */
export function applyStubAdminProbes(
  local: AnalysisResult,
  probes: StubAdminProbeResult | null,
): AnalysisResult {
  if (!probes) return local;

  const reasons = local.reasons.filter(
    (r) => r !== "None" && r !== "Empty_Or_EOA_No_Bytecode",
  );
  let riskScore = local.riskScore;

  if (probes.reservedEofPrefix) {
    reasons.push("Eof_Or_Reserved_Bytecode_Prefix");
  }

  if (probes.erc20ViewsLive) {
    reasons.push("Stub_Or_Hidden_Bytecode");
    // Live token API with missing/opaque runtime code — treat as hard risk.
    riskScore = Math.max(riskScore, RISK_SCAM + 5);
  } else if (probes.minimalBytecode) {
    // Still no live ERC-20 surface — keep soft empty/EOA band.
    reasons.push("Empty_Or_EOA_No_Bytecode");
    riskScore = Math.max(riskScore, 55);
    if (probes.reservedEofPrefix) {
      riskScore = Math.max(riskScore, 60);
    }
  }

  if (probes.adminPolicySurface) {
    reasons.push("Admin_Policy_Surface_Detected");
    riskScore = Math.max(riskScore, probes.erc20ViewsLive ? 85 : 70);
  }

  const cleaned = [...new Set(reasons)];
  if (cleaned.length === 0) cleaned.push("None");
  const score = Math.max(0, Math.min(100, Math.round(riskScore)));

  return {
    status: statusFromScore(score),
    riskScore: score,
    reasons: cleaned,
  };
}
