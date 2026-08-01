import type { ScanResult } from "./client.js";

/**
 * Short LLM-facing summary — no payment / tx details.
 */
export function summarizeScanResult(result: ScanResult): string {
  const address = result.address || "unknown";
  const status = result.status || "UNKNOWN";
  const verdict = result.verdict || "UNKNOWN";
  const score =
    typeof result.verdict_score === "number" ? result.verdict_score : "?";
  const reasons = Array.isArray(result.reasons)
    ? result.reasons.filter(Boolean)
    : [];
  const reasonText = reasons.length > 0 ? reasons.join(", ") : "None";
  const attribution =
    result.creator_attribution === "aa_bundler_mislabel"
      ? " Creator attribution: AA bundler mislabel (not a safe-token signal)."
      : "";

  return `Contract ${address} is ${status} (${verdict}). Score: ${score}/100. Reasons: ${reasonText}.${attribution}`;
}
