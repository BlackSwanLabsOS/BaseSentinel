/**
 * ERC-4337 / Account Abstraction addresses that explorers & GoPlus often
 * mislabel as a token "creator" (tx.from = bundler, not the real deployer).
 * Verified allowlist: when GoPlus sets honeypot_with_same_creator on these,
 * we treat it as yellow (SUSPICIOUS) with an AA/bundler label — not hard SCAM.
 */

/** Machine value on scan/dossier when GoPlus creator is AA infra, not the rugger. */
export type CreatorAttribution = "aa_bundler_mislabel";

/** Lowercase addresses. */
const AA_MISATTRIBUTED_CREATORS = new Set<string>([
  // EntryPoint v0.6
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",
  // EntryPoint v0.7
  "0x0000000071727de22e5e9d8baf0edac6f37da032",
  // EntryPoint v0.8 (canonical CREATE2 when present)
  "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",
  // Hot Base bundler (Coinbase Smart Wallet / AA infra) — GoPlus false positive on Zora
  "0x048ef1062cbb39b338ac2685da72adf104b4cef5",
]);

function normalizeAddress(address: string | null | undefined): string | null {
  if (!address || typeof address !== "string") return null;
  const t = address.trim().toLowerCase();
  if (!/^0x[a-f0-9]{40}$/.test(t)) return null;
  return t;
}

/** True when GoPlus "creator" is almost certainly AA infrastructure, not a rugger. */
export function isAaMisattributedCreator(
  address: string | null | undefined,
): boolean {
  const n = normalizeAddress(address);
  return n !== null && AA_MISATTRIBUTED_CREATORS.has(n);
}

/**
 * True when GoPlus prior-honeypot should NOT force SCAM — creator is on our
 * verified AA/bundler/EntryPoint list (common Zora / smart-wallet mislabel).
 */
export function shouldIgnoreGoPlusPriorHoneypot(opts: {
  creatorAddress?: string | null;
  honeypotWithSameCreator?: boolean | null;
  listingSource?: string | null;
}): boolean {
  if (opts.honeypotWithSameCreator !== true) return false;
  if (isAaMisattributedCreator(opts.creatorAddress)) return true;

  // Listing hook reserved for future source-specific AA rules.
  void opts.listingSource;
  return false;
}

/**
 * Agent-facing attribution hint from risk_flags.
 * `aa_bundler_mislabel` ≠ safe token — only: ignore GoPlus prior-honeypot-on-creator.
 */
export function resolveCreatorAttribution(
  riskFlags: readonly string[],
): CreatorAttribution | null {
  return riskFlags.includes("AA_BUNDLER_CREATOR")
    ? "aa_bundler_mislabel"
    : null;
}

/**
 * True when the address itself is AA EntryPoint / bundler infra
 * (same allowlist as creator mislabel). Do not autopsy these as "scam tokens".
 */
export function isAaInfrastructureAddress(
  address: string | null | undefined,
): boolean {
  return isAaMisattributedCreator(address);
}
