/**
 * ERC-4337 / Account Abstraction addresses that explorers & GoPlus often
 * mislabel as a token "creator" (tx.from = bundler, not the real deployer).
 * Used to soft-ignore GoPlus honeypot_with_same_creator FPs (e.g. Zora coins).
 */

/** Lowercase addresses. */
const AA_MISATTRIBUTED_CREATORS = new Set<string>([
  // EntryPoint v0.6
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",
  // EntryPoint v0.7
  "0x0000000071727de22e5e9d8baf0edac6f37da032",
  // EntryPoint v0.8 (canonical CREATE2 when present)
  "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",
  // Hot Base bundler (Coinbase Smart Wallet / AA infra) — GoPlus FP on Zora
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
 * Soft-ignore GoPlus honeypot_with_same_creator when the attributed creator
 * is AA infra, or when a Zora listing pairs with that misattribution.
 */
export function shouldIgnoreGoPlusPriorHoneypot(opts: {
  creatorAddress?: string | null;
  honeypotWithSameCreator?: boolean | null;
  listingSource?: string | null;
}): boolean {
  if (opts.honeypotWithSameCreator !== true) return false;
  if (isAaMisattributedCreator(opts.creatorAddress)) return true;

  // Extra belt: Zora coin listings + AA creator already covered above.
  // Keep listing hook for future bundlers we add to the set.
  const listing = (opts.listingSource || "").toLowerCase();
  if (
    listing.startsWith("zora") &&
    isAaMisattributedCreator(opts.creatorAddress)
  ) {
    return true;
  }

  return false;
}
