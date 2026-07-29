/**
 * Public marketing / discovery copy about what BaseSentinel detects.
 * Names enrichment providers + launch coverage — never factory contract addresses.
 */

export const PUBLIC_INTEL_SUMMARY =
  "Multi-source Base threat intel: local bytecode heuristics, GoPlus token security, and honeypot.is buy/sell simulation with dual-source consensus. Continuous coverage of Uniswap V2/V3, Aerodrome, Clanker, and Virtuals bonding launches. Returns SAFE / SUSPICIOUS / SCAM plus agent verdict CLEAR / CAUTION / AVOID.";

export const PUBLIC_INTEL_SHORT =
  "Bytecode heuristics + GoPlus + honeypot.is (dual-source consensus). Watches Uni V2/V3, Aerodrome, Clanker, and Virtuals launches on Base. Agent verdict: CLEAR/CAUTION/AVOID.";

/** Machine-readable block for x402 / agent catalogs (no contract addresses). */
export const PUBLIC_INTEL_CAPABILITIES = {
  chain: "Base (eip155:8453)",
  verdicts: ["SAFE", "SUSPICIOUS", "SCAM"] as const,
  agent_verdicts: ["CLEAR", "CAUTION", "AVOID"] as const,
  enrichment_providers: [
    "local_bytecode_heuristics",
    "goplus_token_security",
    "honeypot_is_simulation",
  ] as const,
  consensus: "dual_source_goplus_and_honeypot_is",
  discovery_coverage: [
    "uniswap_v2",
    "uniswap_v3",
    "aerodrome",
    "clanker",
    "virtuals_bonding",
  ] as const,
  dossier_fields: [
    "goplus",
    "honeypotIs",
    "listing",
    "dualSourceConsensus",
  ] as const,
  premium_market_structure: [
    "deployer_balance_pct",
    "top_5_holders_pct",
    "lp_status",
    "is_whale_concentrated",
  ] as const,
};
