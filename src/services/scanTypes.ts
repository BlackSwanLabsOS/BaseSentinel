import type { GoPlusTokenFlags } from "./goplus";
import type { HoneypotIsFlags } from "./honeypotIs";

/** Where / how the token was first seen by BaseSentinel discovery. */
export interface ListingContext {
  source: string;
  pair: string;
  pairedWith: string;
  txHash: string;
  blockNumber: number;
}

export interface ScanDossier {
  /** Compact GoPlus signals (null if enrichment failed). */
  goplus: Omit<GoPlusTokenFlags, "rawAvailable"> | null;
  /** Compact honeypot.is simulation signals (null if failed / unsupported chain). */
  honeypotIs: Omit<HoneypotIsFlags, "rawAvailable"> | null;
  /** Present when scan came from cron discovery (null for ad-hoc paid scans). */
  listing: ListingContext | null;
  /** Optional latency metadata. */
  ageHintSeconds: number | null;
  /** True when GoPlus + honeypot.is both flagged honeypot/can't-sell. */
  dualSourceConsensus: boolean;
}
