import type { Env } from "../types";
import { scanContract, type ScanResult } from "./scanner";
import {
  analyzeMarketStructure,
  type MarketStructure,
} from "./marketStructure";
import { buildVerdict } from "./verdict";
import { resolveCreatorAttribution } from "../config/aaInfrastructure";

export interface DossierResult {
  address: string;
  network: string;
  verdict: ScanResult["verdict"];
  verdict_score: number;
  risk_flags: string[];
  /** Same meaning as on /scan — AA creator mislabel hint for agents. */
  creator_attribution: ScanResult["creator_attribution"];
  market_structure: MarketStructure;
  security: ScanResult;
}

/** Premium dossier: security scan + market structure. */
export async function buildPremiumDossier(
  contractAddress: string,
  env: Env,
  options: { bypassCache?: boolean } = {},
): Promise<DossierResult> {
  const security = await scanContract(contractAddress, env, {
    bypassCache: options.bypassCache,
    rpcTier: "critical",
  });
  const market_structure = await analyzeMarketStructure(env, security);

  // Recompute verdict with concentration flags included.
  const enriched = buildVerdict({
    status: security.status,
    riskScore: security.riskScore,
    reasons: security.reasons,
    goplus: security.dossier.goplus,
    honeypotIs: security.dossier.honeypotIs,
    dualSourceConsensus: security.dossier.dualSourceConsensus,
    listingSource: security.dossier.listing?.source ?? null,
    deployerBalancePct: market_structure.deployer_balance_pct,
    top5HoldersPct: market_structure.top_5_holders_pct,
  });
  const creator_attribution = resolveCreatorAttribution(enriched.risk_flags);

  return {
    address: security.address,
    network: security.network,
    verdict: enriched.verdict,
    verdict_score: enriched.verdict_score,
    risk_flags: enriched.risk_flags,
    creator_attribution,
    market_structure,
    security: {
      ...security,
      verdict: enriched.verdict,
      verdict_score: enriched.verdict_score,
      risk_flags: enriched.risk_flags,
      creator_attribution,
    },
  };
}
