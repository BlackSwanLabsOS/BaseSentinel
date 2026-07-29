import type { Env } from "../types";
import { scanContract, type ScanResult } from "./scanner";
import {
  analyzeMarketStructure,
  type MarketStructure,
} from "./marketStructure";
import { buildVerdict } from "./verdict";

export interface DossierResult {
  address: string;
  network: string;
  verdict: ScanResult["verdict"];
  verdict_score: number;
  risk_flags: string[];
  market_structure: MarketStructure;
  security: ScanResult;
}

/**
 * Premium dossier: security scan + market structure (holders / LP heuristics).
 */
export async function buildPremiumDossier(
  contractAddress: string,
  env: Env,
): Promise<DossierResult> {
  const security = await scanContract(contractAddress, env);
  const market_structure = await analyzeMarketStructure(env, security);

  // Recompute verdict with concentration flags so agents see DEPLOYER_HOLDS_SUPPLY etc.
  const enriched = buildVerdict({
    status: security.status,
    riskScore: security.riskScore,
    reasons: security.reasons,
    goplus: security.dossier.goplus,
    honeypotIs: security.dossier.honeypotIs,
    dualSourceConsensus: security.dossier.dualSourceConsensus,
    deployerBalancePct: market_structure.deployer_balance_pct,
    top5HoldersPct: market_structure.top_5_holders_pct,
  });

  return {
    address: security.address,
    network: security.network,
    verdict: enriched.verdict,
    verdict_score: enriched.verdict_score,
    risk_flags: enriched.risk_flags,
    market_structure,
    security: {
      ...security,
      verdict: enriched.verdict,
      verdict_score: enriched.verdict_score,
      risk_flags: enriched.risk_flags,
    },
  };
}
