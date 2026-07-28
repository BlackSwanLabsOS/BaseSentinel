import type { Env } from "../types";

export type NetworkId = "base-sepolia" | "base";

/** Official Circle USDC contracts (6 decimals). */
export const USDC_BY_NETWORK: Record<NetworkId, string> = {
  // Correct Circle Sepolia address — Gemini's prompt had a typo here.
  "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  base: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
};

const ALCHEMY_RPC_BY_NETWORK: Record<NetworkId, string> = {
  "base-sepolia": "https://base-sepolia.g.alchemy.com/v2",
  base: "https://base-mainnet.g.alchemy.com/v2",
};

/** CAIP-2 chain IDs used by x402. */
const CAIP2_BY_NETWORK: Record<NetworkId, string> = {
  "base-sepolia": "eip155:84532",
  base: "eip155:8453",
};

/** Uniswap V2 factories used to discover newly listed tokens. */
export const UNISWAP_V2_FACTORY_BY_NETWORK: Record<NetworkId, string> = {
  "base-sepolia": "0x7Ae58f10f7849cA6F5fB71b7f45CB416c9204b1e",
  base: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
};

/** Canonical WETH on Base / Base Sepolia. */
export const WETH_BY_NETWORK: Record<NetworkId, string> = {
  "base-sepolia": "0x4200000000000000000000000000000000000006",
  base: "0x4200000000000000000000000000000000000006",
};

const DEFAULT_NETWORK: NetworkId = "base-sepolia";

export function resolveNetwork(env: Pick<Env, "NETWORK">): NetworkId {
  const value = env.NETWORK?.trim().toLowerCase();

  if (value === "base" || value === "base-mainnet") {
    return "base";
  }

  if (value === "base-sepolia" || value === "sepolia") {
    return "base-sepolia";
  }

  return DEFAULT_NETWORK;
}

export function getUsdcContractAddress(network: NetworkId): string {
  return USDC_BY_NETWORK[network];
}

export function getAlchemyRpcBase(network: NetworkId): string {
  return ALCHEMY_RPC_BY_NETWORK[network];
}

export function getCaip2Network(network: NetworkId): string {
  return CAIP2_BY_NETWORK[network];
}

export function getUniswapV2Factory(network: NetworkId): string {
  return UNISWAP_V2_FACTORY_BY_NETWORK[network];
}

export function getWethAddress(network: NetworkId): string {
  return WETH_BY_NETWORK[network];
}

/** Numeric chain id for GoPlus / explorers. */
export function getGoPlusChainId(network: NetworkId): number {
  return network === "base" ? 8453 : 84532;
}
