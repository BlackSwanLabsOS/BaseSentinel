import type { Env } from "../types";
import type { NetworkId } from "./network";

/**
 * Factories / launchers we watch for newly listed tokens on Base.
 * Classic AMM PairCreated/PoolCreated + meme launchers (Clanker v4, Virtuals Bonding).
 * Addresses verified live on Base mainnet (2026) — older Clanker v3.x factories are dead.
 */
export type DexEventKind =
  | "univ2_pair_created"
  | "aero_pool_created"
  | "univ3_pool_created"
  | "clanker_token_created"
  | "virtuals_launched"
  | "virtuals_graduated"
  | "zora_coin_created";

export interface DexFactorySource {
  id: string;
  label: string;
  kind: DexEventKind;
  /** Factory contract that emits create events. */
  address: string;
  /** Event topic0. */
  topic: string;
  /**
   * When false, skipped by discovery (no eth_getLogs).
   * Toggle after `npm run analyze:factories -- --hours=24`.
   */
  enabled: boolean;
}

/** Uniswap V2 PairCreated(address,address,address,uint256) */
export const TOPIC_UNIV2_PAIR_CREATED =
  "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9";

/**
 * Aerodrome PoolCreated(address,address,bool,address,uint256)
 * Note: `stable` is indexed (topics[3]).
 */
export const TOPIC_AERO_POOL_CREATED =
  "0x2128d88d14c80cb081c1252a5acff7a264671bf199ce226b53788fb26065005e";

/** Uniswap V3 PoolCreated(address,address,uint24,int24,address) */
export const TOPIC_UNIV3_POOL_CREATED =
  "0x783cca1c0412dd0d695e784568c96da2e9c04bacab8a4ba816bd480ae4cafd0";

/**
 * Clanker v4 TokenCreated(
 *   address msgSender,
 *   address indexed tokenAddress,
 *   address indexed tokenAdmin,
 *   string, string, string, string, string,
 *   int24, address poolHook, bytes32 poolId,
 *   address pairedToken, address locker, address mevModule,
 *   uint256, address[]
 * )
 * Factory: 0xE85A59c628F7d27878ACeB4bf3b35733630083a9 (Base mainnet, active 2026).
 */
export const TOPIC_CLANKER_TOKEN_CREATED =
  "0x9299d1d1a88d8e1abdc591ae7a167a6bc63a8f17d695804e9091ee33aa89fb67";

/**
 * Virtuals Bonding Proxy Launched(address indexed token, address indexed pair, uint256)
 * Proxy: 0xF66DeA7b3e897cD44A5a231c61B6B4423d613259 (Base, verified 2026 via live launch tx).
 */
export const TOPIC_VIRTUALS_LAUNCHED =
  "0x714aa39317ad9a7a7a99db52b44490da5d068a0b2710fffb1a1282ad3cadae1f";

/**
 * Virtuals Bonding Graduated(address indexed token, address agentToken)
 * agentToken (official Agent ERC20) is in data word0; topics[1] is the fun/bonding token.
 */
export const TOPIC_VIRTUALS_GRADUATED =
  "0x381d54fa425631e6266af114239150fae1d5db67bb65b4fa9ecc65013107e07e";

/** Virtuals Protocol Bonding Proxy (fun.virtuals launchpad). */
export const VIRTUALS_BONDING_PROXY =
  "0xF66DeA7b3e897cD44A5a231c61B6B4423d613259";

/** Zora Coins factory (Base + Base Sepolia). */
export const ZORA_FACTORY = "0x777777751622c0d3258f214F9DF38E35BF45baF3";

/**
 * Zora CoinCreatedV4 / CreatorCoinCreated — content & creator coins (Uniswap V4).
 * topic0 = keccak of canonical event signature (verified via pycryptodome).
 */
export const TOPIC_ZORA_COIN_CREATED_V4 =
  "0x2de436107c2096e039c98bbcc3c5a2560583738ce15c234557eecb4d3221aa81";
export const TOPIC_ZORA_CREATOR_COIN_CREATED =
  "0x74b670d628e152daa36ca95dda7cb0002d6ea7a37b55afe4593db7abd1515781";
/** Legacy Uniswap V3-era Zora coins. */
export const TOPIC_ZORA_COIN_CREATED_LEGACY =
  "0x3d1462491f7fa8396808c230d95c3fa60fd09ef59506d0b9bd1cf072d2a03f56";

/**
 * Base discovery sources.
 * 24h probe (2026-07-30, mainnet.base.org): disable only proven-dead legacy Zora.
 * Aerodrome / Virtuals stayed enabled despite 0 events — re-check topic / narrativ later.
 */
const BASE_FACTORIES: DexFactorySource[] = [
  {
    id: "uniswap_v2",
    label: "Uniswap V2",
    kind: "univ2_pair_created",
    address: "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
    topic: TOPIC_UNIV2_PAIR_CREATED,
    enabled: true,
  },
  {
    id: "aerodrome",
    label: "Aerodrome",
    kind: "aero_pool_created",
    address: "0x420DD381b31aEf6683db6B902084cB0FFECe40Da",
    topic: TOPIC_AERO_POOL_CREATED,
    enabled: true,
  },
  {
    id: "uniswap_v3",
    label: "Uniswap V3",
    kind: "univ3_pool_created",
    address: "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
    // Observed on Base factory logs (same layout as PoolCreated; topic differs from ETH mainnet hash).
    topic:
      "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118",
    enabled: true,
  },
  {
    id: "clanker_v4",
    label: "Clanker v4",
    kind: "clanker_token_created",
    address: "0xE85A59c628F7d27878ACeB4bf3b35733630083a9",
    topic: TOPIC_CLANKER_TOKEN_CREATED,
    enabled: true,
  },
  {
    id: "virtuals_launched",
    label: "Virtuals Bonding (Launched)",
    kind: "virtuals_launched",
    address: VIRTUALS_BONDING_PROXY,
    topic: TOPIC_VIRTUALS_LAUNCHED,
    enabled: true,
  },
  {
    id: "virtuals_graduated",
    label: "Virtuals Bonding (Graduated)",
    kind: "virtuals_graduated",
    address: VIRTUALS_BONDING_PROXY,
    topic: TOPIC_VIRTUALS_GRADUATED,
    enabled: true,
  },
  {
    id: "zora_coin_v4",
    label: "Zora CoinCreatedV4",
    kind: "zora_coin_created",
    address: ZORA_FACTORY,
    topic: TOPIC_ZORA_COIN_CREATED_V4,
    enabled: true,
  },
  {
    id: "zora_creator_coin",
    label: "Zora CreatorCoinCreated",
    kind: "zora_coin_created",
    address: ZORA_FACTORY,
    topic: TOPIC_ZORA_CREATOR_COIN_CREATED,
    enabled: true, // 13 events / 24h — keep
  },
  {
    id: "zora_coin_legacy",
    label: "Zora CoinCreated (legacy)",
    kind: "zora_coin_created",
    address: ZORA_FACTORY,
    topic: TOPIC_ZORA_COIN_CREATED_LEGACY,
    enabled: false, // 0 events / 24h — dead topic burn
  },
];

/** Sepolia: keep UniV2-only (testnet coverage). */
const SEPOLIA_FACTORIES: DexFactorySource[] = [
  {
    id: "uniswap_v2",
    label: "Uniswap V2",
    kind: "univ2_pair_created",
    address: "0x7Ae58f10f7849cA6F5fB71b7f45CB416c9204b1e",
    topic: TOPIC_UNIV2_PAIR_CREATED,
    enabled: true,
  },
];

/** All configured factories (including disabled) — for admin / analyze tooling. */
export function listAllDexFactories(network: NetworkId): DexFactorySource[] {
  return network === "base" ? BASE_FACTORIES : SEPOLIA_FACTORIES;
}

/** Active discovery sources only. */
export function getDexFactories(network: NetworkId): DexFactorySource[] {
  return listAllDexFactories(network).filter((f) => f.enabled);
}

/** Legacy UniV2 factory address helper — prefer getDexFactories(). */
export const UNISWAP_V2_FACTORY_BY_NETWORK: Record<NetworkId, string> = {
  "base-sepolia": SEPOLIA_FACTORIES[0].address,
  base: BASE_FACTORIES[0].address,
};

export function getUniswapV2Factory(network: NetworkId): string {
  return UNISWAP_V2_FACTORY_BY_NETWORK[network];
}
