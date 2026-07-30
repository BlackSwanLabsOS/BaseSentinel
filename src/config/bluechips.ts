import type { NetworkId } from "./network";
import {
  getUsdcContractAddress,
  getVirtualTokenAddress,
  getWethAddress,
} from "./network";

/**
 * Known Base bluechips — skip deep scan / external APIs.
 * Keep lowercase for O(1) set lookup.
 */
const BASE_BLUECHIPS: ReadonlyArray<{ address: string; symbol: string }> = [
  {
    address: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    symbol: "USDC",
  },
  {
    address: "0x4200000000000000000000000000000000000006",
    symbol: "WETH",
  },
  {
    address: "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca",
    symbol: "USDbC",
  },
  {
    address: "0x50c5725949a6f0c72e6c4a641f24049a917db0cb",
    symbol: "DAI",
  },
  {
    address: "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf",
    symbol: "cbBTC",
  },
  {
    address: "0x4ed4e862860bed51a9570b96d89af5e1b0efefed",
    symbol: "DEGEN",
  },
  {
    address: "0x940181a94a35a4569e4529a3cdfb74e38fd98631",
    symbol: "AERO",
  },
  {
    address: "0x0b3e328455c4059eeb9e3f84b5543f74e24e7e1b",
    symbol: "VIRTUAL",
  },
  {
    address: "0x1111111111166b7fe7bd91427724b487980afc69",
    symbol: "ZORA",
  },
];

const BASE_SET = new Set(BASE_BLUECHIPS.map((b) => b.address));

const SYMBOL_BY_ADDRESS = new Map(
  BASE_BLUECHIPS.map((b) => [b.address, b.symbol] as const),
);

/** Lowercased Base bluechip addresses — for discovery skip lists. */
export function getBluechipAddresses(network: NetworkId): string[] {
  if (network !== "base") return [];
  return [...BASE_SET];
}

/** True when address is a known non-scam Base bluechip. */
export function isBluechipAddress(
  network: NetworkId,
  address: string,
): boolean {
  if (network !== "base") return false;
  return BASE_SET.has(address.toLowerCase());
}

export function getBluechipSymbol(
  network: NetworkId,
  address: string,
): string | null {
  if (network !== "base") return null;
  return SYMBOL_BY_ADDRESS.get(address.toLowerCase()) ?? null;
}

/** Sanity: config USDC/WETH/VIRTUAL stay on the allowlist. */
export function assertCoreBluechipsPresent(): void {
  const required = [
    getUsdcContractAddress("base"),
    getWethAddress("base"),
    getVirtualTokenAddress("base"),
  ].map((a) => a.toLowerCase());
  for (const addr of required) {
    if (!BASE_SET.has(addr)) {
      throw new Error(`Bluechip allowlist missing core token ${addr}`);
    }
  }
}
