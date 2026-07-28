/** Strict EVM address: 0x + exactly 40 hex characters. */
export const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

/**
 * Returns true only when `address` is a well-formed Ethereum/EVM address.
 * Does not check EIP-55 checksum — format only.
 */
export function isValidEthereumAddress(address: unknown): address is string {
  return typeof address === "string" && EVM_ADDRESS_REGEX.test(address);
}

/**
 * Validates and normalizes an address to lowercase.
 * Returns null when the input is not a valid EVM address.
 * Use this before any KV key, RPC call, or response body.
 */
export function normalizeEthereumAddress(address: unknown): string | null {
  if (typeof address !== "string") {
    return null;
  }

  const trimmed = address.trim();
  if (!isValidEthereumAddress(trimmed)) {
    return null;
  }

  return trimmed.toLowerCase();
}
