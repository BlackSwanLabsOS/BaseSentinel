import { isKvLimitMessage } from "../errors";

/**
 * Best-effort KV put — never throws on Free-tier daily write limits.
 * Returns false when the write was skipped/failed.
 */
export async function kvPutBestEffort(
  kv: KVNamespace,
  key: string,
  value: string,
  options?: KVNamespacePutOptions,
): Promise<boolean> {
  try {
    await kv.put(key, value, options);
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (isKvLimitMessage(message)) {
      console.warn(`[kv] put skipped (limit): ${key}`);
      return false;
    }
    console.error(`[kv] put failed ${key}:`, message);
    return false;
  }
}
