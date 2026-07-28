import type { Env } from "../types";

/**
 * Constant-time-ish string compare for admin API keys.
 * (Best-effort in JS; still vastly better than early-return on first mismatch.)
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

export function requireAdmin(request: Request, env: Env): Response | null {
  if (!env.ADMIN_API_KEY) {
    return Response.json(
      { error: "Admin API is not configured" },
      { status: 503 },
    );
  }

  if (!isAdminAuthorized(request, env)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  return null;
}

/** Soft check — used when admin key is an optional free bypass. */
export function isAdminAuthorized(request: Request, env: Env): boolean {
  if (!env.ADMIN_API_KEY) {
    return false;
  }

  const provided = request.headers.get("X-Admin-Key")?.trim() ?? "";
  if (!provided) {
    return false;
  }

  return timingSafeEqual(provided, env.ADMIN_API_KEY);
}
