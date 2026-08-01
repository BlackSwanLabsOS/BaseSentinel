/**
 * Per payment-proof mutex. KV has no compare-and-swap; this Durable Object
 * serializes first-redeem for a given product+txHash so concurrent requests
 * cannot double-consume the same proof.
 */
export class PaymentLockDO {
  constructor(private readonly ctx: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/acquire") {
      return this.ctx.blockConcurrencyWhile(() => this.acquire());
    }

    if (request.method === "POST" && url.pathname === "/release") {
      await this.ctx.storage.delete("lock");
      return Response.json({ ok: true });
    }

    return new Response("Not Found", { status: 404 });
  }

  private async acquire(): Promise<Response> {
    const now = Date.now();
    const lock = await this.ctx.storage.get<{ until: number }>("lock");
    if (lock && lock.until > now) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((lock.until - now) / 1000),
      );
      return Response.json(
        { ok: false, retryAfterSeconds },
        { status: 423 },
      );
    }

    // Cover Alchemy receipt + block timestamp under load.
    await this.ctx.storage.put("lock", { until: now + 45_000 });
    return Response.json({ ok: true });
  }
}
