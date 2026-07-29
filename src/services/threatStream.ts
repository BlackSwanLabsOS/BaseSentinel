import type { Env } from "../types";
import { listRecentThreats, type RecentThreatEvent } from "./threatIntel";

/** Short SSE window; clients reconnect via EventSource `retry`. */
export const SSE_SESSION_MS = 28_000;
export const SSE_POLL_MS = 2_000;
export const SSE_RETRY_MS = 5_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatSseEvent(options: {
  event?: string;
  id?: string;
  data: unknown;
  retry?: number;
}): string {
  const lines: string[] = [];
  if (options.retry !== undefined) {
    lines.push(`retry: ${options.retry}`);
  }
  if (options.event) {
    lines.push(`event: ${options.event}`);
  }
  if (options.id) {
    lines.push(`id: ${options.id}`);
  }
  const payload =
    typeof options.data === "string" ? options.data : JSON.stringify(options.data);
  for (const line of payload.split("\n")) {
    lines.push(`data: ${line}`);
  }
  lines.push("");
  lines.push("");
  return lines.join("\n");
}

function isAfterCursor(event: RecentThreatEvent, cursor: string | null): boolean {
  if (!cursor) {
    return true;
  }
  // ids are `${isoTimestamp}|${address}` — lexicographic compare works for ISO times.
  return event.id > cursor;
}

/**
 * Short-lived SSE stream of recent threats (polls KV, then closes with retry).
 */
export function createThreatEventStream(
  env: Env,
  options: { cursor?: string | null } = {},
): Response {
  let lastId = options.cursor ?? null;
  const encoder = new TextEncoder();
  const startedAt = Date.now();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (chunk: string) => {
        controller.enqueue(encoder.encode(chunk));
      };

      try {
        send(
          formatSseEvent({
            retry: SSE_RETRY_MS,
            event: "ready",
            data: {
              service: "base-sentinel",
              message: "threat stream connected",
              sessionMs: SSE_SESSION_MS,
              pollMs: SSE_POLL_MS,
            },
          }),
        );

        while (Date.now() - startedAt < SSE_SESSION_MS) {
          const recent = await listRecentThreats(env);
          // Chronological order within each batch.
          const fresh = recent
            .filter((event) => isAfterCursor(event, lastId))
            .sort((a, b) => (a.id < b.id ? -1 : 1));

          for (const event of fresh) {
            send(
              formatSseEvent({
                event: "threat",
                id: event.id,
                data: {
                  contract: event.contract,
                  network: event.network,
                  status:
                    event.status ??
                    (event.riskScore >= 70 ? "SCAM" : "SUSPICIOUS"),
                  riskScore: event.riskScore,
                  timestamp: event.timestamp,
                  reasons: event.reasons,
                  listing: event.listing ?? null,
                },
              }),
            );
            lastId = event.id;
          }

          // SSE keepalive comment.
          send(`: ping ${new Date().toISOString()}\n\n`);

          const remaining = SSE_SESSION_MS - (Date.now() - startedAt);
          if (remaining <= 0) {
            break;
          }
          await sleep(Math.min(SSE_POLL_MS, remaining));
        }

        send(
          formatSseEvent({
            event: "reconnect",
            data: {
              message: "session ended — reconnect with Last-Event-ID",
              lastEventId: lastId,
              retryMs: SSE_RETRY_MS,
            },
          }),
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        try {
          send(
            formatSseEvent({
              event: "error",
              data: { error: message },
            }),
          );
        } catch {
          // Client may have already disconnected.
        }
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
