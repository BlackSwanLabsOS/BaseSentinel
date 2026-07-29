import type { Env } from "../types";
import type { AgentVerdict } from "./verdict";

export interface DiscordThreatPayload {
  address: string;
  network: string;
  status: "SCAM" | "SUSPICIOUS";
  riskScore: number;
  reasons: string[];
  timestamp: string;
  listingSource?: string | null;
  listingTx?: string | null;
  /** Agent-facing verdict (CLEAR / CAUTION / AVOID). */
  verdict?: AgentVerdict | null;
  verdict_score?: number | null;
  risk_flags?: string[];
}

const MARKETING_CTA =
  "Want real-time threat webhooks in <100ms? Set up a Watchdog stream at https://blackswanlabs.pl";

function basescanUrl(address: string, network: string): string {
  const host =
    network === "base" || network === "base-mainnet"
      ? "https://basescan.org"
      : "https://sepolia.basescan.org";
  return `${host}/address/${address}`;
}

/** Discord alert for SCAM / SUSPICIOUS. No-op if webhook unset. */
export async function notifyDiscord(
  webhookUrl: string | undefined,
  threat: DiscordThreatPayload,
): Promise<void> {
  if (!webhookUrl) {
    return;
  }

  const reasons =
    threat.reasons?.length > 0 ? threat.reasons.join("\n") : "None";
  const explorer = basescanUrl(threat.address, threat.network);
  const isScam = threat.status === "SCAM";
  const flags =
    threat.risk_flags && threat.risk_flags.length > 0
      ? threat.risk_flags.map((f) => `\`${f}\``).join(" ")
      : "`none`";
  const verdictLabel = threat.verdict
    ? `\`${threat.verdict}\`${
        typeof threat.verdict_score === "number"
          ? ` (${threat.verdict_score}/100)`
          : ""
      }`
    : "`n/a`";

  const body = {
    content: null,
    embeds: [
      {
        title: isScam
          ? "🚨 BaseSentinel — SCAM detected"
          : "⚠️ BaseSentinel — SUSPICIOUS contract",
        color: isScam ? 0xe74c3c : 0xf39c12,
        url: explorer,
        fields: [
          {
            name: "Contract",
            value: `[${threat.address}](${explorer})`,
            inline: false,
          },
          {
            name: "Status",
            value: `\`${threat.status}\``,
            inline: true,
          },
          {
            name: "Verdict",
            value: verdictLabel,
            inline: true,
          },
          {
            name: "Network",
            value: `\`${threat.network}\``,
            inline: true,
          },
          {
            name: "Risk score",
            value: `**${threat.riskScore}/100**`,
            inline: true,
          },
          {
            name: "Risk flags",
            value: flags.slice(0, 1000),
            inline: false,
          },
          {
            name: "Reasons",
            value: reasons.slice(0, 1000),
            inline: false,
          },
          ...(threat.listingSource || threat.listingTx
            ? [
                {
                  name: "Listing",
                  value: [
                    threat.listingSource
                      ? `source: \`${threat.listingSource}\``
                      : null,
                    threat.listingTx
                      ? `tx: \`${threat.listingTx.slice(0, 10)}…\``
                      : null,
                  ]
                    .filter(Boolean)
                    .join(" · "),
                  inline: false,
                },
              ]
            : []),
          {
            name: "CTA",
            value: MARKETING_CTA,
            inline: false,
          },
        ],
        timestamp: threat.timestamp,
        footer: {
          text: isScam
            ? "BaseSentinel hard SCAM (≥70) · blackswanlabs.pl"
            : "BaseSentinel watchlist (≥50) · blackswanlabs.pl",
        },
      },
    ],
    allowed_mentions: { parse: [] },
  };

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      console.warn(
        `[discord] webhook failed HTTP ${response.status} ${response.statusText}`,
      );
    }
  } catch (error) {
    console.warn(
      "[discord] webhook error:",
      error instanceof Error ? error.message : error,
    );
  }
}

export async function notifyDiscordFromEnv(
  env: Env,
  threat: DiscordThreatPayload,
): Promise<void> {
  await notifyDiscord(env.DISCORD_WEBHOOK_URL, threat);
}

export interface CronDigestPayload {
  discovered: number;
  scanned: number;
  scams: number;
  suspicious: number;
  errors: number;
  fromBlock: number;
  toBlock: number;
  bySource?: Record<string, number>;
}

/** Cron digest: only sent when the tick found or flagged something. */
export async function notifyCronDigest(
  webhookUrl: string | undefined,
  digest: CronDigestPayload,
): Promise<void> {
  if (!webhookUrl) return;
  if (
    digest.discovered <= 0 &&
    digest.scams <= 0 &&
    digest.suspicious <= 0
  ) {
    return;
  }

  const sources =
    digest.bySource && Object.keys(digest.bySource).length > 0
      ? Object.entries(digest.bySource)
          .map(([k, v]) => `${k}: ${v}`)
          .join(" · ")
      : "—";

  const body = {
    content: null,
    embeds: [
      {
        title: "📡 BaseSentinel — cron scan",
        color:
          digest.scams > 0
            ? 0xe74c3c
            : digest.suspicious > 0
              ? 0xf39c12
              : 0x5eead4,
        fields: [
          {
            name: "Discovered",
            value: `**${digest.discovered}**`,
            inline: true,
          },
          {
            name: "Scanned",
            value: `**${digest.scanned}**`,
            inline: true,
          },
          {
            name: "SCAM / SUS",
            value: `**${digest.scams}** / **${digest.suspicious}**`,
            inline: true,
          },
          {
            name: "Sources",
            value: sources,
            inline: false,
          },
          {
            name: "Blocks",
            value: `\`${digest.fromBlock} → ${digest.toBlock}\``,
            inline: false,
          },
        ],
        timestamp: new Date().toISOString(),
        footer: {
          text: "BaseSentinel discovery (UniV2 · Aerodrome · UniV3 · Clanker · Virtuals)",
        },
      },
    ],
    allowed_mentions: { parse: [] },
  };

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      console.warn(
        `[discord] cron digest failed HTTP ${response.status} ${response.statusText}`,
      );
    }
  } catch (error) {
    console.warn(
      "[discord] cron digest error:",
      error instanceof Error ? error.message : error,
    );
  }
}
