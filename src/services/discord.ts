import type { Env } from "../types";

export interface DiscordThreatPayload {
  address: string;
  network: string;
  riskScore: number;
  reasons: string[];
  timestamp: string;
}

function basescanUrl(address: string, network: string): string {
  const host =
    network === "base" || network === "base-mainnet"
      ? "https://basescan.org"
      : "https://sepolia.basescan.org";
  return `${host}/address/${address}`;
}

/**
 * Sends a SCAM alert embed to Discord.
 * No-ops when DISCORD_WEBHOOK_URL is missing. Never throws to callers.
 */
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

  const body = {
    content: null,
    embeds: [
      {
        title: "🚨 BaseSentinel — SCAM detected",
        color: 0xe74c3c,
        url: explorer,
        fields: [
          {
            name: "Contract",
            value: `[${threat.address}](${explorer})`,
            inline: false,
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
            name: "Reasons",
            value: reasons.slice(0, 1000),
            inline: false,
          },
        ],
        timestamp: threat.timestamp,
        footer: {
          text: "BaseSentinel threat intel",
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
