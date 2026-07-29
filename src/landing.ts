/** Landing page for apex / www. API: api.blackswanlabs.pl */

import {
  PUBLIC_INTEL_SHORT,
  PUBLIC_INTEL_SUMMARY,
} from "./discovery/publicIntel";

const API_ORIGIN = "https://api.blackswanlabs.pl";

export function isMarketingHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === "blackswanlabs.pl" ||
    host === "www.blackswanlabs.pl" ||
    host === "localhost" ||
    host.endsWith(".localhost")
  );
}

export function renderLandingHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="BaseSentinel — ${PUBLIC_INTEL_SHORT} Pay-per-call via HTTP 402 + USDC." />
  <title>BaseSentinel — BlackSwan Labs</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Syne:wght@500;600;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --ink-950: #07080a;
      --ink-900: #0c0e12;
      --bone: #e8e4dc;
      --mist: #9aa3b2;
      --signal: #5eead4;
    }
    *, *::before, *::after { box-sizing: border-box; }
    html, body { min-height: 100%; margin: 0; }
    body {
      font-family: Syne, system-ui, sans-serif;
      color: var(--bone);
      -webkit-font-smoothing: antialiased;
      background-color: var(--ink-950);
      background-image:
        radial-gradient(ellipse 90% 60% at 50% -10%, rgba(94, 234, 212, 0.12), transparent 55%),
        radial-gradient(ellipse 50% 40% at 100% 100%, rgba(232, 228, 220, 0.05), transparent 45%),
        linear-gradient(180deg, #07080a 0%, #0c0e12 55%, #07080a 100%);
    }
    body::before {
      content: "";
      pointer-events: none;
      position: fixed;
      inset: 0;
      opacity: 0.035;
      z-index: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    }
    main {
      position: relative;
      z-index: 10;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .hero {
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 4rem 1.5rem 3rem;
    }
    @media (min-width: 640px) {
      .hero { padding-left: 2.5rem; padding-right: 2.5rem; }
    }
    @media (min-width: 1024px) {
      .hero { padding-left: 4rem; padding-right: 4rem; }
    }
    .wrap { width: 100%; max-width: 48rem; margin: 0 auto; }
    .eyebrow {
      margin: 0;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.28em;
      text-transform: uppercase;
      color: var(--mist);
      animation: rise 0.9s ease-out both;
    }
    h1 {
      margin: 1.5rem 0 0;
      font-size: clamp(3rem, 8vw, 4.5rem);
      font-weight: 600;
      letter-spacing: -0.025em;
      line-height: 1;
      animation: rise 0.9s ease-out 0.12s both;
    }
    .lede {
      margin: 1.25rem 0 0;
      max-width: 42rem;
      font-family: "Instrument Serif", Georgia, serif;
      font-size: clamp(1.5rem, 3.5vw, 1.875rem);
      font-style: italic;
      line-height: 1.375;
      color: rgba(232, 228, 220, 0.9);
      animation: rise 0.9s ease-out 0.18s both;
    }
    .body {
      margin: 2rem 0 0;
      max-width: 42rem;
      font-size: 1rem;
      line-height: 1.625;
      color: var(--mist);
      animation: rise 0.9s ease-out 0.24s both;
    }
    @media (min-width: 640px) {
      .body { font-size: 1.125rem; }
    }
    .actions {
      margin-top: 2.5rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      animation: rise 0.9s ease-out 0.28s both;
    }
    @media (min-width: 640px) {
      .actions { flex-direction: row; align-items: center; }
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 0.375rem;
      padding: 0.75rem 1.5rem;
      font-size: 0.875rem;
      font-weight: 600;
      letter-spacing: 0.025em;
      text-decoration: none;
      transition: background-color 150ms, border-color 150ms, color 150ms;
    }
    .btn-primary {
      background: var(--bone);
      color: var(--ink-950);
    }
    .btn-primary:hover { background: #fff; }
    .btn-ghost {
      background: transparent;
      color: var(--bone);
      border: 1px solid rgba(232, 228, 220, 0.25);
    }
    .btn-ghost:hover {
      border-color: rgba(94, 234, 212, 0.6);
      color: var(--signal);
    }
    .intel {
      padding: 0 1.5rem 4rem;
      animation: rise 0.9s ease-out 0.34s both;
    }
    @media (min-width: 640px) {
      .intel { padding-left: 2.5rem; padding-right: 2.5rem; }
    }
    @media (min-width: 1024px) {
      .intel { padding-left: 4rem; padding-right: 4rem; }
    }
    .intel h2 {
      margin: 0;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--signal);
    }
    .intel p {
      margin: 0.85rem 0 0;
      max-width: 42rem;
      font-size: 0.95rem;
      line-height: 1.65;
      color: rgba(154, 163, 178, 0.95);
    }
    .intel .line {
      margin-top: 1.5rem;
      height: 1px;
      max-width: 42rem;
      background: linear-gradient(90deg, rgba(94, 234, 212, 0.35), transparent);
    }
    footer {
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding: 1.5rem;
    }
    @media (min-width: 640px) {
      footer { padding-left: 2.5rem; padding-right: 2.5rem; }
    }
    .footer-inner {
      max-width: 48rem;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      font-size: 0.75rem;
      color: rgba(154, 163, 178, 0.8);
    }
    @media (min-width: 640px) {
      .footer-inner {
        flex-direction: row;
        align-items: center;
        justify-content: space-between;
      }
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 11px;
      color: rgba(154, 163, 178, 0.6);
    }
    @keyframes rise {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="wrap">
        <p class="eyebrow">Base · M2M · x402</p>
        <h1>BaseSentinel</h1>
        <p class="lede">Pay-per-call threat intel for autonomous agents on Base.</p>
        <p class="body">
          Machine buyers get SAFE / SUSPICIOUS / SCAM scans, a daily threat pack, and a live
          alert stream. No API keys — pay USDC on-chain, retry with proof (HTTP 402 / x402).
        </p>
        <div class="actions">
          <a class="btn btn-primary" href="${API_ORIGIN}/">Open API</a>
          <a class="btn btn-ghost" href="${API_ORIGIN}/.well-known/x402.json">x402 discovery</a>
        </div>
      </div>
    </section>
    <section class="intel" aria-label="Sources and coverage">
      <div class="wrap">
        <div class="line"></div>
        <h2>Sources &amp; coverage</h2>
        <p>${PUBLIC_INTEL_SUMMARY}</p>
      </div>
    </section>
    <footer>
      <div class="footer-inner">
        <span>BlackSwan Labs · Base mainnet · HTTP 402 + USDC</span>
        <span class="mono">${API_ORIGIN}</span>
      </div>
    </footer>
  </main>
</body>
</html>`;
}

export function landingResponse(): Response {
  return new Response(renderLandingHtml(), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=300",
    },
  });
}
