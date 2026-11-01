import { Hono } from "hono";
import { cors } from "hono/cors";

interface Bindings {
  NONCE_KV?: KVNamespace;
}

const app = new Hono<{ Bindings: Bindings }>();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "PROOF-RESPONSE", "PROOF-REQUEST"],
    exposeHeaders: ["WWW-Authenticate", "PROOF-REQUEST", "PROOF-RESULT"]
  })
);

app.get("/", (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>x401 Tech | Zero-Trust Infrastructure for Autonomous Agents</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #080c14; color: #e2e8f0; margin: 0; padding: 48px 24px; line-height: 1.6; }
    .container { max-width: 860px; margin: 0 auto; }
    .hero { text-align: center; margin-bottom: 36px; }
    h1 { color: #38bdf8; font-size: 2.6rem; margin-bottom: 0.4rem; letter-spacing: -0.02em; }
    .tagline { color: #94a3b8; font-size: 1.15rem; max-width: 680px; margin: 0 auto 1.6rem; }
    .badge { display: inline-block; background: #1e293b; color: #38bdf8; border: 1px solid #334155; padding: 4px 10px; border-radius: 6px; font-size: 0.85rem; font-family: monospace; }
    .community-box { background: #0b1329; border: 1px solid #1e3a8a; border-radius: 8px; padding: 16px 20px; margin: 24px 0; color: #93c5fd; font-size: 0.98rem; text-align: center; }
    .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 24px; margin-top: 20px; transition: border-color 0.2s; }
    .card:hover { border-color: #38bdf8; }
    h3 { margin-top: 0; color: #f8fafc; font-size: 1.25rem; }
    p { margin: 8px 0 14px; color: #cbd5e1; font-size: 0.98rem; }
    a { color: #38bdf8; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    code { background: #1e293b; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; font-family: monospace; }
    pre { background: #0b1120; border: 1px solid #1e293b; padding: 14px; border-radius: 8px; overflow-x: auto; color: #f1f5f9; font-family: monospace; font-size: 0.86rem; }
    .grid { display: grid; grid-template-columns: 1fr; gap: 16px; margin-top: 24px; }
    .cta-btn { display: inline-block; background: #0284c7; color: #ffffff; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 0.9rem; text-decoration: none; margin-top: 6px; }
    .cta-btn:hover { background: #0369a1; text-decoration: none; }
    footer { text-align: center; margin-top: 48px; color: #64748b; font-size: 0.88rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <h1>x401 Technologies</h1>
      <div class="tagline">Production-grade cryptographic boundaries, gateways, and reverse proxies for autonomous AI agents.</div>
      <span class="badge">Commercial Infrastructure & Developer Tools</span>
    </div>

    <div class="community-box">
      To contribute to improving the trust relationship between agentic servers and agentic agents, visit <a href="https://401frameworks.org" target="_blank" rel="noreferrer">401frameworks.org</a>.
    </div>

    <div class="grid">
      <div class="card">
        <h3>Live Challenge Gateway</h3>
        <p>Production edge gateway issuing atomic cryptographic challenge nonces and validating AED delegation tickets for high-throughput MCP clusters.</p>
        <p>Endpoint: <code>https://auth.x401.tech/challenge</code></p>
        <pre>curl -i https://auth.x401.tech/challenge</pre>
      </div>

      <div class="card">
        <h3>Interactive Delegation Ticket Debugger & Inspector</h3>
        <p>Inspect, decode, and verify Base64URL-encoded AED tokens, ES256/EdDSA signatures, and parameter commitments in real time.</p>
        <a class="cta-btn" href="https://401frameworks.org/debugger" target="_blank" rel="noreferrer">Open Ticket Inspector &rarr;</a>
      </div>

      <div class="card">
        <h3>AED MCP Proxy (stdio & SSE)</h3>
        <p>Drop-in zero-trust reverse proxy wrapper for any Model Context Protocol server. Intercepts incoming <code>tools/call</code> invocations, enforces parameter commitments, and blocks unauthorized actions before execution.</p>
        <pre>npx @x401/mcp-proxy --server-origin https://api.yourdomain.com -- npx @modelcontextprotocol/server-filesystem /path</pre>
      </div>
    </div>

    <footer>
      Built on the open <a href="https://401frameworks.org" target="_blank" rel="noreferrer">Agent Execution Delegation (AED) Protocol</a> (RFC-x401-02).
    </footer>
  </div>
</body>
</html>`);
});

app.get("/challenge", async (c) => {
  const nonceBytes = new Uint8Array(24);
  crypto.getRandomValues(nonceBytes);
  const nonce = Array.from(nonceBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  if (c.env.NONCE_KV) {
    await c.env.NONCE_KV.put(`nonce:${nonce}`, "active", { expirationTtl: 300 });
  }

  c.header(
    "WWW-Authenticate",
    `AED realm="auth.x401.tech", challenge="${nonce}", spec="https://401frameworks.org/schemas/v2/agent-delegation-ticket.json"`
  );
  c.header(
    "PROOF-REQUEST",
    btoa(
      JSON.stringify({
        version: "2.0.0",
        required_claims: ["permissions.mcp_tools", "settlement_terms"],
        nonce
      })
    )
  );

  return c.json({ error: "Unauthorized", challenge: nonce }, 401);
});

app.get("/health", (c) => {
  return c.json({ status: "healthy", domain: "x401.tech", service: "edge-gateway" });
});

export default app;
