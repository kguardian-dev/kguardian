import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { bearerTokenFrom, requireBearer, tokensMatch } from "./auth.js";
import { createMcpRouter } from "./router.js";
import { MCP_PATH } from "./config.js";

const TOKEN = "s3cret-mcp-token";

test("tokensMatch accepts only identical strings", () => {
  // Mirrors broker/src/auth.rs's ct_eq_matches_only_identical_strings so the
  // two services' comparison semantics are pinned the same way.
  assert.equal(tokensMatch(TOKEN, TOKEN), true);
  assert.equal(tokensMatch("s3cret-mcp-toker", TOKEN), false);
  assert.equal(tokensMatch("short", TOKEN), false, "length mismatch must not throw");
  assert.equal(tokensMatch("", "x"), false);
  assert.equal(tokensMatch("", ""), true);
  // Multi-byte input must not desync the byte comparison.
  assert.equal(tokensMatch("tökén", "tökén"), true);
  assert.equal(tokensMatch("tökén", "token"), false);
});

test("bearerTokenFrom parses the header the way clients actually send it", () => {
  assert.equal(bearerTokenFrom(`Bearer ${TOKEN}`), TOKEN);
  assert.equal(bearerTokenFrom(`bearer ${TOKEN}`), TOKEN, "the scheme is case-insensitive per RFC 7235");
  assert.equal(bearerTokenFrom(`  Bearer   ${TOKEN}  `), TOKEN);
  assert.equal(bearerTokenFrom(undefined), null);
  assert.equal(bearerTokenFrom(""), null);
  assert.equal(bearerTokenFrom(TOKEN), null, "a bare token with no scheme is not a bearer header");
  assert.equal(bearerTokenFrom(`Basic ${TOKEN}`), null);
});

test("requireBearer(null) is a pass-through", () => {
  let called = false;
  requireBearer(null)({ header: () => undefined } as never, {} as never, () => { called = true; });
  assert.equal(called, true);
});

// HTTP-level coverage: the middleware is only useful if it actually sits in
// front of the transport, so both endpoints below are the real /mcp router.

let guarded: http.Server;
let open: http.Server;
let guardedURL = "";
let openURL = "";

/** A minimal, valid StreamableHTTP `initialize` POST. */
async function initialize(baseURL: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(`${baseURL}${MCP_PATH}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // The transport requires the client to accept BOTH, since it may answer
      // with a single JSON body or an SSE stream.
      Accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "auth-test", version: "1.0.0" },
      },
    }),
  });
}

async function listen(app: express.Express): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

before(async () => {
  const guardedApp = express();
  guardedApp.use(express.json({ limit: "100kb" }));
  guardedApp.use(MCP_PATH, createMcpRouter({ enabled: true, authToken: TOKEN, rateLimitPerMin: 300 }));
  ({ server: guarded, url: guardedURL } = await listen(guardedApp));

  const openApp = express();
  openApp.use(express.json({ limit: "100kb" }));
  openApp.use(MCP_PATH, createMcpRouter({ enabled: true, authToken: null, rateLimitPerMin: 300 }));
  ({ server: open, url: openURL } = await listen(openApp));
});

after(async () => {
  await new Promise<void>((resolve) => guarded.close(() => resolve()));
  await new Promise<void>((resolve) => open.close(() => resolve()));
});

test("with a token set, /mcp rejects requests that don't carry it", async () => {
  const cases: Record<string, string>[] = [
    {},
    { Authorization: "Bearer wrong-token-xxxx" },
    { Authorization: `Bearer ${TOKEN}x` },
    { Authorization: TOKEN },
  ];
  for (const headers of cases) {
    const res = await initialize(guardedURL, headers);
    await res.text();
    assert.equal(res.status, 401, `expected 401 for ${JSON.stringify(headers)}`);
    assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer /);
  }
});

test("with a token set, the correct bearer reaches the transport", async () => {
  const res = await initialize(guardedURL, { Authorization: `Bearer ${TOKEN}` });
  const body = await res.text();
  assert.equal(res.status, 200);
  // The initialize result comes back on an SSE stream by default; either way
  // the server identity must be in it, which proves the MCP server — not just
  // the middleware — handled the request.
  assert.match(body, /"serverInfo"/);
  assert.match(body, /"kguardian"/);
});

test("with no token set, /mcp is open", async () => {
  const res = await initialize(openURL);
  const body = await res.text();
  assert.equal(res.status, 200);
  assert.match(body, /"serverInfo"/);
});
