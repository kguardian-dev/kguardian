import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";

import { MCP_PATH } from "./config.js";

// The default posture: MCP_ENABLED unset means /mcp is not routed at all.
//
// This boots the real index.ts app rather than a hand-built one, because the
// thing under test is the wiring decision in index.ts, not the router. A 404
// (rather than a 403 from a mounted-but-refusing route) is the intended
// behaviour: a default install must be indistinguishable from a build that
// never had the endpoint.

let appServer: http.Server;
let appURL = "";

before(async () => {
  // Cleared before the import because index.ts reads the env once at module
  // load, and dotenv may have picked up a developer's local .env.
  delete process.env.MCP_ENABLED;
  delete process.env.MCP_AUTH_TOKEN;

  const { app } = (await import("../index.js")) as { app: Express };
  appServer = http.createServer(app);
  await new Promise<void>((resolve) => appServer.listen(0, "127.0.0.1", resolve));
  appURL = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => appServer.close(() => resolve()));
});

test("/mcp 404s when the endpoint is not enabled", async () => {
  for (const method of ["POST", "GET", "DELETE"]) {
    const res = await fetch(`${appURL}${MCP_PATH}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: method === "POST" ? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) : undefined,
    });
    await res.text();
    assert.equal(res.status, 404, `expected ${method} ${MCP_PATH} to 404`);
  }
});

test("/health reports mcp: false without disturbing the existing fields", async () => {
  const res = await fetch(`${appURL}/health`);
  const body = (await res.json()) as Record<string, unknown>;

  assert.equal(res.status, 200);
  // status and hasProvider are consumed by the chart's probes and the
  // frontend's provider gate — the mcp field is additive, never a reshape.
  assert.equal(body.status, "healthy");
  assert.equal(typeof body.hasProvider, "boolean");
  assert.equal(body.mcp, false);
});
