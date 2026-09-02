import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { clusterCni, resetClusterCniCache } from "./backendClient.js";

// clusterCni backs the CNI-aligned policy generation (issue #1413).
// The contract under test: cached, and EVERY failure degrades to
// "unknown" — which callers treat as "no signal, behave as before".

let server: http.Server;
let responses: Array<{ status: number; body?: unknown }> = [];
let hits = 0;

before(async () => {
  server = http.createServer((_req, res) => {
    hits += 1;
    const next = responses.shift() ?? { status: 404 };
    if (next.body !== undefined) {
      res.writeHead(next.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(next.body));
    } else {
      res.writeHead(next.status);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  process.env.BROKER_URL = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  resetClusterCniCache();
  responses = [];
  hits = 0;
});

test("returns the broker's cni and caches the success", async () => {
  responses = [{ status: 200, body: { cni: "calico", nodes: 3 } }];
  assert.equal(await clusterCni(), "calico");
  assert.equal(await clusterCni(), "calico"); // served from cache
  assert.equal(hits, 1);
});

test("older broker 404 degrades to unknown, never throws", async () => {
  responses = [{ status: 404 }];
  assert.equal(await clusterCni(), "unknown");
});

test("malformed body degrades to unknown", async () => {
  responses = [{ status: 200, body: { nodes: 3 } }];
  assert.equal(await clusterCni(), "unknown");
});
