import { test, before, after } from "node:test";
import { strict as assert } from "node:assert";
import http from "node:http";
import type { AddressInfo } from "node:net";

// ALLOWED_ORIGIN is read when index.ts loads, so clear it before the import.
delete process.env.ALLOWED_ORIGIN;
const { app, corsOriginFromEnv, LOOPBACK_ORIGIN } = await import("./index.js");

test("corsOriginFromEnv: unset or blank falls back to loopback origins", () => {
  assert.equal(corsOriginFromEnv(undefined), LOOPBACK_ORIGIN);
  assert.equal(corsOriginFromEnv(""), LOOPBACK_ORIGIN);
  assert.equal(corsOriginFromEnv("   "), LOOPBACK_ORIGIN);
});

test("corsOriginFromEnv: a set value is used trimmed, including an explicit *", () => {
  assert.equal(corsOriginFromEnv(" https://kguardian.example.com \n"), "https://kguardian.example.com");
  assert.equal(corsOriginFromEnv("*"), "*");
});

test("LOOPBACK_ORIGIN matches local origins only", () => {
  for (const o of ["http://localhost:5173", "http://localhost", "https://127.0.0.1:8443", "http://[::1]:6274"]) {
    assert.ok(LOOPBACK_ORIGIN.test(o), o);
  }
  for (const o of [
    "https://evil.example",
    "http://localhost.evil.example",
    "http://evil.example/?http://localhost",
    "http://127.0.0.1.evil.example",
    "null",
  ]) {
    assert.ok(!LOOPBACK_ORIGIN.test(o), o);
  }
});

let server: http.Server;
let url = "";

before(async () => {
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

function preflight(origin: string): Promise<Response> {
  return fetch(`${url}/api/chat/stream`, {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type",
    },
  });
}

test("default CORS: the vite dev origin passes preflight", async () => {
  const res = await preflight("http://localhost:5173");
  assert.equal(res.headers.get("access-control-allow-origin"), "http://localhost:5173");
  assert.match(res.headers.get("access-control-allow-headers") ?? "", /content-type/);
});

test("default CORS: a foreign origin gets no allow-origin header", async () => {
  const res = await preflight("https://evil.example");
  assert.equal(res.headers.get("access-control-allow-origin"), null);
});

test("default CORS: a same-origin request (the UI's /llm-api proxy) is unaffected", async () => {
  const res = await fetch(`${url}/health`, { headers: { Origin: "https://kguardian.example.com" } });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, "healthy");
});
