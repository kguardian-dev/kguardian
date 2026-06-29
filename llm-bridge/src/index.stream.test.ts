import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { app } from "./index.js";
import { BrokerClient } from "./brokerClient.js";

// Integration test for the SSE /api/chat/stream route: boots the real Express
// app, points the Anthropic SDK at a mock streaming server, and asserts the
// wire-level SSE frames the browser would receive.

function sse(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function textMessageSSE(text: string): string {
  return (
    sse("message_start", {
      type: "message_start",
      message: {
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "claude-opus-4-8",
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 0 },
      },
    }) +
    sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }) +
    sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }) +
    sse("content_block_stop", { type: "content_block_stop", index: 0 }) +
    sse("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 1 } }) +
    sse("message_stop", { type: "message_stop" })
  );
}

let anthropicMock: http.Server;
let appServer: http.Server;
let appURL = "";

before(async () => {
  anthropicMock = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.end(textMessageSSE("hello world"));
  });
  await new Promise<void>((resolve) => anthropicMock.listen(0, "127.0.0.1", resolve));
  const mockPort = (anthropicMock.address() as AddressInfo).port;

  // Force a clean, anthropic-only provider environment pointed at the mock.
  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${mockPort}`;
  delete process.env.OPENAI_API_KEY;
  delete process.env.GOOGLE_API_KEY;
  delete process.env.GITHUB_TOKEN;

  (BrokerClient as unknown as { getToolsCached: () => Promise<unknown[]> }).getToolsCached =
    async () => [
      { name: "get_cluster_pods", description: "List pods.", parameters: { type: "object", properties: {}, required: [] } },
    ];

  appServer = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => appServer.once("listening", () => resolve()));
  appURL = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => appServer.close(() => resolve()));
  await new Promise<void>((resolve) => anthropicMock.close(() => resolve()));
});

beforeEach(() => {
  // Re-assert (other test files in the same process may have mutated these).
  process.env.ANTHROPIC_API_KEY = "test-key";
});

test("POST /api/chat/stream emits SSE text + done frames", async () => {
  const res = await fetch(`${appURL}/api/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "hi", provider: "anthropic" }),
  });

  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") || "", /text\/event-stream/);

  const body = await res.text();
  // Wire format: a text event carrying the delta, and a terminal done event.
  assert.match(body, /event: text\ndata: \{"type":"text","delta":"hello world"\}/);
  assert.match(body, /event: done\ndata: \{"type":"done","model":"claude-opus-4-8"/);
});

test("POST /api/chat/stream rejects an invalid body with JSON 400 (pre-stream)", async () => {
  const res = await fetch(`${appURL}/api/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "anthropic" }), // missing required `message`
  });

  assert.equal(res.status, 400);
  assert.match(res.headers.get("content-type") || "", /application\/json/);
  const body = await res.json();
  assert.equal(body.error, "Invalid request format");
});
