import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { callAnthropic } from "./anthropic.js";
import { BrokerClient } from "../brokerClient.js";
import type { ChatRequest } from "../types/index.js";

// A scripted mock of the Anthropic Messages API. Each request pops the next
// queued response; request bodies are captured for assertions. The official
// SDK is pointed here via ANTHROPIC_BASE_URL, so this exercises the real
// client (serialization, headers, error mapping) without any network egress.

interface MockResponse {
  status: number;
  body: unknown;
}

let server: http.Server;
let baseURL = "";
let responseQueue: MockResponse[] = [];
let capturedRequests: any[] = [];

function message(content: unknown[], stopReason: string): MockResponse {
  return {
    status: 200,
    body: {
      id: "msg_test",
      type: "message",
      role: "assistant",
      model: "claude-opus-4-8",
      content,
      stop_reason: stopReason,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    },
  };
}

before(async () => {
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      capturedRequests.push(raw ? JSON.parse(raw) : null);
      const next = responseQueue.shift() ?? message([{ type: "text", text: "default" }], "end_turn");
      res.writeHead(next.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(next.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  baseURL = `http://127.0.0.1:${port}`;

  // Isolate from the real Anthropic API and the MCP server.
  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.ANTHROPIC_BASE_URL = baseURL;
  // Stub the MCP-backed tool discovery so the loop has a deterministic,
  // network-free tool set.
  (BrokerClient as unknown as { getToolsCached: () => Promise<unknown[]> }).getToolsCached =
    async () => [
      {
        name: "get_cluster_pods",
        description: "List pods.",
        parameters: { type: "object", properties: {}, required: [] },
      },
    ];
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  responseQueue = [];
  capturedRequests = [];
});

function stubBroker(calls: string[]): BrokerClient {
  return {
    executeTool: async (toolCall: { name: string }) => {
      calls.push(toolCall.name);
      return { data: { ok: true, tool: toolCall.name } };
    },
  } as unknown as BrokerClient;
}

const baseRequest: ChatRequest = { message: "hello", provider: undefined } as ChatRequest;

test("plain text response: returns text, model, provider, and sends cached system + tools", async () => {
  responseQueue.push(message([{ type: "text", text: "hello world" }], "end_turn"));

  const res = await callAnthropic({ ...baseRequest }, stubBroker([]));

  assert.equal(res.message, "hello world");
  assert.equal(res.provider, "anthropic");
  assert.equal(res.model, "claude-opus-4-8");

  const sent = capturedRequests[0];
  assert.equal(sent.model, "claude-opus-4-8", "uses the Opus 4.8 default model");
  // Prompt caching: system is a block array with a cache_control breakpoint.
  assert.ok(Array.isArray(sent.system), "system is a content-block array");
  assert.deepEqual(sent.system[0].cache_control, { type: "ephemeral" });
  assert.ok(Array.isArray(sent.tools) && sent.tools.length > 0, "tools are sent");
});

test("tool loop: executes tool, feeds result back, returns final text", async () => {
  responseQueue.push(
    message([{ type: "tool_use", id: "tu_1", name: "get_cluster_pods", input: {} }], "tool_use"),
  );
  responseQueue.push(message([{ type: "text", text: "done" }], "end_turn"));

  const calls: string[] = [];
  const res = await callAnthropic({ ...baseRequest }, stubBroker(calls));

  assert.equal(res.message, "done");
  assert.deepEqual(calls, ["get_cluster_pods"], "tool executed exactly once");

  // Second request must carry the tool_result keyed to the tool_use id.
  const secondBody = capturedRequests[1];
  const lastMsg = secondBody.messages[secondBody.messages.length - 1];
  assert.equal(lastMsg.role, "user");
  assert.equal(lastMsg.content[0].type, "tool_result");
  assert.equal(lastMsg.content[0].tool_use_id, "tu_1");
});

test("refusal stop_reason yields a clean message instead of empty output", async () => {
  responseQueue.push(message([], "refusal"));

  const res = await callAnthropic({ ...baseRequest }, stubBroker([]));
  assert.equal(res.message, "I can't help with that request.");
});

test("API error is normalised into a thrown Error", async () => {
  responseQueue.push({
    status: 400,
    body: { type: "error", error: { type: "invalid_request_error", message: "bad input" } },
  });

  await assert.rejects(
    () => callAnthropic({ ...baseRequest }, stubBroker([])),
    /Anthropic API error:/,
  );
});

test("missing API key fails fast with a clear message", async () => {
  const saved = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    await assert.rejects(
      () => callAnthropic({ ...baseRequest }, stubBroker([])),
      /ANTHROPIC_API_KEY not configured/,
    );
  } finally {
    process.env.ANTHROPIC_API_KEY = saved;
  }
});
