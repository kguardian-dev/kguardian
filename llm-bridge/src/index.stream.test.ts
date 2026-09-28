import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { app } from "./index.js";
import { McpClient } from "./mcpClient.js";

// Integration test for the SSE /api/chat/stream route: boots the real Express
// app, points the Anthropic SDK and the OpenAI-compatible provider at mock
// streaming servers, and asserts the wire-level SSE frames the browser would
// receive.

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

// OpenAI-compatible mock: `stream: true` chat completions, one `data:` frame
// per delta, scripted per request as raw chunks. The model id is the
// gateway-style one the dev install reports (OpenRouter fronting Claude), and
// the comment line is the keepalive OpenRouter interleaves while it waits.
const GATEWAY_MODEL = "anthropic/claude-sonnet-5";
const DONE = "data: [DONE]\n\n";

function openaiDelta(delta: Record<string, unknown>, finish: string | null = null, model = GATEWAY_MODEL): string {
  return `data: ${JSON.stringify({
    id: "chatcmpl-1",
    object: "chat.completion.chunk",
    model,
    choices: [{ index: 0, delta, finish_reason: finish }],
  })}\n\n`;
}

let anthropicMock: http.Server;
let openaiMock: http.Server;
let openaiScript: string[][] = [];
let openaiRequests: any[] = [];
let toolCalls: { name: string; arguments: unknown }[] = [];
let appServer: http.Server;
let appURL = "";

before(async () => {
  anthropicMock = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.end(textMessageSSE("hello world"));
  });
  await new Promise<void>((resolve) => anthropicMock.listen(0, "127.0.0.1", resolve));
  const mockPort = (anthropicMock.address() as AddressInfo).port;

  openaiMock = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      openaiRequests.push(JSON.parse(raw));
      const chunks = openaiScript.shift() ?? [openaiDelta({ content: "default" }), openaiDelta({}, "stop"), DONE];
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      for (const chunk of chunks) {
        res.write(chunk);
        await new Promise((resolve) => setTimeout(resolve, 1));
      }
      res.end();
    });
  });
  await new Promise<void>((resolve) => openaiMock.listen(0, "127.0.0.1", resolve));
  const openaiPort = (openaiMock.address() as AddressInfo).port;

  // Force a clean provider environment: anthropic and openai pointed at the
  // mocks, nothing else configured.
  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${mockPort}`;
  process.env.OPENAI_API_KEY = "test-key";
  process.env.OPENAI_BASE_URL = `http://127.0.0.1:${openaiPort}/v1`;
  delete process.env.OPENAI_MODEL;
  delete process.env.GOOGLE_API_KEY;
  delete process.env.GITHUB_TOKEN;

  const stub = McpClient as unknown as {
    getToolsCached: () => Promise<unknown[]>;
    prototype: { executeTool: (tc: { name: string; arguments: unknown }) => Promise<unknown> };
  };
  stub.getToolsCached = async () => [
    { name: "get_cluster_pods", description: "List pods.", parameters: { type: "object", properties: {}, required: [] } },
  ];
  stub.prototype.executeTool = async (tc) => {
    toolCalls.push(tc);
    return { data: [{ pod_name: "web-1" }, { pod_name: "batch-1" }] };
  };

  appServer = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => appServer.once("listening", () => resolve()));
  appURL = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => appServer.close(() => resolve()));
  await new Promise<void>((resolve) => anthropicMock.close(() => resolve()));
  await new Promise<void>((resolve) => openaiMock.close(() => resolve()));
});

beforeEach(() => {
  // Re-assert (other test files in the same process may have mutated these).
  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.OPENAI_API_KEY = "test-key";
  openaiScript = [];
  openaiRequests = [];
  toolCalls = [];
});

/** Decode the `data:` payloads of an SSE body, in order. */
function eventsOf(body: string): any[] {
  return body
    .split("\n")
    .filter((line) => line.startsWith("data: "))
    .map((line) => JSON.parse(line.slice(6)));
}

async function streamChat(payload: Record<string, unknown>): Promise<Response> {
  return fetch(`${appURL}/api/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

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

test("POST /api/chat/stream on the openai provider streams text as it arrives", async () => {
  openaiScript.push([
    ": OPENROUTER PROCESSING\n\n",
    openaiDelta({ role: "assistant", content: "" }),
    openaiDelta({ content: "Your cluster " }),
    openaiDelta({ content: "runs 2 pods." }),
    openaiDelta({}, "stop"),
    DONE,
  ]);

  const res = await streamChat({ message: "how many pods?", provider: "openai" });

  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") || "", /text\/event-stream/);
  const body = await res.text();
  // Each delta is its own text frame, not one frame with the whole answer.
  assert.match(body, /event: text\ndata: \{"type":"text","delta":"Your cluster "\}/);
  assert.match(body, /event: text\ndata: \{"type":"text","delta":"runs 2 pods."\}/);
  assert.deepEqual(eventsOf(body), [
    { type: "text", delta: "Your cluster " },
    { type: "text", delta: "runs 2 pods." },
    { type: "done", model: GATEWAY_MODEL },
  ]);
  assert.equal(openaiRequests[0].stream, true);
});

test("POST /api/chat/stream on the openai provider reports tool activity before the answer", async () => {
  openaiScript.push([
    openaiDelta({ role: "assistant", content: null }),
    openaiDelta({ tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "get_cluster_pods", arguments: "" } }] }),
    openaiDelta({ tool_calls: [{ index: 0, function: { arguments: '{"namespace":' } }] }),
    openaiDelta({ tool_calls: [{ index: 0, function: { arguments: '"argocd"}' } }] }),
    openaiDelta({}, "tool_calls"),
    DONE,
  ]);
  openaiScript.push([openaiDelta({ content: "2 pods." }), openaiDelta({}, "stop"), DONE]);

  const res = await streamChat({ message: "how many pods?", provider: "openai" });

  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /event: tool_use\ndata: \{"type":"tool_use","name":"get_cluster_pods","id":"call_1"\}/);
  assert.match(body, /event: tool_result\ndata: \{"type":"tool_result","name":"get_cluster_pods","ok":true\}/);
  assert.deepEqual(eventsOf(body), [
    { type: "tool_use", name: "get_cluster_pods", id: "call_1" },
    { type: "tool_result", name: "get_cluster_pods", ok: true },
    { type: "text", delta: "2 pods." },
    { type: "done", model: GATEWAY_MODEL },
  ]);
  assert.deepEqual(toolCalls, [{ name: "get_cluster_pods", arguments: { namespace: "argocd" } }]);
  // The result went back to the model under the call id it issued.
  const toolMessage = openaiRequests[1].messages.at(-1);
  assert.equal(toolMessage.role, "tool");
  assert.equal(toolMessage.tool_call_id, "call_1");
});

test("POST /api/chat/stream on the openai provider ends a failed stream with an error frame after the text already sent", async () => {
  openaiScript.push([
    openaiDelta({ content: "Partial answer" }),
    `data: ${JSON.stringify({ error: { message: "rate limited", code: 429 } })}\n\n`,
  ]);

  const res = await streamChat({ message: "hi", provider: "openai" });

  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /event: error\n/);
  assert.deepEqual(eventsOf(body), [
    { type: "text", delta: "Partial answer" },
    { type: "error", error: "The AI provider is rate-limiting requests right now. Please retry in a few seconds." },
  ]);
});
