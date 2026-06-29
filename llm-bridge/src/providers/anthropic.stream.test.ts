import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { streamAnthropic, type StreamEvent } from "./anthropic.js";
import { BrokerClient } from "../brokerClient.js";
import type { ChatRequest } from "../types/index.js";

// Mock of the Anthropic Messages API streaming endpoint. Each request is
// answered with a queued Server-Sent-Events body that the real SDK parses, so
// this exercises the actual streaming client end to end without network egress.

type Block =
  | { kind: "text"; text: string }
  | { kind: "thinking"; thinking: string }
  | { kind: "tool_use"; id: string; name: string };

function sse(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function sseForMessage(blocks: Block[], stopReason: string, model = "claude-opus-4-8"): string {
  let out = sse("message_start", {
    type: "message_start",
    message: {
      id: "msg_test",
      type: "message",
      role: "assistant",
      model,
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 0 },
    },
  });

  blocks.forEach((block, index) => {
    if (block.kind === "text") {
      out += sse("content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } });
      out += sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: block.text } });
    } else if (block.kind === "thinking") {
      out += sse("content_block_start", { type: "content_block_start", index, content_block: { type: "thinking", thinking: "" } });
      out += sse("content_block_delta", { type: "content_block_delta", index, delta: { type: "thinking_delta", thinking: block.thinking } });
    } else {
      out += sse("content_block_start", {
        type: "content_block_start",
        index,
        content_block: { type: "tool_use", id: block.id, name: block.name, input: {} },
      });
    }
    out += sse("content_block_stop", { type: "content_block_stop", index });
  });

  out += sse("message_delta", { type: "message_delta", delta: { stop_reason: stopReason }, usage: { output_tokens: 1 } });
  out += sse("message_stop", { type: "message_stop" });
  return out;
}

let server: http.Server;
let responseQueue: string[] = [];

before(async () => {
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = responseQueue.shift() ?? sseForMessage([{ kind: "text", text: "default" }], "end_turn");
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end(body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${port}`;
  (BrokerClient as unknown as { getToolsCached: () => Promise<unknown[]> }).getToolsCached =
    async () => [
      { name: "get_cluster_pods", description: "List pods.", parameters: { type: "object", properties: {}, required: [] } },
    ];
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  responseQueue = [];
});

function stubBroker(calls: string[]): BrokerClient {
  return {
    executeTool: async (toolCall: { name: string }) => {
      calls.push(toolCall.name);
      return { data: { ok: true } };
    },
  } as unknown as BrokerClient;
}

const baseRequest: ChatRequest = { message: "hello" } as ChatRequest;

async function collect(req: ChatRequest, broker: BrokerClient): Promise<StreamEvent[]> {
  const events: StreamEvent[] = [];
  await streamAnthropic(req, broker, (e) => events.push(e));
  return events;
}

test("streams text deltas then a terminal done event", async () => {
  responseQueue.push(sseForMessage([{ kind: "text", text: "hello world" }], "end_turn"));

  const events = await collect({ ...baseRequest }, stubBroker([]));

  const text = events.filter((e) => e.type === "text").map((e) => (e as { delta: string }).delta).join("");
  assert.equal(text, "hello world");
  const done = events.at(-1);
  assert.equal(done?.type, "done");
  assert.equal((done as { model: string }).model, "claude-opus-4-8");
});

test("emits summarized thinking deltas before the answer", async () => {
  responseQueue.push(
    sseForMessage([{ kind: "thinking", thinking: "pondering" }, { kind: "text", text: "ok" }], "end_turn"),
  );

  const events = await collect({ ...baseRequest }, stubBroker([]));

  const thinking = events.find((e) => e.type === "thinking");
  assert.equal((thinking as { delta: string }).delta, "pondering");
  const text = events.find((e) => e.type === "text");
  assert.equal((text as { delta: string }).delta, "ok");
});

test("tool round emits tool_use + tool_result activity, then streams the answer", async () => {
  responseQueue.push(sseForMessage([{ kind: "tool_use", id: "tu_1", name: "get_cluster_pods" }], "tool_use"));
  responseQueue.push(sseForMessage([{ kind: "text", text: "done" }], "end_turn"));

  const calls: string[] = [];
  const events = await collect({ ...baseRequest }, stubBroker(calls));

  assert.deepEqual(calls, ["get_cluster_pods"], "tool executed once");

  const toolUse = events.find((e) => e.type === "tool_use");
  assert.equal((toolUse as { name: string }).name, "get_cluster_pods");
  assert.equal((toolUse as { id: string }).id, "tu_1");

  const toolResult = events.find((e) => e.type === "tool_result");
  assert.equal((toolResult as { ok: boolean }).ok, true);

  // Activity events precede the final answer text.
  const toolUseIdx = events.findIndex((e) => e.type === "tool_use");
  const textIdx = events.findIndex((e) => e.type === "text");
  assert.ok(toolUseIdx < textIdx, "tool_use is emitted before answer text");

  assert.equal(events.at(-1)?.type, "done");
});
