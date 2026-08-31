import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";

import { app } from "./index.js";
import { McpClient } from "./mcpClient.js";

// G3 SSE stream contract.
//
// Records a full assistant session — thinking, a tool round (tool_use +
// tool_result), streamed text, and the terminal done frame — as raw SSE bytes
// plus the decoded event list. The goldens under llm-bridge/contract/ are THE
// stream contract: the frontend parser test (frontend/src/services/
// aiApi.contract.test.ts) replays sse_session.golden.txt and must decode the
// exact event sequence in sse_events.golden.json. A diff on either side is a
// contract change. Regenerate deliberately: UPDATE_GOLDEN=1 npm test

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractDir = path.resolve(__dirname, "..", "contract");

function sse(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

const messageStart = (id: string) =>
  sse("message_start", {
    type: "message_start",
    message: {
      id,
      type: "message",
      role: "assistant",
      model: "claude-opus-4-8",
      content: [],
      stop_reason: null,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 0 },
    },
  });

// Round 1: a summarized-thinking block, then a tool_use block → stop_reason tool_use.
const toolRoundSSE =
  messageStart("msg_contract_1") +
  sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } }) +
  sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "Checking the cluster inventory." } }) +
  sse("content_block_stop", { type: "content_block_stop", index: 0 }) +
  sse("content_block_start", { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "toolu_contract_1", name: "get_cluster_pods", input: {} } }) +
  sse("content_block_delta", { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: "{}" } }) +
  sse("content_block_stop", { type: "content_block_stop", index: 1 }) +
  sse("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 5 } }) +
  sse("message_stop", { type: "message_stop" });

// Round 2: the final streamed text answer.
const textRoundSSE =
  messageStart("msg_contract_2") +
  sse("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }) +
  sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Your cluster runs " } }) +
  sse("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "2 pods." } }) +
  sse("content_block_stop", { type: "content_block_stop", index: 0 }) +
  sse("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 8 } }) +
  sse("message_stop", { type: "message_stop" });

let anthropicMock: http.Server;
let appServer: http.Server;
let appURL = "";
let mockCalls = 0;
let failNext = false;

before(async () => {
  anthropicMock = http.createServer((_req, res) => {
    if (failNext) {
      res.writeHead(529, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ type: "error", error: { type: "overloaded_error", message: "Overloaded" } }));
      return;
    }
    mockCalls += 1;
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.end(mockCalls === 1 ? toolRoundSSE : textRoundSSE);
  });
  await new Promise<void>((resolve) => anthropicMock.listen(0, "127.0.0.1", resolve));
  const mockPort = (anthropicMock.address() as AddressInfo).port;

  process.env.ANTHROPIC_API_KEY = "test-key";
  process.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${mockPort}`;
  delete process.env.OPENAI_API_KEY;
  delete process.env.GOOGLE_API_KEY;
  delete process.env.GITHUB_TOKEN;

  const stub = McpClient as unknown as {
    getToolsCached: () => Promise<unknown[]>;
    prototype: { executeTool: (tc: { name: string }) => Promise<unknown> };
  };
  stub.getToolsCached = async () => [
    { name: "get_cluster_pods", description: "List pods.", parameters: { type: "object", properties: {}, required: [] } },
  ];
  stub.prototype.executeTool = async (tc) => ({
    tool: tc.name,
    result: JSON.stringify([{ pod_name: "web-1" }, { pod_name: "batch-1" }]),
  });

  appServer = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => appServer.once("listening", () => resolve()));
  appURL = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => appServer.close(() => resolve()));
  await new Promise<void>((resolve) => anthropicMock.close(() => resolve()));
});

function checkGolden(name: string, got: string) {
  const p = path.join(contractDir, name);
  if (process.env.UPDATE_GOLDEN) {
    fs.mkdirSync(contractDir, { recursive: true });
    fs.writeFileSync(p, got);
    return;
  }
  const want = fs.readFileSync(p, "utf8");
  assert.equal(
    got,
    want,
    `SSE CONTRACT DRIFT in ${name}. The frontend parser tests against this exact recording; if the change is intentional, regenerate with UPDATE_GOLDEN=1 and update both sides in the same PR.`,
  );
}

test("G3: full session (thinking + tool round + text + done) matches recording", async () => {
  mockCalls = 0;
  failNext = false;
  const res = await fetch(`${appURL}/api/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: "how many pods?", provider: "anthropic" }),
  });
  assert.equal(res.status, 200);
  const body = await res.text();

  checkGolden("sse_session.golden.txt", body);

  // Decoded event list — the canonical sequence the frontend must produce.
  const events = body
    .split("\n")
    .filter((l) => l.startsWith("data: "))
    .map((l) => JSON.parse(l.slice(6)));
  checkGolden("sse_events.golden.json", JSON.stringify(events, null, 2) + "\n");
});

test("G3: upstream overload surfaces as a terminal error frame", async () => {
  failNext = true;
  try {
    const res = await fetch(`${appURL}/api/chat/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hi", provider: "anthropic" }),
    });
    const body = await res.text();
    checkGolden("sse_error.golden.txt", body);
    assert.match(body, /event: error\n/);
  } finally {
    failNext = false;
  }
});
