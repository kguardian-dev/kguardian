import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { callGemini } from "./gemini.js";
import { McpClient } from "../mcpClient.js";
import type { ChatRequest } from "../types/index.js";

// Mock of the Gemini generateContent API. Gemini's path carries both the API
// version and the model id, so these tests exist mainly to prove the model
// default and the base URL compose into the right path — the mistake here is
// easy to make and invisible until a request 404s.

interface MockResponse {
  status: number;
  body: unknown;
}

let server: http.Server;
let origin = "";
let responseQueue: MockResponse[] = [];
let capturedPaths: string[] = [];

function textResponse(text: string): MockResponse {
  return { status: 200, body: { candidates: [{ content: { parts: [{ text }] } }] } };
}

before(async () => {
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      capturedPaths.push(req.url ?? "");
      const next = responseQueue.shift() ?? textResponse("default");
      res.writeHead(next.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(next.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${port}`;

  process.env.GOOGLE_API_KEY = "test-key";
  (McpClient as unknown as { getToolsCached: () => Promise<unknown[]> }).getToolsCached =
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
  capturedPaths = [];
  delete process.env.GEMINI_BASE_URL;
  delete process.env.GEMINI_MODEL;
});

const stubBroker = { executeTool: async () => ({ data: {} }) } as unknown as McpClient;
const baseRequest: ChatRequest = { message: "hello", provider: undefined } as ChatRequest;

test("GEMINI_BASE_URL override: the versioned model path is appended to the base", async () => {
  process.env.GEMINI_BASE_URL = `${origin}/gemini`;
  responseQueue.push(textResponse("hello world"));

  const res = await callGemini({ ...baseRequest }, stubBroker);

  assert.equal(res.message, "hello world");
  assert.deepEqual(capturedPaths, ["/gemini/v1beta/models/gemini-2.0-flash:generateContent"]);
});

test("a trailing slash on the base does not double up in the path", async () => {
  process.env.GEMINI_BASE_URL = `${origin}/`;
  responseQueue.push(textResponse("hello world"));

  await callGemini({ ...baseRequest }, stubBroker);

  assert.deepEqual(capturedPaths, ["/v1beta/models/gemini-2.0-flash:generateContent"]);
});

test("GEMINI_MODEL replaces the default, and request.model still wins", async () => {
  process.env.GEMINI_BASE_URL = origin;
  process.env.GEMINI_MODEL = "gemini-custom";
  responseQueue.push(textResponse("a"));
  responseQueue.push(textResponse("b"));

  const fromEnv = await callGemini({ ...baseRequest }, stubBroker);
  assert.equal(fromEnv.model, "gemini-custom");

  const fromRequest = await callGemini({ ...baseRequest, model: "gemini-2.5-pro" }, stubBroker);
  assert.equal(fromRequest.model, "gemini-2.5-pro");

  assert.deepEqual(capturedPaths, [
    "/v1beta/models/gemini-custom:generateContent",
    "/v1beta/models/gemini-2.5-pro:generateContent",
  ]);
});

test("whitespace-only GEMINI_MODEL counts as unset", async () => {
  process.env.GEMINI_BASE_URL = origin;
  process.env.GEMINI_MODEL = "  ";
  responseQueue.push(textResponse("hello world"));

  const res = await callGemini({ ...baseRequest }, stubBroker);

  assert.equal(res.model, "gemini-2.0-flash");
});

test("malformed GEMINI_BASE_URL rejects with a message naming the env var", async () => {
  process.env.GEMINI_BASE_URL = "generativelanguage.googleapis.com";

  await assert.rejects(
    () => callGemini({ ...baseRequest }, stubBroker),
    /GEMINI_BASE_URL is not a valid URL/,
  );
  assert.deepEqual(capturedPaths, [], "fails before any request is sent");
});

test("a 404 from the gateway explains which URL was called and which var to fix", async () => {
  process.env.GEMINI_BASE_URL = origin;
  responseQueue.push({ status: 404, body: { error: { message: "Not Found" } } });

  await assert.rejects(
    () => callGemini({ ...baseRequest }, stubBroker),
    (error: Error) => {
      assert.match(error.message, /Gemini API error: Not Found/);
      assert.match(error.message, /returned 404/);
      assert.match(error.message, /check GEMINI_BASE_URL/);
      return true;
    },
  );
});
