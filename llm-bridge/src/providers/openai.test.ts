import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { callOpenAI, callCopilot } from "./openai.js";
import { McpClient } from "../mcpClient.js";
import type { ChatRequest } from "../types/index.js";

// A scripted mock of an OpenAI-compatible gateway, standing in for the
// LiteLLM/vLLM deployments this configurability exists for. It records the
// request PATH as well as the body, because the whole point of the base-URL
// support is which URL we end up calling. Nothing here touches the network
// beyond loopback: every test sets *_BASE_URL to this server, so a regression
// that ignored the override would fail by trying to reach the real API rather
// than by silently passing.

interface MockResponse {
  status: number;
  body: unknown;
}

let server: http.Server;
let origin = "";
let responseQueue: MockResponse[] = [];
let capturedPaths: string[] = [];
let capturedBodies: any[] = [];

function completion(content: string, model = "gpt-4o"): MockResponse {
  return {
    status: 200,
    body: { model, choices: [{ message: { role: "assistant", content } }] },
  };
}

before(async () => {
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      capturedPaths.push(req.url ?? "");
      capturedBodies.push(raw ? JSON.parse(raw) : null);
      const next = responseQueue.shift() ?? completion("default");
      res.writeHead(next.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(next.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${port}`;

  process.env.OPENAI_API_KEY = "test-key";
  process.env.GITHUB_TOKEN = "test-token";
  // Deterministic, network-free tool set (the real one is local too, but this
  // keeps the assertions independent of the tool registry).
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
  capturedBodies = [];
  delete process.env.OPENAI_BASE_URL;
  delete process.env.OPENAI_MODEL;
  delete process.env.COPILOT_BASE_URL;
  delete process.env.COPILOT_MODEL;
});

function stubBroker(): McpClient {
  return {
    executeTool: async (toolCall: { name: string }) => ({ data: { ok: true, tool: toolCall.name } }),
  } as unknown as McpClient;
}

const baseRequest: ChatRequest = { message: "hello", provider: undefined } as ChatRequest;

test("OPENAI_BASE_URL override: /chat/completions is appended to the base verbatim", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push(completion("hello world"));

  const res = await callOpenAI({ ...baseRequest }, stubBroker());

  assert.equal(res.message, "hello world");
  assert.equal(res.provider, "openai");
  assert.deepEqual(capturedPaths, ["/v1/chat/completions"]);
});

test("a trailing slash on the base does not double up in the path", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1/`;
  responseQueue.push(completion("hello world"));

  await callOpenAI({ ...baseRequest }, stubBroker());

  assert.deepEqual(capturedPaths, ["/v1/chat/completions"]);
});

test("a base without /v1 is left alone — kguardian never inserts the version segment", async () => {
  // LiteLLM answers on both forms, so honouring the operator's exact choice is
  // what keeps gateways that serve only one of them working.
  process.env.OPENAI_BASE_URL = origin;
  responseQueue.push(completion("hello world"));

  await callOpenAI({ ...baseRequest }, stubBroker());

  assert.deepEqual(capturedPaths, ["/chat/completions"]);
});

test("OPENAI_MODEL replaces the built-in default", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  process.env.OPENAI_MODEL = "llama-3.3-70b";
  responseQueue.push(completion("hello world", "llama-3.3-70b"));

  await callOpenAI({ ...baseRequest }, stubBroker());

  assert.equal(capturedBodies[0].model, "llama-3.3-70b");
});

test("request.model still wins over OPENAI_MODEL", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  process.env.OPENAI_MODEL = "llama-3.3-70b";
  responseQueue.push(completion("hello world"));

  await callOpenAI({ ...baseRequest, model: "mixtral-8x7b" }, stubBroker());

  assert.equal(capturedBodies[0].model, "mixtral-8x7b");
});

test("whitespace-only OPENAI_MODEL counts as unset, not as an empty model id", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  process.env.OPENAI_MODEL = "   ";
  responseQueue.push(completion("hello world"));

  await callOpenAI({ ...baseRequest }, stubBroker());

  assert.equal(capturedBodies[0].model, "gpt-4o");
});

test("malformed OPENAI_BASE_URL rejects with a message naming the env var", async () => {
  process.env.OPENAI_BASE_URL = "litellm:4000/v1";

  // Must be a rejected promise, not a synchronous throw: callOpenAI is a plain
  // function and the HTTP layer only awaits its result.
  await assert.rejects(
    () => callOpenAI({ ...baseRequest }, stubBroker()),
    /OPENAI_BASE_URL is not a valid URL/,
  );
  assert.deepEqual(capturedPaths, [], "fails before any request is sent");
});

test("a 404 from the gateway explains which URL was called and which var to fix", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 404, body: { error: { message: "Not Found" } } });

  await assert.rejects(
    () => callOpenAI({ ...baseRequest }, stubBroker()),
    (error: Error) => {
      assert.match(error.message, /OpenAI API error: Not Found/);
      assert.match(error.message, new RegExp(`POST ${origin}/v1/chat/completions returned 404`));
      assert.match(error.message, /check OPENAI_BASE_URL/);
      return true;
    },
  );
});

test("a non-404 API error keeps its upstream message unadorned", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 401, body: { error: { message: "Invalid API key" } } });

  await assert.rejects(() => callOpenAI({ ...baseRequest }, stubBroker()), (error: Error) => {
    assert.equal(error.message, "OpenAI API error: Invalid API key");
    return true;
  });
});

test("missing API key still fails fast with a clear message", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  const saved = process.env.OPENAI_API_KEY;
  delete process.env.OPENAI_API_KEY;
  try {
    await assert.rejects(
      () => callOpenAI({ ...baseRequest }, stubBroker()),
      /OPENAI_API_KEY not configured/,
    );
  } finally {
    process.env.OPENAI_API_KEY = saved;
  }
});

test("tool loop still runs against a gateway base URL", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    body: {
      model: "gpt-4o",
      choices: [
        {
          message: {
            role: "assistant",
            content: null,
            tool_calls: [
              { id: "call_1", type: "function", function: { name: "get_cluster_pods", arguments: "{}" } },
            ],
          },
        },
      ],
    },
  });
  responseQueue.push(completion("done"));

  const res = await callOpenAI({ ...baseRequest }, stubBroker());

  assert.equal(res.message, "done");
  assert.deepEqual(capturedPaths, ["/v1/chat/completions", "/v1/chat/completions"]);
  const followUp = capturedBodies[1];
  const toolMessage = followUp.messages[followUp.messages.length - 1];
  assert.equal(toolMessage.role, "tool");
  assert.equal(toolMessage.tool_call_id, "call_1");
});

test("Copilot reads its own base URL and model vars", async () => {
  process.env.COPILOT_BASE_URL = origin;
  process.env.COPILOT_MODEL = "gpt-4.1";
  responseQueue.push(completion("hello world", "gpt-4.1"));

  const res = await callCopilot({ ...baseRequest }, stubBroker());

  assert.equal(res.provider, "copilot");
  // Copilot's default base carries no version segment, so the path is bare.
  assert.deepEqual(capturedPaths, ["/chat/completions"]);
  assert.equal(capturedBodies[0].model, "gpt-4.1");
});

test("the post-max-rounds summary request reports failures like the loop does", async () => {
  // The tool loop runs MAX_TOOL_ROUNDS times, then makes one final tool-less
  // request. That request used to throw a raw axios error with no provider
  // label and no endpoint hint.
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  const toolCall = {
    status: 200,
    body: {
      model: "gpt-4o",
      choices: [
        {
          message: {
            role: "assistant",
            content: null,
            tool_calls: [
              { id: "call_1", type: "function", function: { name: "get_cluster_pods", arguments: "{}" } },
            ],
          },
        },
      ],
    },
  };
  for (let i = 0; i < 10; i++) responseQueue.push(toolCall);
  responseQueue.push({ status: 404, body: { error: { message: "Not Found" } } });

  await assert.rejects(
    () => callOpenAI({ ...baseRequest }, stubBroker()),
    (error: Error) => {
      assert.match(error.message, /OpenAI API error: Not Found/);
      assert.match(error.message, /check OPENAI_BASE_URL/);
      return true;
    },
  );
  assert.equal(capturedPaths.length, 11, "10 tool rounds plus the final summary request");
});
