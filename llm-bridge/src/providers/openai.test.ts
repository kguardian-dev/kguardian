import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { callOpenAI, callCopilot, streamOpenAI, streamCopilot } from "./openai.js";
import { McpClient } from "../mcpClient.js";
import type { ChatRequest } from "../types/index.js";
import type { ProviderError, StreamEvent } from "./events.js";

// A scripted mock of an OpenAI-compatible gateway, standing in for the
// LiteLLM/vLLM deployments this configurability exists for. It records the
// request PATH as well as the body, because the whole point of the base-URL
// support is which URL we end up calling. Nothing here touches the network
// beyond loopback: every test sets *_BASE_URL to this server, so a regression
// that ignored the override would fail by trying to reach the real API rather
// than by silently passing.

// A JSON reply, or a scripted SSE body written one chunk at a time. `dropAfter`
// cuts the socket before that chunk to imitate an upstream that dies mid-stream;
// `hang` never ends the response and keeps sending comment pings, the way a
// gateway keepalive does, so a test can prove the client releases the socket.
interface MockResponse {
  status: number;
  body?: unknown;
  sse?: string[];
  dropAfter?: number;
  hang?: boolean;
}

let server: http.Server;
let origin = "";
let responseQueue: MockResponse[] = [];
let capturedPaths: string[] = [];
let capturedBodies: any[] = [];
// Resolves when the socket of the current `hang` response closes; pending
// (never vacuously resolved) until the mock serves one.
let hungSocketClosed: Promise<void> = new Promise(() => {});

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
    req.on("end", async () => {
      capturedPaths.push(req.url ?? "");
      capturedBodies.push(raw ? JSON.parse(raw) : null);
      const next = responseQueue.shift() ?? completion("default");
      if (next.hang) {
        // Attach before any byte is written, so a client that tears down
        // immediately cannot close the socket before we start listening.
        const socket = req.socket;
        hungSocketClosed = new Promise((resolve) => socket.once("close", () => resolve()));
      }
      if (next.sse) {
        res.writeHead(next.status, { "Content-Type": "text/event-stream" });
        for (let i = 0; i < next.sse.length; i++) {
          if (next.dropAfter === i) {
            res.socket?.destroy();
            return;
          }
          res.write(next.sse[i]);
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
        if (next.hang) {
          const socket = req.socket;
          const ping = setInterval(() => {
            if (socket.destroyed) clearInterval(ping);
            else res.write(": ping\n\n");
          }, 50);
          socket.once("close", () => clearInterval(ping));
          return;
        }
        res.end();
        return;
      }
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
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  responseQueue = [];
  capturedPaths = [];
  capturedBodies = [];
  hungSocketClosed = new Promise(() => {});
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

// Streaming path. The mock speaks `stream: true` chat completions: one `data:`
// frame per delta, tool calls arriving as fragments keyed by index, and the
// `[DONE]` sentinel, the way OpenAI, OpenRouter, LiteLLM and vLLM do.

const DONE = "data: [DONE]\n\n";

function frame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function delta(d: Record<string, unknown>, finish: string | null = null, model = "gpt-4o"): string {
  return frame({
    id: "chatcmpl-1",
    object: "chat.completion.chunk",
    model,
    choices: [{ index: 0, delta: d, finish_reason: finish }],
  });
}

function textStream(parts: string[], model = "gpt-4o"): MockResponse {
  return {
    status: 200,
    sse: [
      delta({ role: "assistant", content: "" }, null, model),
      ...parts.map((part) => delta({ content: part }, null, model)),
      delta({}, "stop", model),
      DONE,
    ],
  };
}

function toolCallStream(name: string, argumentFragments: string[], id = "call_1"): MockResponse {
  return {
    status: 200,
    sse: [
      delta({ role: "assistant", content: null }),
      delta({ tool_calls: [{ index: 0, id, type: "function", function: { name, arguments: "" } }] }),
      ...argumentFragments.map((fragment) => delta({ tool_calls: [{ index: 0, function: { arguments: fragment } }] })),
      delta({}, "tool_calls"),
      DONE,
    ],
  };
}

interface RecordedCall {
  name: string;
  arguments: unknown;
}

function recordingBroker(calls: RecordedCall[], onCall?: () => void): McpClient {
  return {
    executeTool: async (toolCall: RecordedCall) => {
      calls.push(toolCall);
      onCall?.();
      return { data: { ok: true, tool: toolCall.name } };
    },
  } as unknown as McpClient;
}

async function collect(
  req: ChatRequest,
  broker: McpClient,
  stream: typeof streamOpenAI = streamOpenAI,
  signal?: AbortSignal,
): Promise<StreamEvent[]> {
  const events: StreamEvent[] = [];
  await stream(req, broker, (e) => events.push(e), signal);
  return events;
}

const textOf = (events: StreamEvent[]): string[] =>
  events.filter((e) => e.type === "text").map((e) => (e as { delta: string }).delta);

test("streams text as separate events and ends with done carrying the stream's model", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push(textStream(["Hello", ", ", "world"], "anthropic/claude-sonnet-5"));

  const events = await collect({ ...baseRequest }, stubBroker());

  assert.deepEqual(textOf(events), ["Hello", ", ", "world"]);
  assert.deepEqual(events.at(-1), { type: "done", model: "anthropic/claude-sonnet-5" });
  assert.deepEqual(capturedPaths, ["/v1/chat/completions"]);
  assert.equal(capturedBodies[0].stream, true);
  assert.equal(capturedBodies[0].tool_choice, "auto");
  assert.equal(capturedBodies[0].tools.length, 1);
});

test("assembles a tool call from its fragments, reports the activity, and feeds the result back", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push(toolCallStream("get_cluster_pods", ['{"names', 'pace":"argocd"}']));
  responseQueue.push(textStream(["done"]));

  const calls: RecordedCall[] = [];
  const events = await collect({ ...baseRequest }, recordingBroker(calls));

  assert.deepEqual(calls, [{ name: "get_cluster_pods", arguments: { namespace: "argocd" } }]);
  assert.deepEqual(events, [
    { type: "tool_use", name: "get_cluster_pods", id: "call_1" },
    { type: "tool_result", name: "get_cluster_pods", ok: true },
    { type: "text", delta: "done" },
    { type: "done", model: "gpt-4o" },
  ]);

  const followUp = capturedBodies[1].messages;
  const assistant = followUp.at(-2);
  const tool = followUp.at(-1);
  assert.equal(assistant.role, "assistant");
  assert.equal(assistant.content, null);
  assert.deepEqual(assistant.tool_calls, [
    { id: "call_1", type: "function", function: { name: "get_cluster_pods", arguments: '{"namespace":"argocd"}' } },
  ]);
  assert.equal(tool.role, "tool");
  assert.equal(tool.tool_call_id, "call_1");
  assert.equal(tool.content, JSON.stringify({ ok: true, tool: "get_cluster_pods" }));
});

test("parallel tool calls interleaved by index are assembled separately and answered in order", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    sse: [
      delta({ tool_calls: [{ index: 0, id: "call_a", type: "function", function: { name: "get_cluster_pods", arguments: "" } }] }),
      delta({ tool_calls: [{ index: 1, id: "call_b", type: "function", function: { name: "list_services", arguments: "" } }] }),
      delta({
        tool_calls: [
          { index: 0, function: { arguments: '{"namespace":' } },
          { index: 1, function: { arguments: '{"namespace":"b"}' } },
        ],
      }),
      delta({ tool_calls: [{ index: 0, function: { arguments: '"a"}' } }] }),
      delta({}, "tool_calls"),
      DONE,
    ],
  });
  responseQueue.push(textStream(["ok"]));

  const calls: RecordedCall[] = [];
  const events = await collect({ ...baseRequest }, recordingBroker(calls));

  assert.deepEqual(calls, [
    { name: "get_cluster_pods", arguments: { namespace: "a" } },
    { name: "list_services", arguments: { namespace: "b" } },
  ]);
  assert.deepEqual(
    events.filter((e) => e.type === "tool_use").map((e) => (e as { id: string }).id),
    ["call_a", "call_b"],
  );
  assert.equal(events.filter((e) => e.type === "tool_result").length, 2);
  const toolMessages = capturedBodies[1].messages.filter((m: { role: string }) => m.role === "tool");
  assert.deepEqual(toolMessages.map((m: { tool_call_id: string }) => m.tool_call_id), ["call_a", "call_b"]);
});

test("reasoning deltas surface as thinking events ahead of the answer", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    sse: [
      delta({ reasoning_content: "checking" }),
      delta({ reasoning: " more" }),
      delta({ content: "ok" }),
      delta({}, "stop"),
      DONE,
    ],
  });

  const events = await collect({ ...baseRequest }, stubBroker());

  assert.deepEqual(events, [
    { type: "thinking", delta: "checking" },
    { type: "thinking", delta: " more" },
    { type: "text", delta: "ok" },
    { type: "done", model: "gpt-4o" },
  ]);
});

test("an error frame mid-stream rejects with the gateway's message and keeps the text already streamed", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    sse: [delta({ content: "Partial" }), frame({ error: { message: "Provider returned error", code: 502 } })],
  });

  const events: StreamEvent[] = [];
  await assert.rejects(
    () => streamOpenAI({ ...baseRequest }, stubBroker(), (e) => events.push(e)),
    (error: ProviderError) => {
      assert.equal(error.message, "OpenAI API error: Provider returned error");
      assert.equal(error.status, 502);
      return true;
    },
  );
  assert.deepEqual(events, [{ type: "text", delta: "Partial" }]);
});

test("a connection cut mid-stream rejects instead of hanging or passing as complete", { timeout: 5000 }, async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ content: "Part" }), delta({ content: "ial" })], dropAfter: 1 });

  const events: StreamEvent[] = [];
  await assert.rejects(
    () => streamOpenAI({ ...baseRequest }, stubBroker(), (e) => events.push(e)),
    /OpenAI API error: stream ended unexpectedly/,
  );
  assert.deepEqual(events, [{ type: "text", delta: "Part" }]);
});

test("a malformed frame fails the turn rather than silently dropping part of the answer", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ content: "a" }), "data: {not json\n\n"] });

  await assert.rejects(
    () => streamOpenAI({ ...baseRequest }, stubBroker(), () => {}),
    /OpenAI API error: malformed stream chunk/,
  );
});

test("an error status on the streaming request reports the upstream message and status", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 429, body: { error: { message: "Rate limit reached" } } });

  await assert.rejects(
    () => streamOpenAI({ ...baseRequest }, stubBroker(), () => {}),
    (error: ProviderError) => {
      assert.equal(error.message, "OpenAI API error: Rate limit reached");
      assert.equal(error.status, 429);
      return true;
    },
  );

  responseQueue.push({ status: 404, body: { error: { message: "Not Found" } } });
  await assert.rejects(
    () => streamOpenAI({ ...baseRequest }, stubBroker(), () => {}),
    (error: Error) => {
      assert.match(error.message, /OpenAI API error: Not Found/);
      assert.match(error.message, new RegExp(`POST ${origin}/v1/chat/completions returned 404`));
      assert.match(error.message, /check OPENAI_BASE_URL/);
      return true;
    },
  );
});

test("a gateway that ignores stream:true and answers with JSON still completes the turn", async () => {
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
            tool_calls: [{ id: "call_1", type: "function", function: { name: "get_cluster_pods", arguments: "{}" } }],
          },
        },
      ],
    },
  });
  responseQueue.push(completion("done"));

  const calls: RecordedCall[] = [];
  const events = await collect({ ...baseRequest }, recordingBroker(calls));

  assert.deepEqual(calls, [{ name: "get_cluster_pods", arguments: {} }]);
  assert.deepEqual(events, [
    { type: "tool_use", name: "get_cluster_pods", id: "call_1" },
    { type: "tool_result", name: "get_cluster_pods", ok: true },
    { type: "text", delta: "done" },
    { type: "done", model: "gpt-4o" },
  ]);
  assert.equal(capturedBodies[0].stream, true);
});

test("a silent turn explains itself instead of ending with a blank answer", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ role: "assistant" }), delta({}, "length"), DONE] });
  const cutOff = await collect({ ...baseRequest }, stubBroker());
  assert.deepEqual(textOf(cutOff), [
    "The response was cut off because it hit the length limit. Please narrow the question or ask for a shorter answer.",
  ]);
  assert.equal(cutOff.at(-1)?.type, "done");

  responseQueue.push({ status: 200, sse: [DONE] });
  const nothing = await collect({ ...baseRequest }, stubBroker());
  assert.deepEqual(textOf(nothing), ["No response from OpenAI"]);
  assert.equal(nothing.at(-1)?.type, "done");
});

test("a stream that closes without [DONE] still completes", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ content: "fin" }), delta({}, "stop")] });

  const events = await collect({ ...baseRequest }, stubBroker());

  assert.deepEqual(events, [
    { type: "text", delta: "fin" },
    { type: "done", model: "gpt-4o" },
  ]);
});

test("an empty arguments string is a call with no arguments, not a parse failure", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push(toolCallStream("get_cluster_pods", []));
  responseQueue.push(textStream(["ok"]));

  const calls: RecordedCall[] = [];
  const events = await collect({ ...baseRequest }, recordingBroker(calls));

  assert.deepEqual(calls, [{ name: "get_cluster_pods", arguments: {} }]);
  assert.deepEqual(events[1], { type: "tool_result", name: "get_cluster_pods", ok: true });
});

test("a client abort between rounds ends the turn quietly with no further requests", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push(toolCallStream("get_cluster_pods", ["{}"]));
  responseQueue.push(textStream(["never sent"]));

  const abort = new AbortController();
  const calls: RecordedCall[] = [];
  const events = await collect({ ...baseRequest }, recordingBroker(calls, () => abort.abort()), streamOpenAI, abort.signal);

  assert.equal(calls.length, 1);
  assert.equal(capturedPaths.length, 1, "no request is made after the abort");
  assert.deepEqual(events.map((e) => e.type), ["tool_use", "tool_result"]);
});

test("a client abort mid-stream resolves without an error and emits nothing further", { timeout: 5000 }, async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  // Everything in one write, so the deltas after the abort are already
  // buffered client-side: the outcome must not depend on TCP framing.
  responseQueue.push({ status: 200, sse: [textStream(["first", "second", "third"]).sse!.join("")] });

  const abort = new AbortController();
  const events: StreamEvent[] = [];
  await streamOpenAI(
    { ...baseRequest },
    stubBroker(),
    (e) => {
      events.push(e);
      if (e.type === "text") abort.abort();
    },
    abort.signal,
  );

  assert.deepEqual(events, [{ type: "text", delta: "first" }]);
});

async function closedWithin(ms: number): Promise<boolean> {
  return Promise.race([
    hungSocketClosed.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), ms)),
  ]);
}

test("an error frame on a connection the gateway keeps open still releases the socket", { timeout: 5000 }, async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    sse: [delta({ content: "Partial" }), frame({ error: { message: "boom", code: 502 } })],
    hang: true,
  });

  await assert.rejects(() => streamOpenAI({ ...baseRequest }, stubBroker(), () => {}), /OpenAI API error: boom/);

  assert.equal(await closedWithin(2000), true, "upstream socket closed after the error frame");
});

test("a malformed frame on a connection the gateway keeps open still releases the socket", { timeout: 5000 }, async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ content: "a" }), "data: {nope\n\n"], hang: true });

  await assert.rejects(() => streamOpenAI({ ...baseRequest }, stubBroker(), () => {}), /malformed stream chunk/);

  assert.equal(await closedWithin(2000), true, "upstream socket closed after the malformed frame");
});

test("a client abort on a connection the gateway keeps open releases the socket", { timeout: 5000 }, async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({ status: 200, sse: [delta({ content: "first" })], hang: true });

  const abort = new AbortController();
  await streamOpenAI({ ...baseRequest }, stubBroker(), () => abort.abort(), abort.signal);

  assert.equal(await closedWithin(2000), true, "upstream socket closed after the abort");
});

test("[DONE] with surrounding whitespace and empty-data keepalives do not fail the turn", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  responseQueue.push({
    status: 200,
    sse: [delta({ content: "a" }), "data:\n\n", delta({ content: "b" }), delta({}, "stop"), "data: [DONE] \n\n"],
  });

  const events = await collect({ ...baseRequest }, stubBroker());

  assert.deepEqual(textOf(events), ["a", "b"]);
  assert.equal(events.at(-1)?.type, "done");
});

test("after the max tool rounds the final request streams without tools", async () => {
  process.env.OPENAI_BASE_URL = `${origin}/v1`;
  for (let i = 0; i < 10; i++) responseQueue.push(toolCallStream("get_cluster_pods", ["{}"], `call_${i}`));
  responseQueue.push(textStream(["summary"]));

  const events = await collect({ ...baseRequest }, stubBroker());

  assert.equal(capturedPaths.length, 11, "10 tool rounds plus the final summary request");
  assert.equal(events.filter((e) => e.type === "tool_use").length, 10);
  assert.deepEqual(events.at(-2), { type: "text", delta: "summary" });
  assert.equal(events.at(-1)?.type, "done");
  const last = capturedBodies[10];
  assert.equal(last.stream, true);
  assert.equal(last.tools, undefined);
  assert.equal(last.tool_choice, undefined);
});

test("Copilot streams through its own base URL and model", async () => {
  process.env.COPILOT_BASE_URL = origin;
  process.env.COPILOT_MODEL = "gpt-4.1";
  responseQueue.push(textStream(["hi"], "gpt-4.1"));

  const events = await collect({ ...baseRequest }, stubBroker(), streamCopilot);

  assert.deepEqual(capturedPaths, ["/chat/completions"]);
  assert.equal(capturedBodies[0].model, "gpt-4.1");
  assert.deepEqual(events, [
    { type: "text", delta: "hi" },
    { type: "done", model: "gpt-4.1" },
  ]);
});
