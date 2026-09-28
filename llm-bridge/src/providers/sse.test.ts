import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";

import { parseSse, withIdleTimeout } from "./sse.js";

async function* chunks(parts: (string | Uint8Array)[]): AsyncGenerator<string | Uint8Array> {
  for (const part of parts) yield part;
}

async function collect(parts: (string | Uint8Array)[]): Promise<string[]> {
  const out: string[] = [];
  for await (const data of parseSse(chunks(parts))) out.push(data);
  return out;
}

test("yields one payload per event and ignores comments and non-data fields", async () => {
  const out = await collect([
    ": OPENROUTER PROCESSING\n\nevent: message\nid: 1\nretry: 5\ndata: {\"a\":1}\n\ndata: [DONE]\n\n",
  ]);
  assert.deepEqual(out, ['{"a":1}', "[DONE]"]);
});

test("reassembles a frame split across chunks, including mid-payload", async () => {
  const out = await collect(["da", "ta: {\"del", "ta\":\"hi\"}\n", "\n", "data: x\n\n"]);
  assert.deepEqual(out, ['{"delta":"hi"}', "x"]);
});

test("accepts CRLF line endings", async () => {
  const out = await collect(["data: a\r\n\r\ndata: b\r\n\r\n"]);
  assert.deepEqual(out, ["a", "b"]);
});

test("joins multi-line data with newlines and strips a single leading space", async () => {
  const out = await collect(["data: line1\ndata:line2\ndata:  spaced\n\n"]);
  assert.deepEqual(out, ["line1\nline2\n spaced"]);
});

test("decodes a multi-byte character split across chunks", async () => {
  const bytes = Buffer.from("data: café — ok\n\n", "utf8");
  // Cut inside the two-byte "é" and again inside the three-byte em dash.
  const out = await collect([bytes.subarray(0, 10), bytes.subarray(10, 13), bytes.subarray(13)]);
  assert.deepEqual(out, ["café — ok"]);
});

test("an empty data buffer is a keepalive, not an event", async () => {
  const out = await collect(["data:\n\ndata: \n\ndata: real\n\n"]);
  assert.deepEqual(out, ["real"]);
});

test("two empty data lines still dispatch a newline, as the spec says", async () => {
  const out = await collect(["data:\ndata:\n\n"]);
  assert.deepEqual(out, ["\n"]);
});

test("delivers a final event that arrives without its blank line", async () => {
  const out = await collect(["data: first\n\ndata: last"]);
  assert.deepEqual(out, ["first", "last"]);
});

test("withIdleTimeout passes chunks through while the source keeps up", async () => {
  async function* slow(): AsyncGenerator<string> {
    yield "a";
    await new Promise((resolve) => setTimeout(resolve, 30));
    yield "b";
  }
  const out: string[] = [];
  for await (const item of withIdleTimeout(slow(), 500)) out.push(item);
  assert.deepEqual(out, ["a", "b"]);
});

test("withIdleTimeout fails once the source stalls longer than the gap", async () => {
  async function* stalls(): AsyncGenerator<string> {
    yield "a";
    await new Promise((resolve) => setTimeout(resolve, 200));
    yield "b";
  }
  const out: string[] = [];
  await assert.rejects(async () => {
    for await (const item of withIdleTimeout(stalls(), 20)) out.push(item);
  }, /no data received for 20ms/);
  assert.deepEqual(out, ["a"]);
});

test("withIdleTimeout destroys a stalled readable so the socket is released", async () => {
  const readable = new Readable({ read() {} });
  await assert.rejects(withIdleTimeout(readable, 20).next(), /no data received/);
  assert.equal(readable.destroyed, true);
});

test("withIdleTimeout releases the source when the consumer stops early", async () => {
  const readable = Readable.from([Buffer.from("a"), Buffer.from("b"), Buffer.from("c")]);
  const seen: string[] = [];
  for await (const chunk of withIdleTimeout(readable, 500)) {
    seen.push(String(chunk));
    break;
  }
  assert.deepEqual(seen, ["a"]);
  assert.equal(readable.destroyed, true);
});
