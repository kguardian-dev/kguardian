import test from "node:test";
import assert from "node:assert/strict";
import { ChatRequestSchema, MessageSchema, LLMProvider } from "./index.js";

// Zod schema contract tests. The explicit max() and min() bounds in
// these schemas are the request-validation gate at the express
// boundary; a regression that loosens them either lets oversized
// payloads burn through provider TPM limits, or accepts malformed
// shapes that crash the downstream provider call.

test("MessageSchema accepts valid roles", () => {
  for (const role of ["user", "assistant", "system"]) {
    const out = MessageSchema.parse({ role, content: "hi" });
    assert.equal(out.role, role);
  }
});

test("MessageSchema rejects an unknown role", () => {
  // 'tool' is a real OpenAI role but NOT one of the three the bridge
  // accepts — guarding against future drift where someone adds 'tool'
  // to the provider but forgets to update the gate.
  assert.throws(() => MessageSchema.parse({ role: "tool", content: "x" }));
});

test("MessageSchema enforces content length cap (50_000)", () => {
  const ok = MessageSchema.parse({ role: "user", content: "a".repeat(50_000) });
  assert.equal(ok.content.length, 50_000);
  assert.throws(
    () => MessageSchema.parse({ role: "user", content: "a".repeat(50_001) }),
    "content >50_000 chars must be rejected to protect provider TPM",
  );
});

test("ChatRequestSchema rejects empty message", () => {
  // .min(1) — empty messages are degenerate and the downstream
  // provider would reject them anyway. Fail at the boundary.
  assert.throws(() => ChatRequestSchema.parse({ message: "" }));
});

test("ChatRequestSchema enforces 50_000-char message cap", () => {
  ChatRequestSchema.parse({ message: "a".repeat(50_000) });
  assert.throws(() => ChatRequestSchema.parse({ message: "a".repeat(50_001) }));
});

test("ChatRequestSchema enforces 2_000-char context cap", () => {
  ChatRequestSchema.parse({ message: "hi", context: "a".repeat(2_000) });
  assert.throws(
    () => ChatRequestSchema.parse({ message: "hi", context: "a".repeat(2_001) }),
    "context >2_000 chars must be rejected (LLM context budget)",
  );
});

test("ChatRequestSchema enforces 100-message history cap", () => {
  const make = (n: number) =>
    Array.from({ length: n }, () => ({ role: "user" as const, content: "hi" }));

  ChatRequestSchema.parse({ message: "x", history: make(100) });
  assert.throws(
    () => ChatRequestSchema.parse({ message: "x", history: make(101) }),
    "history >100 must be rejected (provider context window)",
  );
});

test("ChatRequestSchema accepts known LLMProvider values", () => {
  for (const p of [LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.GEMINI, LLMProvider.COPILOT]) {
    const r = ChatRequestSchema.parse({ message: "hi", provider: p });
    assert.equal(r.provider, p);
  }
});

test("ChatRequestSchema rejects unknown provider strings", () => {
  // 'mistral' might be a valid LLM but isn't in our provider enum.
  assert.throws(() =>
    ChatRequestSchema.parse({ message: "hi", provider: "mistral" as any }),
  );
});

test("ChatRequestSchema: optional fields are truly optional", () => {
  // Bare-minimum payload — only `message` is required.
  const r = ChatRequestSchema.parse({ message: "hello" });
  assert.equal(r.message, "hello");
  assert.equal(r.provider, undefined);
  assert.equal(r.history, undefined);
});
