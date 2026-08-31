import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";

import { executeInProcessTool } from "./execute.js";
import { TOOL_DEFS } from "./registry.js";

// Parity: the in-process tool layer must reproduce the retired
// mcp-server's tool-call outputs. Replays the shared contract fixtures
// (test/fixtures/contract) that were the mcp-server's Go G1 goldens: broker
// tools must reproduce that output exactly (parsed JSON, key-order
// immaterial); the in-process generate_* tools are wiring-checked here and
// correctness-locked by the G2 generator fixtures. These fixtures are now the
// sole surviving copy of the tool-call contract — this test is its gate.

const here = path.dirname(fileURLToPath(import.meta.url));
const contractDir = path.resolve(here, "../../../test/fixtures/contract");

const fixtures = JSON.parse(fs.readFileSync(path.join(contractDir, "backend_fixtures.json"), "utf8")) as Record<string, unknown>;
const golden = JSON.parse(fs.readFileSync(path.join(contractDir, "tool_calls.golden.json"), "utf8")) as Record<string, { content: { text: string }[] }>;

// One representative call per tool — mirrors the Go contractCalls list.
const CALLS: Record<string, Record<string, unknown>> = {
  get_pod_network_traffic: { pod_name: "web-1" },
  get_pod_syscalls: { pod_name: "web-1" },
  get_pod_details: { ip: "10.0.0.1" },
  get_service_details: { ip: "10.96.0.10" },
  get_cluster_traffic: {},
  get_cluster_pods: {},
  get_pod_details_by_name: { pod_name: "web-1" },
  list_services: {},
  get_pods_on_node: { node: "node-a" },
  get_audit_verdicts: {},
  generate_network_policy: { pod_name: "web-1" },
  generate_seccomp_profile: { pod_name: "web-1" },
};

// Both generate_* tools now run IN-PROCESS rather than proxying to the
// advisor. Their output correctness is proven exhaustively by the G2 generator
// fixture tests (seccomp.fixture.test.ts, networkpolicy.fixture.test.ts) which
// lock every path to the advisor goldens. Here we only assert the tool wiring
// executes without error against the fixture backend — the broker DATA tools
// keep the strict semantic golden comparison below.
const GENERATED_TOOLS = new Set(["generate_network_policy", "generate_seccomp_profile"]);

let server: http.Server;

before(async () => {
  server = http.createServer((req, res) => {
    const urlPath = (req.url || "").split("?")[0];
    // Advisor generate endpoints are keyed in fixtures without the query string.
    const body = fixtures[urlPath];
    if (body === undefined) { res.writeHead(404); res.end(); return; }
    if (typeof body === "string") { res.writeHead(200, { "Content-Type": "text/plain" }); res.end(body); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  process.env.BROKER_URL = `http://127.0.0.1:${port}`;
});

after(async () => { await new Promise<void>((r) => server.close(() => r())); });

test("every registered tool has a parity call", () => {
  for (const t of TOOL_DEFS) assert.ok(CALLS[t.name], `missing parity call for ${t.name}`);
  assert.equal(Object.keys(CALLS).length, TOOL_DEFS.length);
});

for (const [tool, args] of Object.entries(CALLS)) {
  test(`parity: ${tool} reproduces the mcp-server golden`, async () => {
    const got = await executeInProcessTool(tool, args);
    assert.equal(got.isError, false, `${tool} errored: ${got.text}`);

    if (GENERATED_TOOLS.has(tool)) {
      // In-process generator: wiring check only (correctness is G2's job).
      assert.ok(got.text.length > 0, `${tool} produced empty output`);
      return;
    }
    // Broker data tool: strict semantic comparison against the mcp-server golden.
    const goldenText = golden[tool].content[0].text;
    assert.deepEqual(JSON.parse(got.text), JSON.parse(goldenText), `${tool} broker data drift`);
  });
}
