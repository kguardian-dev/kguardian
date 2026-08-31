import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { createMcpRouter } from "./router.js";
import { MCP_PATH } from "./config.js";
import { TOOL_DEFS } from "../tools/registry.js";

// End-to-end test of the MCP endpoint over the real StreamableHTTP transport,
// driven by the SDK's own client: initialize, tools/list, tools/call. Asserting
// against the transport rather than calling the handlers directly is the point
// — a handler can be correct while the wire format is wrong, and the wire
// format is what an external client actually consumes.
//
// Deliberately NOT compared against test/fixtures/contract/tools_list.golden.
// That golden records the retired Go mcp-server's tools/list and the registry
// has since diverged from it on purpose (descriptions moved with generation
// going in-process; the Go schemas carried additionalProperties: false).
// src/tools/parity.test.ts gates the tool-CALL contract against those fixtures
// and stays the authority there; this file gates only that MCP re-serves
// whatever TOOL_DEFS currently says.

let brokerMock: http.Server;
let appServer: http.Server;
let appURL = "";

const POD_ROW = {
  pod_name: "api-7c9f",
  pod_namespace: "shop",
  pod_ip: "10.0.1.7",
  node_name: "node-a",
  is_dead: false,
  // Heavyweight field the compaction layer must strip — proves the MCP path
  // runs the same executor the assistant does, not a thinner copy.
  pod_obj: { metadata: { labels: { app: "api" } } },
};

before(async () => {
  // Stand in for the broker so tool execution is hermetic. /pod/info serves a
  // pod; every other path 500s, which is how the failing-tool case is driven.
  brokerMock = http.createServer((req, res) => {
    if (req.url === "/pod/info") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([POD_ROW]));
      return;
    }
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "boom" }));
  });
  await new Promise<void>((resolve) => brokerMock.listen(0, "127.0.0.1", resolve));
  process.env.BROKER_URL = `http://127.0.0.1:${(brokerMock.address() as AddressInfo).port}`;

  // A bare app with only the pieces index.ts puts in front of the router, so
  // the test exercises the same body-parsing situation production has.
  const app = express();
  app.use(express.json({ limit: "100kb" }));
  app.use(MCP_PATH, createMcpRouter({ enabled: true, authToken: null, rateLimitPerMin: 300 }));

  appServer = http.createServer(app);
  await new Promise<void>((resolve) => appServer.listen(0, "127.0.0.1", resolve));
  appURL = `http://127.0.0.1:${(appServer.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => appServer.close(() => resolve()));
  await new Promise<void>((resolve) => brokerMock.close(() => resolve()));
});

/** Connect an SDK client to the endpoint; the caller closes it. */
async function connect(): Promise<Client> {
  const client = new Client({ name: "mcp-transport-test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${appURL}${MCP_PATH}`)));
  return client;
}

test("tools/list serves exactly the registry, verbatim", async () => {
  const client = await connect();
  try {
    const { tools } = await client.listTools();

    // Derivation, not a snapshot: adding a tool to TOOL_DEFS without touching
    // this file must keep the test passing, and adding one that MCP fails to
    // serve must break it. A hardcoded list of 12 names would do neither.
    assert.equal(tools.length, TOOL_DEFS.length);
    assert.equal(tools.length, 12, "the tool set is 12 tools; a change here is a product decision");
    assert.deepEqual(
      tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      TOOL_DEFS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.parameters })),
    );
  } finally {
    await client.close();
  }
});

test("tools/call round-trips a tool result as text content", async () => {
  const client = await connect();
  try {
    const result = await client.callTool({ name: "get_cluster_pods", arguments: {} });

    // The handler sets isError explicitly rather than omitting it on success;
    // MCP treats an absent flag as false, so both are legal — pinning it here
    // stops the field silently flipping to true on a regression.
    assert.equal(result.isError, false);
    const content = result.content as { type: string; text: string }[];
    assert.equal(content.length, 1);
    assert.equal(content[0].type, "text");

    const parsed = JSON.parse(content[0].text);
    assert.deepEqual(parsed, [
      { pod_name: "api-7c9f", pod_namespace: "shop", pod_ip: "10.0.1.7", node_name: "node-a", is_dead: false },
    ]);
  } finally {
    await client.close();
  }
});

test("tools/call reports a namespace filter reaching the executor", async () => {
  const client = await connect();
  try {
    const result = await client.callTool({ name: "get_cluster_pods", arguments: { namespace: "other" } });
    const content = result.content as { type: string; text: string }[];
    // The mock's single pod is in "shop", so filtering to "other" empties it —
    // proof the arguments object survives the JSON-RPC hop rather than being
    // dropped and the tool running unfiltered.
    assert.deepEqual(JSON.parse(content[0].text), []);
  } finally {
    await client.close();
  }
});

test("a failing tool returns isError, not a protocol error", async () => {
  const client = await connect();
  try {
    // The mock 500s on /pod/syscalls/*, so the tool throws internally. It must
    // come back as a tool-level error the model can read and recover from; a
    // JSON-RPC error would make callTool reject and read to a client as "the
    // server is broken".
    const result = await client.callTool({ name: "get_pod_syscalls", arguments: { pod_name: "api-7c9f" } });

    assert.equal(result.isError, true);
    const content = result.content as { type: string; text: string }[];
    assert.match(content[0].text, /error executing get_pod_syscalls/);
  } finally {
    await client.close();
  }
});

test("an unknown tool is a tool-level error, not a transport failure", async () => {
  const client = await connect();
  try {
    const result = await client.callTool({ name: "definitely_not_a_tool", arguments: {} });
    assert.equal(result.isError, true);
    const content = result.content as { type: string; text: string }[];
    assert.match(content[0].text, /unknown tool/);
  } finally {
    await client.close();
  }
});

test("GET and DELETE are refused with 405 rather than left hanging", async () => {
  // A GET handed to the transport would open a standalone SSE stream that
  // never closes — this server sends no server-initiated messages, so that
  // connection would be pinned open for nothing. The 405 is the spec's own
  // "not offered" answer and is what the SDK client expects. Both requests
  // must also COMPLETE: a regression here shows up as a hung test, not a
  // failed assertion.
  for (const method of ["GET", "DELETE"]) {
    const res = await fetch(`${appURL}${MCP_PATH}`, {
      method,
      headers: { Accept: "application/json, text/event-stream" },
    });
    await res.text();
    assert.equal(res.status, 405, `expected 405 for ${method}`);
    assert.equal(res.headers.get("allow"), "POST");
  }
});
