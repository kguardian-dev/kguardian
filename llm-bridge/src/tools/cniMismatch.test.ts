import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { executeInProcessTool } from "./execute.js";
import { resetClusterCniCache } from "./backendClient.js";

// The CNI-mismatch annotation (issue #1413): generate_network_policy
// with policy_type=cilium on a non-Cilium cluster prepends a WARNING
// comment; kubernetes output and unknown-CNI output stay untouched
// (the parity/G2 fixtures pin the untouched case byte-for-byte).

const here = path.dirname(fileURLToPath(import.meta.url));
const contractDir = path.resolve(here, "../../../test/fixtures/contract");
const fixtures = JSON.parse(
  fs.readFileSync(path.join(contractDir, "backend_fixtures.json"), "utf8"),
) as Record<string, unknown>;

let server: http.Server;
let cniResponse: { status: number; body?: unknown } = { status: 404 };

before(async () => {
  server = http.createServer((req, res) => {
    const urlPath = (req.url || "").split("?")[0];
    if (urlPath === "/cluster/environment") {
      if (cniResponse.body !== undefined) {
        res.writeHead(cniResponse.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(cniResponse.body));
      } else {
        res.writeHead(cniResponse.status);
        res.end();
      }
      return;
    }
    const body = fixtures[urlPath];
    if (body === undefined) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  process.env.BROKER_URL = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

beforeEach(() => {
  resetClusterCniCache();
});

test("cilium policy on a calico cluster is annotated, not altered", async () => {
  cniResponse = { status: 200, body: { cni: "calico" } };
  const res = await executeInProcessTool("generate_network_policy", {
    pod_name: "web-1",
    policy_type: "cilium",
  });
  assert.equal(res.isError, false, res.text);
  assert.ok(res.text.startsWith("# WARNING: cluster CNI detected as 'calico'"), res.text.slice(0, 120));
  // The YAML itself is intact after the one comment line.
  assert.ok(res.text.includes("kind: CiliumNetworkPolicy"));
});

test("cilium policy on a cilium cluster is untouched", async () => {
  cniResponse = { status: 200, body: { cni: "cilium" } };
  const res = await executeInProcessTool("generate_network_policy", {
    pod_name: "web-1",
    policy_type: "cilium",
  });
  assert.equal(res.isError, false, res.text);
  assert.ok(!res.text.startsWith("# WARNING"));
});

test("unknown CNI (older broker 404) leaves output untouched", async () => {
  cniResponse = { status: 404 };
  const res = await executeInProcessTool("generate_network_policy", {
    pod_name: "web-1",
    policy_type: "cilium",
  });
  assert.equal(res.isError, false, res.text);
  assert.ok(!res.text.startsWith("# WARNING"));
});

test("kubernetes policy is never annotated regardless of CNI", async () => {
  cniResponse = { status: 200, body: { cni: "calico" } };
  const res = await executeInProcessTool("generate_network_policy", {
    pod_name: "web-1",
    policy_type: "kubernetes",
  });
  assert.equal(res.isError, false, res.text);
  assert.ok(!res.text.startsWith("# WARNING"));
  assert.ok(res.text.includes("kind: NetworkPolicy"));
});
