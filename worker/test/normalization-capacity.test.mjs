import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { limits } from "../dist/contract.js";
import { assessmentLimits } from "../dist/assessment-contract.js";
import { parseWorkflow } from "../dist/n8n.js";
import { createContext } from "../dist/static-context.js";
import { staticLocationSchema } from "../dist/static-contract.js";
import {
  summarizeFunction,
  functionSummarySchema,
} from "../dist/assessment-summary.js";

const encode = (value) => Buffer.from(JSON.stringify(value));
const hash = (value) => createHash("sha256").update(value).digest("hex");
const fixture = (size, ring = false) => ({
  nodes: Array.from({ length: size }, (_, index) => ({
    id: `node-${index}`,
    name: `node-${index}`,
    type: "n8n-nodes-base.noOp",
    typeVersion: 1,
    parameters: {},
  })),
  connections: Object.fromEntries(
    Array.from({ length: ring ? size : Math.max(0, size - 1) }, (_, index) => [
      `node-${index}`,
      {
        main: [
          [{ node: `node-${(index + 1) % size}`, type: "main", index: 0 }],
        ],
      },
    ]),
  ),
});

test("91-node synthetic exports preserve every node and original byte identity", () => {
  const raw = fixture(91);
  const bytes = encode(raw);
  const before = hash(bytes);
  const normalized = parseWorkflow(bytes);
  assert.equal(normalized.nodes.length, 91);
  assert.equal(normalized.edges.length, 90);
  assert.equal(normalized.nodes.at(-1).pointer, "/nodes/90");
  assert.equal(new Set(normalized.nodes.map((node) => node.key)).size, 91);
  assert.deepEqual(
    normalized.nodes.map((node) => node.raw),
    raw.nodes,
  );
  assert.equal(hash(bytes), before);
});

test("128-node boundary is accepted and 129 nodes still fail before normalization", () => {
  assert.equal(limits.nodes, 128);
  const maximum = fixture(limits.nodes);
  const parsed = parseWorkflow(encode(maximum));
  assert.equal(parsed.nodes.length, limits.nodes);
  assert.equal(parsed.edges.length, limits.nodes - 1);
  assert.throws(() => parseWorkflow(encode(fixture(limits.nodes + 1))), {
    code: "graph_limit",
    pointer: "/nodes",
  });
});

test("larger graphs retain the independent 128-edge cap and broken-edge checks", () => {
  assert.equal(limits.edges, 128);
  const maximum = fixture(limits.nodes, true);
  assert.equal(parseWorkflow(encode(maximum)).edges.length, limits.edges);
  maximum.connections["node-0"].main[0].push({
    node: "node-2",
    type: "main",
    index: 0,
  });
  assert.throws(() => parseWorkflow(encode(maximum)), {
    code: "graph_limit",
    pointer: "/connections",
  });
  const broken = fixture(91);
  broken.connections["node-0"].main[0][0].node = "nonexistent";
  assert.throws(() => parseWorkflow(encode(broken)), {
    code: "broken_connection",
    pointer: "/connections",
  });
});

test("summary and safe-location schemas cover the accepted final node only", () => {
  const context = createContext(encode(fixture(limits.nodes)));
  const summary = functionSummarySchema.parse(summarizeFunction(context));
  assert.equal(summary.nodes.length, limits.nodes);
  const location = {
    nodeKey: context.nodes.at(-1).key,
    pointer: `/nodes/${limits.nodes - 1}/parameters`,
  };
  assert.deepEqual(staticLocationSchema.parse(location), location);
  assert.equal(
    staticLocationSchema.safeParse({
      ...location,
      pointer: `/nodes/${limits.nodes}/parameters`,
    }).success,
    false,
  );
});

test("capacity expansion keeps byte, depth, execution and child-workflow budgets", () => {
  assert.equal(limits.fileBytes, 256 * 1024);
  assert.equal(limits.depth, 32);
  assert.equal(limits.analysisTimeoutMs, 3000);
  assert.equal(limits.subprocessHeapMiB, 96);
  assert.equal(assessmentLimits.timeoutMs, 180000);
  assert.equal(assessmentLimits.resultBytes, 2 * 1024 * 1024);
  assert.equal(assessmentLimits.children, 8);
  assert.equal(assessmentLimits.depth, 3);
  assert.throws(() => parseWorkflow(Buffer.alloc(limits.fileBytes + 1, 32)), {
    code: "file_too_large",
  });
  const duplicate = fixture(91);
  duplicate.nodes.at(-1).id = duplicate.nodes[0].id;
  assert.throws(() => parseWorkflow(encode(duplicate)), {
    code: "identity_collision",
    pointer: "/nodes/90",
  });
});
