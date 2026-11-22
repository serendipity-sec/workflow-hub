import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { limits } from "../dist/contract.js";
import { parseReference, parseWorkflow, WorkflowError } from "../dist/n8n.js";

const fixture = (id) =>
  readFileSync(new URL(`../fixtures/workflows/${id}.json`, import.meta.url));
const encode = (value) => Buffer.from(JSON.stringify(value));
const read = (id) => JSON.parse(fixture(id));
const normalize = (workflow) => parseWorkflow(encode(workflow));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("ID-less imports derive stable internal namespaced identities without modifying raw exports", () => {
  const document = read("interpolated");
  for (const node of document.nodes) delete node.id;
  const input = encode(document);
  const before = parseWorkflow(input);
  const keys = new Map(before.nodes.map((node) => [node.name, node.key]));
  for (const node of before.nodes) {
    assert.equal(node.identity, "name_derived");
    assert.equal(Object.hasOwn(node.raw, "id"), false);
  }
  document.nodes.reverse();
  document.nodes[0].parameters.query = "SELECT 1";
  const after = normalize(document);
  assert.ok(after.nodes.every((node) => node.key === keys.get(node.name)));
  assert.deepEqual(
    JSON.parse(input).nodes.map((node) => Object.hasOwn(node, "id")),
    [false, false],
  );
  assert.notEqual(before.nodes[0].key, hash(before.nodes[0].name));
  // A provided empty/null ID is malformed, not a missing-ID import.
  for (const value of [null, "", 123]) {
    const invalid = JSON.parse(input);
    invalid.nodes[0].id = value;
    rejects(encode(invalid), "invalid_workflow", "/nodes/0");
  }
  const duplicate = JSON.parse(input);
  duplicate.nodes[1].name = duplicate.nodes[0].name;
  rejects(encode(duplicate), "identity_collision", "/nodes/1");
});

function rejects(bytes, code, pointer) {
  assert.throws(
    () => parseWorkflow(bytes),
    (error) => {
      assert.ok(error instanceof WorkflowError);
      assert.equal(error.code, code);
      assert.equal(error.pointer, pointer);
      assert.equal(error.message, code);
      return true;
    },
  );
}

test("preserves field locations, n8n typeVersion, source references, and control edges separately", () => {
  const graph = parseWorkflow(fixture("direct-origin"));
  const [webhook, gate, db] = graph.nodes;
  assert.deepEqual(graph.diagnostics, []);
  assert.equal(webhook.key, hash("node-webhook"));
  assert.equal(webhook.typeVersion, 2);
  assert.equal(gate.typeVersion, 2.2);
  assert.equal(db.typeVersion, 2.8);
  assert.deepEqual(graph.edges, [
    { from: webhook.key, to: gate.key, output: 0, input: 0 },
    { from: gate.key, to: db.key, output: 0, input: 0 },
  ]);
  assert.deepEqual(graph.references, [
    {
      consumer: gate.key,
      pointer: "/nodes/1/parameters/conditions/conditions/0/leftValue",
      reference: { kind: "current", field: "gate" },
      source: null,
    },
    {
      consumer: db.key,
      pointer: "/nodes/2/parameters/query",
      reference: { kind: "direct", field: "id", nodeName: "Webhook" },
      source: webhook.key,
    },
  ]);

  const bound = parseWorkflow(fixture("bound"));
  assert.deepEqual(bound.references, [
    {
      consumer: bound.nodes[1].key,
      pointer: "/nodes/1/parameters/options/queryReplacement",
      reference: { kind: "current", field: "id" },
      source: null,
    },
  ]);
});

test("keeps stable node keys across array reordering and display-name changes while relocating fields", () => {
  const bytes = fixture("direct-origin");
  const before = parseWorkflow(bytes);
  const workflow = JSON.parse(bytes);
  workflow.nodes[0].name = "Webhook renamed";
  workflow.nodes[2].parameters.query =
    workflow.nodes[2].parameters.query.replace(
      "'Webhook'",
      '"Webhook renamed"',
    );
  workflow.nodes.reverse();
  workflow.connections["Webhook renamed"] = workflow.connections.Webhook;
  delete workflow.connections.Webhook;
  const after = normalize(workflow);
  const postgres = after.nodes[0];
  assert.equal(postgres.key, before.nodes[2].key);
  assert.equal(postgres.pointer, "/nodes/0");
  assert.ok(
    after.edges.some(
      (edge) =>
        edge.from === before.nodes[0].key && edge.to === before.nodes[1].key,
    ),
  );
  assert.deepEqual(after.references[0], {
    source: before.nodes[0].key,
    consumer: postgres.key,
    pointer: "/nodes/0/parameters/query",
    reference: { kind: "direct", field: "id", nodeName: "Webhook renamed" },
  });
  assert.deepEqual(after.diagnostics, []);
  assert.notEqual(hash(bytes), hash(encode(workflow)));
});

test("does not widen the expression grammar or evaluate expressions", () => {
  assert.deepEqual(parseReference(" \t$json.body.record_2  "), {
    kind: "current",
    field: "record_2",
  });
  assert.deepEqual(
    parseReference(' $("Webhook v2").first().json.body.record_2 '),
    {
      kind: "direct",
      nodeName: "Webhook v2",
      field: "record_2",
    },
  );
  for (const value of [
    "$json.body[0]",
    "$json.body.id.value",
    "$json.body.id + 1",
    "$('Webhook').item.json.body.id",
    "$('Webhook').first(1).json.body.id",
    "$('임시').first().json.body.id",
    "$('Unused\\Label').first().json.body.id",
    "= $json.body.id",
  ])
    assert.equal(parseReference(value), undefined, value);
});

test("retains false output index across null slots, AI edges, and disabled nodes", () => {
  const workflow = read("reject-branch");
  workflow.connections.If.main[0] = null;
  workflow.nodes[1].disabled = true;
  workflow.connections.Webhook.ai_tool = [
    [{ node: "Postgres", type: "ai_tool", index: 0 }],
  ];
  const {
    nodes: [webhook, gate, db],
    edges,
    unsupportedEdges,
    diagnostics,
  } = normalize(workflow);

  assert.equal(gate.disabled, true);
  assert.equal(edges[1].output, 1);
  assert.deepEqual(unsupportedEdges, [
    { from: webhook.key, to: db.key, channel: "ai_tool", output: 0, input: 0 },
  ]);
  assert.deepEqual(diagnostics, [
    {
      code: "unsupported_config",
      location: "/nodes/1/disabled",
      affected: [gate.key, db.key].sort(),
    },
    {
      code: "unsupported_connection",
      location: "/connections",
      affected: [webhook.key, gate.key, db.key].sort(),
    },
  ]);
});

test("records unsupported transforms, node versions and missing subworkflows with downstream scope", () => {
  for (const [id, code, pointer] of [
    ["code-on-path", "unsupported_node", "/nodes/1/type"],
    ["subworkflow-missing", "subworkflow_missing", "/nodes/1/parameters"],
    ["unsupported-version", "unsupported_version", "/nodes/1/typeVersion"],
  ]) {
    const { nodes, diagnostics } = parseWorkflow(fixture(id));
    assert.deepEqual(diagnostics, [
      {
        code,
        location: pointer,
        affected: nodes
          .slice(1)
          .map(({ key }) => key)
          .sort(),
      },
    ]);
  }

  const inline = read("subworkflow-missing");
  inline.nodes[1].parameters = {
    source: "parameter",
    workflowJson: '{"nodes":[],"connections":{}}',
  };
  assert.equal(normalize(inline).diagnostics[0].code, "unsupported_node");
});

test("excludes saved query and binding fields of unsupported Postgres operations", () => {
  for (const [field, value] of [
    ["operation", "select"],
    ["operation", undefined],
    ["resource", "table"],
    ["resource", undefined],
  ]) {
    const workflow = read("interpolated");
    const parameters = workflow.nodes[1].parameters;
    parameters[field] = value;
    parameters.options.queryReplacement = "={{ [ $json.body.id ] }}";
    const graph = normalize(workflow);
    assert.deepEqual(graph.references, []);
    assert.deepEqual(graph.diagnostics, [
      {
        code: "unsupported_config",
        location: `/nodes/1/parameters/${field}`,
        affected: [graph.nodes[1].key],
      },
    ]);
  }
});

test("marks unfamiliar configuration and unresolved node references without copying input strings", () => {
  const workflow = read("direct-origin");
  workflow.nodes[2].parameters.query =
    workflow.nodes[2].parameters.query.replace("Webhook", "Unresolved label");
  workflow.settings = { executionOrder: "v0" };
  workflow.pinData = { Webhook: [{ synthetic: "workflow pin" }] };
  const graph = normalize(workflow);
  const allKeys = graph.nodes.map(({ key }) => key).sort();
  assert.deepEqual(graph.diagnostics, [
    {
      code: "unsupported_expression",
      location: "/nodes/2/parameters/query",
      affected: [graph.nodes[2].key],
    },
    { code: "unsupported_config", location: "/settings", affected: allKeys },
    { code: "unsupported_config", location: "/pinData", affected: allKeys },
  ]);
  assert.equal(graph.references[1].source, null);
});

test("diagnoses unsupported or malformed templates at the exact carrier fields", () => {
  const workflow = read("direct-origin");
  workflow.nodes[1].parameters.conditions.conditions[0].leftValue =
    "={{ $json.body.gate + 1 }}";
  workflow.nodes[2].parameters.query =
    "SELECT label FROM demo_items WHERE id = {{ $json.body.id";
  workflow.nodes[2].parameters.options.queryReplacement =
    "={{ $json.body.id }}";
  const graph = normalize(workflow);
  assert.deepEqual(graph.references, []);
  assert.deepEqual(
    graph.diagnostics.map(({ code, location }) => [code, location]),
    [
      [
        "unsupported_expression",
        "/nodes/1/parameters/conditions/conditions/0/leftValue",
      ],
      ["unsupported_expression", "/nodes/2/parameters/query"],
      [
        "unsupported_expression",
        "/nodes/2/parameters/options/queryReplacement",
      ],
    ],
  );
  assert.deepEqual(
    graph.diagnostics[0].affected,
    graph.nodes
      .slice(1)
      .map(({ key }) => key)
      .sort(),
  );
});

test("preserves additional ports in recognized but unsupported routing modes", () => {
  const multipleMethods = read("interpolated");
  multipleMethods.nodes[0].parameters.multipleMethods = true;
  multipleMethods.nodes[0].parameters.httpMethod = ["GET", "POST"];
  multipleMethods.connections.Webhook.main.unshift(null);
  const graph = normalize(multipleMethods);
  assert.equal(graph.edges[0].output, 1);
  assert.deepEqual(graph.diagnostics, [
    {
      code: "unsupported_config",
      location: "/nodes/0/parameters/httpMethod",
      affected: graph.nodes.map(({ key }) => key).sort(),
    },
  ]);

  const errorOutput = read("reject-branch");
  const groups = errorOutput.connections.If.main;
  groups.splice(1, 0, null);
  rejects(encode(errorOutput), "broken_connection", "/connections");
  errorOutput.nodes[1].onError = "continueErrorOutput";
  const withErrorOutput = normalize(errorOutput);
  assert.equal(withErrorOutput.edges[1].output, 2);
  assert.deepEqual(withErrorOutput.diagnostics, [
    {
      code: "unsupported_config",
      location: "/nodes/1",
      affected: withErrorOutput.nodes
        .slice(1)
        .map(({ key }) => key)
        .sort(),
    },
  ]);
});

test("rejects decoded duplicate keys, structural corruption, invalid UTF-8, depth and size excess", () => {
  rejects(
    Buffer.from('{"nodes":[],"\\u006eodes":[],"connections":{}}'),
    "duplicate_key",
  );
  rejects(
    Buffer.from('{"nodes":[],"connections":{},"meta":{"k":1,"k":2}}'),
    "duplicate_key",
  );
  rejects(Buffer.from('{"nodes":[],"connections":{},}'), "invalid_json");
  rejects(
    Buffer.from('{"nodes":[],"connections":{},"meta":[01]}'),
    "invalid_json",
  );
  rejects(Buffer.from([0xc3, 0x28]), "invalid_utf8");
  rejects(
    Buffer.from("[".repeat(limits.depth + 1) + "]".repeat(limits.depth + 1)),
    "depth_limit",
  );
  rejects(Buffer.alloc(limits.fileBytes + 1), "file_too_large");
});

test("rejects colliding node IDs or names and broken connection targets, kinds, and indices", () => {
  const duplicateId = read("interpolated");
  duplicateId.nodes[1].id = duplicateId.nodes[0].id;
  rejects(encode(duplicateId), "identity_collision", "/nodes/1");

  const duplicateName = read("interpolated");
  duplicateName.nodes[1].name = duplicateName.nodes[0].name;
  rejects(encode(duplicateName), "identity_collision", "/nodes/1");

  const invalidId = read("interpolated");
  invalidId.nodes[0].id = "\uD800";
  rejects(encode(invalidId), "invalid_workflow", "/nodes/0");

  for (const invalid of [
    { node: "Missing node", type: "main", index: 0 },
    { node: "Postgres", type: "ai_tool", index: 0 },
    { node: "Postgres", type: "main", index: -1 },
    { node: "Postgres", type: "main", index: 1 },
    { node: "Webhook", type: "main", index: 0 },
  ]) {
    const workflow = read("interpolated");
    workflow.connections.Webhook.main[0][0] = invalid;
    rejects(encode(workflow), "broken_connection", "/connections");
  }
});

test("rejects unknown connection channel names even without edges", () => {
  for (const edges of [[], [[{ node: "Postgres", type: "mian", index: 0 }]]]) {
    const workflow = read("interpolated");
    workflow.connections.Webhook.mian = edges;
    rejects(encode(workflow), "broken_connection", "/connections");
  }

  const valid = read("interpolated");
  const type = "ai_languageModel";
  valid.connections.Webhook[type] = [[{ node: "Postgres", type, index: 0 }]];
  const graph = normalize(valid);
  assert.equal(graph.unsupportedEdges[0].channel, type);
  assert.equal(graph.diagnostics[0].code, "unsupported_connection");
});

test("applies node and edge admission limits to main and non-main graph data", () => {
  const excessiveNodes = read("interpolated");
  excessiveNodes.nodes = Array.from({ length: limits.nodes + 1 }, (_, i) => ({
    ...excessiveNodes.nodes[1],
    id: `node-${i}`,
    name: `Node ${i}`,
  }));
  rejects(encode(excessiveNodes), "graph_limit", "/nodes");

  const excessiveEdges = read("interpolated");
  excessiveEdges.connections.Webhook.ai_tool = [
    Array.from({ length: limits.edges }, (_, index) => ({
      node: "Postgres",
      type: "ai_tool",
      index,
    })),
  ];
  rejects(encode(excessiveEdges), "graph_limit", "/connections");
});
