import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { analyzeFlow } from "../dist/static-flow.js";
import { ruleResultSchema } from "../dist/static-contract.js";

const node = (name, type, typeVersion, parameters = {}) => ({
  id: name,
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const input = () => node("Input", "webhook", 2.1);
const request = (url = "={{ $('Input').first().json.body.url }}") =>
  node("Request", "httpRequest", 4.2, { url });
const set = (parameters = {}) =>
  node("Map", "set", 3.4, {
    assignments: {
      assignments: [
        { name: "url", type: "string", value: "={{ $json.body.url }}" },
      ],
    },
    ...parameters,
  });
const aggregate = (parameters = {}) =>
  node("Group", "aggregate", 1, {
    fieldsToAggregate: {
      fieldToAggregate: [
        { fieldToAggregate: "body.url", outputFieldName: "values" },
      ],
    },
    ...parameters,
  });
const branch = (parameters = {}) =>
  node("Branch", "switch", 3.4, {
    rules: {
      values: [
        {
          conditions: {
            options: { typeValidation: "strict", version: 3 },
            combinator: "and",
            conditions: [
              {
                leftValue: "={{ $json.body.kind }}",
                rightValue: "include",
                operator: { type: "string", operation: "equals" },
              },
            ],
          },
        },
      ],
    },
    ...parameters,
  });
function scan(nodes, change) {
  const document = {
    nodes,
    connections: Object.fromEntries(
      nodes
        .slice(0, -1)
        .map((n, i) => [
          n.name,
          { main: [[{ node: nodes[i + 1].name, type: "main", index: 0 }]] },
        ]),
    ),
  };
  change?.(document);
  const context = createContext(Buffer.from(JSON.stringify(document)));
  return {
    context,
    rules: analyzeFlow(context).map((rule) => ruleResultSchema.parse(rule)),
  };
}
const codes = (rules) =>
  rules.flatMap((rule) => rule.diagnostics.map(({ code }) => code));
const findings = (rules) => rules.flatMap((rule) => rule.findings);
const assertOpaque = (target) => {
  const { context, rules } = scan([input(), target, request()]);
  const key = context.nodeByName.get(target.name).key;
  assert.ok(
    rules.every((rule) =>
      rule.diagnostics.some(
        (d) => d.code === "opaque_node_effects" && d.location.nodeKey === key,
      ),
    ),
  );
};

test("malformed Switch operators remain opaque without coercion or a scan crash", () => {
  for (const value of [["string"], { toString: null }, null, 1]) {
    const target = branch();
    target.parameters.rules.values[0].conditions.conditions[0].operator.type =
      value;
    assertOpaque(target);
  }
});

test("validated Set and Aggregate effects enable explicit source paths without assuming unchanged values", () => {
  for (const target of [
    set(),
    set({ mode: "raw", jsonOutput: '{"url":"public"}' }),
    aggregate(),
    aggregate({ aggregate: "aggregateAllItemData" }),
  ]) {
    const direct = scan([input(), target, request()]).rules;
    assert.ok(!codes(direct).includes("opaque_node_effects"));
    assert.ok(!codes(direct).includes("input_provenance_unresolved"));
    assert.ok(
      findings(direct).some((finding) => finding.claim === "supported_path"),
    );
    const current = scan([
      input(),
      target,
      request("={{ $json.body.url }}"),
    ]).rules;
    assert.ok(codes(current).includes("input_provenance_unresolved"));
    assert.ok(
      !findings(current).some((finding) => finding.claim === "supported_path"),
    );
  }
});

test("Switch rules and extra fallback preserve input sources on valid declared output ports", () => {
  for (const fallback of [undefined, "none", 0, "0", "extra"]) {
    const target = branch({
      options: fallback === undefined ? {} : { fallbackOutput: fallback },
    });
    const result = scan(
      [input(), target, request("={{ $json.body.url }}")],
      (document) => {
        if (fallback === "extra") document.connections.Branch.main.unshift([]);
      },
    ).rules;
    assert.ok(!codes(result).includes("opaque_node_effects"));
    assert.ok(!codes(result).includes("input_provenance_unresolved"));
    assert.ok(
      findings(result).some((finding) => finding.claim === "supported_path"),
    );
  }
});

test("Switch output count does not promote its conditions to a numeric SQL guard", () => {
  const query = node("Query", "postgres", 2.5, {
    operation: "executeQuery",
    query: "SELECT name FROM users WHERE id = {{ $json.body.id }}",
  });
  const rules = scan([input(), branch(), query]).rules;
  assert.ok(!codes(rules).includes("opaque_node_effects"));
  assert.ok(
    findings(rules).some(
      (finding) =>
        finding.category === "sql" && finding.claim === "supported_path",
    ),
  );
  assert.ok(!JSON.stringify(rules).includes("numeric_guarded"));
});

test("data-effect expressions parse bounded n8n reads and never invoke unknown calls", () => {
  for (const value of [
    "={{ $json['body'].url }}",
    "={{ $('Input').first().json.body.url }}",
    "={{ $input.item.json.body.url }}",
    "={{ $json.body.url || 'public' }}",
    "={{ $json.body.count + 1 }}",
  ]) {
    const rules = scan([
      input(),
      set({
        assignments: {
          assignments: [{ name: "value", type: "string", value }],
        },
      }),
      request(),
    ]).rules;
    assert.ok(!codes(rules).includes("opaque_node_effects"), value);
  }
  for (const value of [
    "={{ $json.body.invoke() }}",
    "={{ $input.first().first() }}",
    "={{ (() => 7)() }}",
    "={{ globalThis.__staticEffectProbe = 1 }}",
    "={{ $json.constructor.constructor('return 1')() }}",
    "={{ $json[$json.body.key] }}",
  ]) {
    assertOpaque(
      set({
        assignments: {
          assignments: [{ name: "value", type: "string", value }],
        },
      }),
    );
  }
  assert.equal(globalThis.__staticEffectProbe, undefined);
});

test("malformed Set declarations, unsafe fields and profile limits remain opaque", () => {
  for (const parameters of [
    { mode: null },
    { mode: "future" },
    { mode: "raw", jsonOutput: "{" },
    { mode: "raw", jsonOutput: "[]" },
    { assignments: "malformed" },
    { assignments: { assignments: false } },
    { options: [] },
    { options: { dotNotation: "true" } },
    { duplicateItem: true },
    {
      assignments: {
        assignments: [
          { name: "constructor.value", type: "string", value: "public" },
        ],
      },
    },
    {
      assignments: {
        assignments: [{ name: "value", type: "unreviewed", value: "public" }],
      },
    },
    {
      assignments: {
        assignments: Array.from({ length: 129 }, (_, i) => ({
          name: `v${i}`,
          type: "string",
          value: "public",
        })),
      },
    },
  ])
    assertOpaque(set(parameters));
});

test("malformed Switch modes, fallback selectors, conditions and ports remain opaque", () => {
  for (const parameters of [
    { mode: null },
    { mode: "expression", output: 0, numberOutputs: 1 },
    { rules: { values: [] } },
    { rules: { values: [{ conditions: {} }] } },
    { options: { fallbackOutput: "={{ $json.body.port }}" } },
    { options: { fallbackOutput: null } },
    { options: { fallbackOutput: 1 } },
    { options: { fallbackOutput: -1 } },
    { options: { allMatchingOutputs: "true" } },
  ])
    assertOpaque(branch(parameters));
  for (const target of [set(), aggregate(), branch()]) {
    const result = scan([input(), target, request()], (document) =>
      document.connections[target.name].main.unshift([]),
    ).rules;
    assert.ok(codes(result).includes("opaque_node_effects"));
    assert.ok(codes(result).includes("input_provenance_unresolved"));
  }
});

test("Aggregate malformed mappings and cached upstream validation failures remain opaque", () => {
  const bad = aggregate({
    fieldsToAggregate: {
      fieldToAggregate: [
        { fieldToAggregate: "body.url", outputFieldName: "a" },
        { fieldToAggregate: "body.url", outputFieldName: "b" },
      ],
    },
  });
  assertOpaque(bad);
  const result = scan(
    [input(), set({ includeOtherFields: true }), bad, request()],
    (document) => {
      document.connections.Input.main[0][0].node = "Group";
      document.connections.Group.main[0][0].node = "Map";
      document.connections.Map.main[0][0].node = "Request";
    },
  );
  const key = result.context.nodeByName.get("Group").key;
  assert.ok(
    result.rules.every((rule) =>
      rule.diagnostics.some(
        (d) => d.code === "opaque_node_effects" && d.location.nodeKey === key,
      ),
    ),
  );
});

test("future versions, abnormal execution, unsupported channels and external connectors stay opaque", () => {
  for (const target of [set(), aggregate(), branch()]) {
    assertOpaque({ ...target, typeVersion: 999 });
    assertOpaque({ ...target, continueOnFail: true });
    assertOpaque({ ...target, executeOnce: true });
    const rules = scan([input(), target, request()], (document) => {
      document.connections[target.name].ai_tool = [
        [{ node: "Request", type: "ai_tool", index: 0 }],
      ];
    }).rules;
    assert.ok(codes(rules).includes("opaque_node_effects"));
  }
  assertOpaque(
    node("Connector", "telegram", 1.2, { operation: "sendMessage" }),
  );
});
