import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/workflow/static-context.js";
import { analyzeFlow } from "../dist/rules/static-flow.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";

const node = (name, type, typeVersion, parameters = {}, raw = {}) => ({
  id: name,
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
  ...raw,
});
const input = () => node("Input", "webhook", 2.1);
const request = (url = "={{ $('Input').first().json.body.url }}") =>
  node("Request", "httpRequest", 4.2, { url });
const stop = (parameters, raw) =>
  node("Fail", "stopAndError", 1, parameters, raw);
const edge = (name, index = 0) => ({ node: name, type: "main", index });
function scan(nodes, change) {
  const document = {
    nodes,
    connections: Object.fromEntries(
      nodes
        .slice(0, -1)
        .map((n, i) => [n.name, { main: [[edge(nodes[i + 1].name)]] }]),
    ),
  };
  change?.(document);
  const context = createContext(Buffer.from(JSON.stringify(document)));
  const rules = analyzeFlow(context).map((r) => ruleResultSchema.parse(r));
  return {
    context,
    rules,
    findings: rules.flatMap((r) => r.findings),
    diagnostics: rules.flatMap((r) => r.diagnostics),
  };
}
const has = (result, code) =>
  result.findings.some((f) => f.evidence.some((e) => e.code === code));
const opaque = (result, name) =>
  result.diagnostics.filter(
    (d) =>
      d.code === "opaque_node_effects" &&
      d.location.nodeKey === result.context.nodeByName.get(name).key,
  );

test("Limit preserves current JSON source without claiming a numeric guard", () => {
  for (const parameters of [
    {},
    { maxItems: 2, keep: "firstItems" },
    { maxItems: 2, keep: "lastItems", options: {} },
  ]) {
    const result = scan([
      input(),
      node("Select", "limit", 1, parameters),
      request("={{ $json.body.url }}"),
    ]);
    assert.equal(opaque(result, "Select").length, 0);
    assert.ok(result.findings.some((f) => f.claim === "supported_path"));
    assert.ok(
      !result.diagnostics.some((d) => d.code === "input_provenance_unresolved"),
    );
  }
  const result = scan([
    input(),
    node("Select", "limit", 1),
    node("Query", "postgres", 2.5, {
      operation: "executeQuery",
      query: "SELECT name FROM users WHERE id = {{ $json.body.id }}",
    }),
  ]);
  assert.ok(has(result, "dynamic_sql_text"));
});

test("Limit rejects coercion, dynamic selection, future versions and nonstandard execution", () => {
  for (const parameters of [
    { maxItems: null },
    { maxItems: "1" },
    { maxItems: 0 },
    { maxItems: -1 },
    { maxItems: 1.5 },
    { maxItems: 1000001 },
    { maxItems: "={{ $json.count }}" },
    { keep: ["firstItems"] },
    { keep: "future" },
    { options: { future: true } },
  ]) {
    assert.equal(
      opaque(
        scan([input(), node("Select", "limit", 1, parameters), request()]),
        "Select",
      ).length,
      4,
    );
  }
  for (const raw of [
    { continueOnFail: true },
    { alwaysOutputData: true },
    { executeOnce: true },
    { onError: "continueErrorOutput" },
  ]) {
    assert.equal(
      opaque(
        scan([input(), node("Select", "limit", 1, {}, raw), request()]),
        "Select",
      ).length,
      4,
    );
  }
  assert.equal(
    opaque(scan([input(), node("Select", "limit", 9), request()]), "Select")
      .length,
    4,
  );
});

test("Merge append accepts each declared input for explicit source references, not current source identity", () => {
  for (const version of [3, 3.1, 3.2]) {
    for (const current of [false, true]) {
      const result = scan(
        [
          input(),
          node("Join", "merge", version, { mode: "append", numberInputs: 3 }),
          request(current ? "={{ $json.body.url }}" : undefined),
        ],
        (doc) => {
          doc.connections.Input.main[0][0].index = 2;
        },
      );
      assert.equal(opaque(result, "Join").length, 0);
      assert.equal(
        result.diagnostics.some(
          (d) => d.code === "input_provenance_unresolved",
        ),
        current,
      );
      assert.equal(
        result.findings.some((f) => f.claim === "supported_path"),
        !current,
      );
    }
  }
});

test("Merge combine, invalid ports/counts and undeclared options remain opaque", () => {
  for (const parameters of [
    { mode: null },
    { mode: "combine" },
    { mode: "combineBySql", query: "SELECT * FROM input1" },
    { mode: "append", numberInputs: "2" },
    { mode: "append", numberInputs: 11 },
    { mode: "append", options: { future: true } },
  ]) {
    assert.equal(
      opaque(
        scan([input(), node("Join", "merge", 3.2, parameters), request()]),
        "Join",
      ).length,
      4,
    );
  }
  for (const change of [
    (doc) => {
      doc.connections.Input.main[0][0].index = 2;
    },
    (doc) => {
      doc.connections.Join.main.unshift([]);
    },
  ]) {
    const result = scan(
      [input(), node("Join", "merge", 3.2, { mode: "append" }), request()],
      change,
    );
    assert.equal(opaque(result, "Join").length, 4);
    assert.ok(!result.findings.some((f) => f.claim === "supported_path"));
  }
});

test("Merge defaults to append with two inputs and supports a fixed declared input count", () => {
  for (const parameters of [{}, { numberInputs: 4 }]) {
    const result = scan(
      [input(), node("Join", "merge", 3.2, parameters), request()],
      (doc) => {
        doc.connections.Input.main[0][0].index =
          (parameters.numberInputs ?? 2) - 1;
      },
    );
    assert.equal(opaque(result, "Join").length, 0);
    assert.ok(result.findings.some((f) => f.claim === "supported_path"));
  }
});

test("Split Out validates local JSON restructuring without preserving current paths", () => {
  for (const version of [1, 1.1]) {
    for (const parameters of [
      { fieldToSplitOut: "body.items" },
      {
        fieldToSplitOut: "$json.body.items",
        include: "allOtherFields",
        options: {
          destinationFieldName: "selected",
          disableDotNotation: false,
          includeBinary: false,
        },
      },
      {
        fieldToSplitOut: "body.items",
        include: "selectedOtherFields",
        fieldsToInclude: "body.kind",
      },
    ]) {
      const direct = scan([
        input(),
        node("Split", "splitOut", version, parameters),
        request(),
      ]);
      assert.equal(opaque(direct, "Split").length, 0);
      assert.ok(direct.findings.some((f) => f.claim === "supported_path"));
      const current = scan([
        input(),
        node("Split", "splitOut", version, parameters),
        request("={{ $json.body.url }}"),
      ]);
      assert.ok(
        current.diagnostics.some(
          (d) => d.code === "input_provenance_unresolved",
        ),
      );
    }
  }
});

test("Split Out leaves binary, unsafe or dynamic fields and malformed destination profiles opaque", () => {
  for (const parameters of [
    { fieldToSplitOut: "$binary" },
    { fieldToSplitOut: "body[0]" },
    { fieldToSplitOut: "constructor.value" },
    { fieldToSplitOut: "={{ $json.field }}" },
    { fieldToSplitOut: "body.items", options: { includeBinary: true } },
    { fieldToSplitOut: "body.items", include: "selectedOtherFields" },
    { fieldToSplitOut: "body.items", include: ["allOtherFields"] },
    { fieldToSplitOut: "body.items", options: { destinationFieldName: "a,b" } },
    {
      fieldToSplitOut: "body.items",
      options: { destinationFieldName: "__proto__" },
    },
  ]) {
    assert.equal(
      opaque(
        scan([input(), node("Split", "splitOut", 1, parameters), request()]),
        "Split",
      ).length,
      4,
    );
  }
});

test("Error Trigger is an error-data source, never an incoming webhook carrier", () => {
  const generated = scan([
    node("Errors", "errorTrigger", 1),
    request("={{ $json.body.url }}"),
  ]);
  assert.equal(opaque(generated, "Errors").length, 0);
  assert.ok(
    generated.diagnostics.some((d) => d.code === "input_provenance_unresolved"),
  );
  const fabricated = scan([
    input(),
    node("Errors", "errorTrigger", 1),
    request(),
  ]);
  assert.equal(opaque(fabricated, "Errors").length, 4);
  assert.ok(!fabricated.findings.some((f) => f.claim === "supported_path"));
});

test("Stop and Error detects secret, personal and whole-input payloads", () => {
  for (const [expression, code] of [
    ["={{ $json.body.password }}", "secret_candidate_in_error_payload"],
    ["={{ $json.body.email }}", "personal_data_candidate_in_error_payload"],
    ["={{ $json }}", "whole_input_in_error_payload"],
    ["={{ JSON.stringify($json) }}", "whole_input_in_error_payload"],
  ]) {
    const result = scan([input(), stop({ errorMessage: expression })]);
    assert.ok(has(result, code), code);
    assert.ok(result.findings.every((f) => f.claim === "candidate"));
    assert.ok(
      result.findings.every((f) =>
        f.assumptions.includes("error_storage_visibility_unverified"),
      ),
    );
  }
});

test("Stop and Error examines full errorObject metadata and keeps literal strings literal", () => {
  const metadata = scan([
    input(),
    stop({
      errorType: "errorObject",
      errorObject:
        '{"message":"Request failed","metadata":{"password":"SYNTHETIC_PRIVATE_MARKER"}}',
    }),
  ]);
  assert.ok(has(metadata, "secret_candidate_in_error_payload"));
  const result = scan([
    input(),
    stop({
      errorType: "errorObject",
      errorObject: '{"message":"={{ $json.body.password }}"}',
    }),
  ]);
  assert.ok(!has(result, "secret_candidate_in_error_payload"));
  const dynamic = scan([
    input(),
    stop({
      errorType: "errorObject",
      errorObject:
        "={{ JSON.stringify({message:'failed',details:$json.body.password}) }}",
    }),
  ]);
  assert.ok(has(dynamic, "secret_candidate_in_error_payload"));
});

test("Stop and Error uses the selected field, not a stale unselected error object", () => {
  const result = scan([
    input(),
    stop({
      errorMessage: "PUBLIC_ERROR_CODE",
      errorObject: "={{ $json.body.password }}",
    }),
  ]);
  assert.ok(!has(result, "secret_candidate_in_error_payload"));
  assert.ok(!has(result, "whole_input_in_error_payload"));
  assert.equal(opaque(result, "Fail").length, 0);
  const noInput = scan([stop({ errorMessage: "PUBLIC_ERROR_CODE" })]);
  assert.equal(noInput.findings.length, 0);
  const missingInput = scan([
    stop({ errorMessage: "={{ $json.body.password }}" }),
  ]);
  assert.ok(
    missingInput.diagnostics.some(
      (d) => d.code === "error_payload_provenance_unresolved",
    ),
  );
});

test("Stop and Error distinguishes rewritten current data from explicit source references", () => {
  const map = node("Map", "set", 3.4, {
    assignments: {
      assignments: [
        { name: "summary", type: "string", value: "PUBLIC_ERROR_CODE" },
      ],
    },
  });
  const current = scan([
    input(),
    map,
    stop({ errorMessage: "={{ $json.summary }}" }),
  ]);
  assert.ok(!has(current, "secret_candidate_in_error_payload"));
  const original = scan([
    input(),
    map,
    stop({ errorMessage: "={{ $('Input').first().json.body.password }}" }),
  ]);
  assert.ok(has(original, "secret_candidate_in_error_payload"));
});

test("Stop and Error preserves uncertainty for prototype reads, malformed metadata and unknown modes", () => {
  for (const parameters of [
    { errorMessage: "={{ $json.constructor.password }}" },
    { errorType: "future", errorMessage: "={{ $json.body.password }}" },
    { errorType: ["errorMessage"], errorMessage: "PUBLIC" },
    { errorType: "errorObject", errorObject: "{" },
    { errorType: "errorObject", errorObject: "[]" },
    { errorMessage: null },
  ]) {
    const result = scan([input(), stop(parameters)]);
    assert.ok(result.diagnostics.length > 0);
    assert.ok(!result.findings.some((f) => f.claim === "supported_path"));
    assert.ok(
      result.rules
        .find((r) => r.category === "output")
        .coverage.some(
          (c) => c.status === "partial" || c.status === "unsupported",
        ),
    );
  }
  const unknown = scan([
    input(),
    stop({ errorType: "future", errorMessage: "={{ $json.body.password }}" }),
  ]);
  assert.ok(has(unknown, "secret_candidate_in_error_payload"));
});

test("Stop and Error never runs expressions, leaks raw fields or assumes error continuation semantics", () => {
  const result = scan([
    input(),
    stop(
      {
        errorMessage:
          "={{ globalThis.__errorOutputProbe($json.body.password) }}",
      },
      { onError: "continueErrorOutput" },
    ),
  ]);
  assert.equal(globalThis.__errorOutputProbe, undefined);
  assert.ok(
    result.diagnostics.some(
      (d) => d.code === "nonstandard_execution_semantics",
    ),
  );
  assert.ok(
    result.diagnostics.some(
      (d) => d.code === "error_payload_provenance_unresolved",
    ),
  );
  const marker = "SYNTHETIC_PRIVATE_MARKER";
  const masked = scan([
    input(),
    stop({
      errorType: "errorObject",
      errorObject: JSON.stringify({ message: marker, password: marker }),
    }),
  ]);
  const serialized = JSON.stringify(masked.rules);
  assert.ok(!serialized.includes(marker));
  assert.ok(!serialized.includes("password"));
  assert.ok(!serialized.includes("Input"));
});

test("Stop and Error cannot fabricate a downstream main path", () => {
  const result = scan([input(), stop({ errorMessage: "PUBLIC" }), request()]);
  assert.equal(opaque(result, "Fail").length, 3);
  assert.ok(!result.findings.some((f) => f.claim === "supported_path"));
  const disabled = scan([
    input(),
    stop({ errorMessage: "={{ $json.body.password }}" }, { disabled: true }),
  ]);
  assert.ok(!has(disabled, "secret_candidate_in_error_payload"));
});

test("Unknown connectors and nonstandard AI topology stay visible", () => {
  const result = scan([input(), node("Cloud", "telegram", 1.2), request()]);
  assert.equal(opaque(result, "Cloud").length, 4);
  const auxiliary = scan(
    [input(), node("Select", "limit", 1), request()],
    (doc) => {
      doc.connections.Select.ai_tool = [
        [{ node: "Request", type: "ai_tool", index: 0 }],
      ];
    },
  );
  assert.equal(opaque(auxiliary, "Select").length, 4);
  assert.ok(
    auxiliary.diagnostics.some((d) => d.code === "partial_workflow_topology"),
  );
});

test("error payload findings respect the contract budget and expose every omitted location", () => {
  const payload =
    "={{ JSON.stringify({password:$json.body.password,email:$json.body.email,body:$json}) }}";
  const make = (count, extraSecret = false) => {
    const failures = Array.from({ length: count }, (_, i) =>
      node(`Failure${i}`, "stopAndError", 1, { errorMessage: payload }),
    );
    if (extraSecret)
      failures.push(
        node("LastSecret", "stopAndError", 1, {
          errorMessage: "={{ $json.body.password }}",
        }),
      );
    return scan([input(), ...failures], (doc) => {
      doc.connections = {
        Input: { main: [failures.map((n) => edge(n.name))] },
      };
    });
  };
  for (const [count, extraSecret, expected] of [
    [85, false, 255],
    [85, true, 256],
  ]) {
    const result = make(count, extraSecret);
    assert.equal(result.findings.length, expected);
    assert.ok(
      !result.diagnostics.some((d) => d.code === "definition_finding_limit"),
    );
  }
  const result = make(90);
  const output = result.rules.find((r) => r.category === "output");
  assert.equal(output.findings.length, 256);
  assert.equal(output.findings.filter((f) => f.severity === "high").length, 90);
  assert.equal(new Set(output.findings.map((f) => f.id)).size, 256);
  for (const n of result.context.nodes.filter((n) =>
    n.type.endsWith(".stopAndError"),
  )) {
    const retained = output.findings.filter(
      (f) => f.location.nodeKey === n.key,
    );
    if (retained.length === 3) continue;
    const limit = output.diagnostics.find(
      (d) =>
        d.code === "definition_finding_limit" && d.location.nodeKey === n.key,
    );
    assert.ok(limit, "each omitted payload location remains visible");
    assert.ok(
      output.coverage.some(
        (c) =>
          c.location.nodeKey === n.key &&
          c.status === "partial" &&
          c.diagnosticIds.includes(limit.id),
      ),
    );
  }
});
