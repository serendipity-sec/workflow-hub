import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow } from "../dist/value-flow.js";
import { analyzeFlow } from "../dist/static-flow.js";
import {
  analyzeExtendedSinks,
  transferDataClasses,
} from "../dist/extended-sinks.js";
import { assessDestination } from "../dist/assessment-policy.js";
import { ruleResultSchema } from "../dist/static-contract.js";

const node = (id, type, typeVersion, parameters = {}) => ({
  id,
  name: id,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const source = () => node("Input", "webhook", 2.1);
function analyze(nodes) {
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes,
        connections: Object.fromEntries(
          nodes.slice(0, -1).map((item, index) => [
            item.name,
            {
              main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]],
            },
          ]),
        ),
      }),
    ),
  );
  const flow = buildValueFlow(context);
  const target = context.nodeByName.get(nodes.at(-1).name).key;
  return { context, flow, output: (path) => flow.output(target, path) };
}
const code = (text) =>
  analyze([source(), node("Code", "code", 2, { jsCode: text })]);

test("fixed interval Wait retains precise input provenance and existing sensitivity", () => {
  for (const version of [1, 1.1]) {
    for (const parameters of [
      {},
      { amount: 0, unit: "seconds" },
      { amount: 2, unit: "hours" },
    ]) {
      const run = analyze([
        source(),
        node("Wait", "wait", version, parameters),
      ]);
      const value = run.output("/body/password");
      assert.equal(value.status, "resolved");
      assert.equal(value.trust, "external");
      assert.equal(value.origins[0].fieldPath, "/body/password");
      assert.ok(value.sensitivityClasses.includes("secret_candidate"));
      assert.equal(run.flow.diagnostics.length, 0);
    }
  }
});

test("Wait resume inputs, dynamic intervals, invalid units and execution modes remain unresolved", () => {
  for (const parameters of [
    { resume: "webhook" },
    { resume: "form" },
    { resume: "specificTime" },
    { resume: null },
    { amount: "={{ $json.body.delay }}" },
    { amount: -1 },
    { unit: "invalid" },
    { unit: ["seconds"] },
    { unit: { toString: "seconds" } },
  ]) {
    const value = analyze([
      source(),
      node("Wait", "wait", 1.1, parameters),
    ]).output("/body/password");
    assert.notEqual(value.status, "resolved");
    assert.equal(value.constant, undefined);
  }
  const wait = node("Wait", "wait", 1.1);
  wait.continueOnFail = true;
  assert.notEqual(
    analyze([source(), wait]).output("/body/password").status,
    "resolved",
  );
});

test("base source-to-sink evidence traverses a validated interval Wait", () => {
  const nodes = [
    source(),
    node("Wait", "wait", 1.1),
    node("Query", "postgres", 2.8, {
      operation: "executeQuery",
      query: "SELECT id FROM records WHERE id = {{ $json.body.id }}",
    }),
  ];
  const { context } = analyze(nodes);
  const sql = analyzeFlow(context).find((rule) => rule.category === "sql");
  assert.ok(sql.findings.some((finding) => finding.claim === "supported_path"));
  assert.ok(
    !sql.diagnostics.some((entry) => entry.code === "opaque_node_effects"),
  );
  nodes[1].parameters.resume = "webhook";
  const unresolved = analyzeFlow(analyze(nodes).context).find(
    (rule) => rule.category === "sql",
  );
  assert.ok(
    unresolved.diagnostics.some(
      (entry) => entry.code === "opaque_node_effects",
    ),
  );
  assert.ok(
    !unresolved.findings.some((finding) => finding.claim === "supported_path"),
  );
});

test("mail, Telegram and form triggers establish external origins without inventing payloads", () => {
  for (const [type, version] of [
    ["gmailTrigger", 1.3],
    ["emailReadImap", 2],
    ["telegramTrigger", 1.2],
    ["formTrigger", 2.3],
  ]) {
    const run = analyze([node("Trigger", type, version)]);
    const value = run.output("/email");
    assert.equal(value.trust, "external");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.ok(value.sensitivityClasses.includes("unknown"));
    assert.ok(
      run.flow.diagnostics.some(
        ({ code }) => code === "trigger_payload_schema_unverified",
      ),
    );
    assert.ok(
      !run.flow.diagnostics.some(
        ({ code }) => code === "node_transform_unsupported",
      ),
    );
    assert.equal(value.constant, undefined);
    assert.equal(value.guards.length, 0);
  }
});

test("mail body candidates survive schema-based source modeling and fabricated incoming edges stay uncertain", () => {
  const run = analyze([node("Trigger", "gmailTrigger", 1.3)]);
  assert.ok(
    run.output("/snippet").sensitivityClasses.includes("pii_candidate"),
  );
  const invalid = analyze([source(), node("Trigger", "gmailTrigger", 1.3)]);
  const value = invalid.output("/snippet");
  assert.ok(
    value.diagnosticCodes.includes("trigger_input_connection_unresolved"),
  );
  assert.notEqual(value.status, "resolved");
});

test("aggregate all-items selection follows exact top-level fields and preserves sensitive descendants", () => {
  const run = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      aggregate: "aggregateAllItemData",
      fieldsToInclude: "body",
      destinationFieldName: "records",
    }),
  ]);
  const value = run.output("/records/7/body/password");
  assert.equal(value.origins[0].fieldPath, "/body/password");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(value.constant, undefined);
  assert.equal(value.guards.length, 0);
  assert.equal(run.output("/elsewhere").presence, "absent");
  const removed = run.output("/records/0/unselected");
  assert.ok(!removed.sensitivityClasses.includes("secret_candidate"));
});

test("aggregate retained hidden include/exclude fields both affect the runtime projection", () => {
  const run = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      aggregate: "aggregateAllItemData",
      include: "allFields",
      fieldsToInclude: "body",
      fieldsToExclude: "body",
    }),
  ]);
  const value = run.output("/data/0/body/password");
  assert.ok(!value.sensitivityClasses.includes("secret_candidate"));
  assert.notEqual(value.status, "resolved");
  const whole = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      aggregate: "aggregateAllItemData",
      fieldsToExclude: "unused",
    }),
  ]).output("/data");
  assert.ok(
    whole.diagnosticCodes.includes("aggregate_excluded_unknown_fields"),
  );
});

test("aggregate individual fields maps nested paths and renames without claiming item alignment", () => {
  const run = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          {
            fieldToAggregate: "body.email",
            renameField: true,
            outputFieldName: "contacts",
          },
          {
            fieldToAggregate: "body.password",
            renameField: true,
            outputFieldName: "private.values",
          },
        ],
      },
    }),
  ]);
  const email = run.output("/contacts/0");
  assert.ok(email.sensitivityClasses.includes("pii_candidate"));
  assert.ok(!email.sensitivityClasses.includes("secret_candidate"));
  assert.equal(email.origins[0].fieldPath, "/body/email");
  const secret = run.output("/private/values/9");
  assert.ok(secret.sensitivityClasses.includes("secret_candidate"));
  assert.equal(secret.origins[0].fieldPath, "/body/password");
  assert.equal(secret.guards.length, 0);
  assert.ok(
    secret.diagnosticCodes.includes("collection_cardinality_unverified"),
  );
});

test("aggregate literal dotted keys, stale output names and nested payload fields follow source semantics", () => {
  const run = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          {
            fieldToAggregate: "a.b",
            renameField: false,
            outputFieldName: "saved.name",
          },
        ],
      },
      options: { disableDotNotation: true },
    }),
  ]);
  const value = run.output("/saved.name/0/password");
  assert.equal(value.origins[0].fieldPath, "/a.b/password");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
});

test("aggregate dynamic keys, prototype keys, conflicting output paths and flattening stay conservative", () => {
  for (const parameters of [
    {
      aggregate: "aggregateAllItemData",
      destinationFieldName: "={{ $json.body.key }}",
    },
    { aggregate: "aggregateAllItemData", destinationFieldName: "__proto__" },
    { aggregate: null },
    { aggregate: "aggregateAllItemData", destinationFieldName: null },
    { aggregate: "aggregateAllItemData", fieldsToInclude: null },
    {
      aggregate: "aggregateAllItemData",
      fieldsToInclude: "={{ $json.body.key }}",
    },
    {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.email", outputFieldName: "v" },
          { fieldToAggregate: "body.password", outputFieldName: "v.a" },
        ],
      },
    },
    {
      fieldsToAggregate: {
        fieldToAggregate: [{ fieldToAggregate: "body[0]" }],
      },
    },
    { options: { unexpected: true } },
  ]) {
    const value = analyze([
      source(),
      node("Aggregate", "aggregate", 1, parameters),
    ]).output("/v");
    assert.notEqual(value.status, "resolved");
    assert.equal(value.constant, undefined);
  }
  const merged = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.password", outputFieldName: "values" },
        ],
      },
      options: { mergeLists: true },
    }),
  ]).output("/values/0");
  assert.ok(
    merged.diagnosticCodes.includes("aggregate_flatten_shape_unverified"),
  );
  assert.ok(merged.sensitivityClasses.includes("secret_candidate"));
});

test("immutable primitive closures use lexical definitions despite caller parameter shadowing", () => {
  const run = code(
    "const prefix='prefix-'; function label(value){return prefix+value;} function wrapper(prefix){return label($json.body.email);} let result=wrapper('other-'); return {json:{result,fixed:'public'}};",
  );
  assert.ok(run.output("/result").sensitivityClasses.includes("pii_candidate"));
  assert.deepEqual(run.output("/fixed").sensitivityClasses, ["public_literal"]);
  assert.ok(
    !run.flow.diagnostics.some(
      ({ code }) => code === "code_closure_capture_unresolved",
    ),
  );
  const constant = code(
    "const value='lexical'; function read(){return value;} function wrapper(value){return read();} let result=wrapper('caller'); return {json:{result}};",
  );
  assert.equal(constant.output("/result").constant, "lexical");
});

test("immutable callback captures retain sensitive input while mutable and object captures stay opaque", () => {
  const mapped = code(
    "const suffix='-fixed'; return $input.all().map(item=>({json:{result:item.json.body.email+suffix,fixed:'public'}}));",
  );
  assert.ok(
    mapped.output("/result").sensitivityClasses.includes("pii_candidate"),
  );
  assert.deepEqual(mapped.output("/fixed").sensitivityClasses, [
    "public_literal",
  ]);
  for (const text of [
    "let value='public'; function read(){return value;} value=$json.body.password; let result=read(); return {json:{result}};",
    "const value={text:'public'}; function read(){return value;} value.text=$json.body.password; let result=read(); return {json:{result}};",
    "function read(){return value;} const value=$json.body.password; let result=read(); return {json:{result}};",
  ]) {
    const run = code(text);
    const result = run.output("/result");
    assert.ok(result.sensitivityClasses.includes("secret_candidate"));
    assert.notEqual(result.status, "resolved");
    assert.equal(result.constant, undefined);
  }
});

test("a caller parameter shadowing a helper cannot invoke the outer helper as a trusted function", () => {
  const run = code(
    "function safe(){return 'public';} function wrapper(safe){return safe();} let result=wrapper($json.body.password); return {json:{result}};",
  );
  const result = run.output("/result");
  assert.notEqual(result.status, "resolved");
  assert.ok(result.sensitivityClasses.includes("secret_candidate"));
  assert.equal(result.constant, undefined);
});

test("Aggregate lodash dotted lookup retains a literal-key alternative rather than proving a public nested value", () => {
  const run = analyze([
    source(),
    node("Map", "code", 2, {
      jsCode:
        "return {json:{a:{value:'public'},'a.value':$json.body.password}};",
    }),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "a.value", outputFieldName: "values" },
        ],
      },
    }),
  ]);
  const value = run.output("/values/0");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(value.constant, undefined);
  assert.ok(
    value.diagnosticCodes.includes(
      "aggregate_dotted_key_resolution_unverified",
    ),
  );
});

test("external trigger source profiles do not accept fabricated output ports", () => {
  const run = analyze([node("Trigger", "gmailTrigger", 1.3)]);
  const key = run.context.nodeByName.get("Trigger").key;
  const value = run.flow.output(key, "/email", 1);
  assert.ok(value.diagnosticCodes.includes("service_output_port_unresolved"));
  assert.notEqual(value.status, "resolved");
  assert.equal(value.guards.length, 0);
});

test("Aggregate retains every candidate when default null filtering shifts nested array indexes", () => {
  for (const options of [
    {},
    { keepMissing: false },
    { keepMissing: false, mergeLists: false },
  ]) {
    const run = analyze([
      source(),
      node("Map", "code", 2, {
        jsCode:
          "return {json:{values:[null,$json.body.password,$json.body.email]}};",
      }),
      node("Aggregate", "aggregate", 1, {
        fieldsToAggregate: {
          fieldToAggregate: [{ fieldToAggregate: "values" }],
        },
        options,
      }),
    ]);
    const value = run.output("/values/0/0");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.ok(value.sensitivityClasses.includes("unknown"));
    assert.ok(
      value.origins.some(({ fieldPath }) => fieldPath === "/body/password"),
    );
    assert.equal(value.constant, undefined);
    assert.equal(value.guards.length, 0);
    assert.ok(
      value.diagnosticCodes.includes(
        "aggregate_null_filter_alignment_unverified",
      ),
    );
  }
  const preserved = analyze([
    source(),
    node("Map", "code", 2, {
      jsCode: "return {json:{values:[null,$json.body.password]}};",
    }),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: { fieldToAggregate: [{ fieldToAggregate: "values" }] },
      options: { keepMissing: true },
    }),
  ]);
  assert.ok(
    !preserved
      .output("/values/0/0")
      .sensitivityClasses.includes("secret_candidate"),
  );
  assert.ok(
    preserved
      .output("/values/0/1")
      .sensitivityClasses.includes("secret_candidate"),
  );
  const unknownList = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.values", outputFieldName: "values" },
        ],
      },
    }),
  ]).output("/values/0/0/password");
  assert.ok(unknownList.sensitivityClasses.includes("secret_candidate"));
  assert.ok(
    unknownList.origins.some(
      ({ fieldPath }) => fieldPath === "/body/values/0/password",
    ),
  );
  assert.ok(
    unknownList.diagnosticCodes.includes(
      "aggregate_null_filter_alignment_unverified",
    ),
  );
});

test("named function expression self-binding never resolves to an outer primitive constant", () => {
  for (const text of [
    "const name='outer'; const helper=function name(value){return name+value;}; let result=helper($json.body.email); return {json:{result}};",
    "const name='outer'; return $input.all().map(function name(item){return {json:{result:name+item.json.body.password}};});",
    "const helper=function name(value){return name+value;}; let result=helper($json.body.email); return {json:{result}};",
  ]) {
    const run = code(text);
    const value = run.output("/result");
    assert.notEqual(value.status, "resolved");
    assert.equal(value.constant, undefined);
    assert.ok(
      value.sensitivityClasses.includes(
        text.includes("password") ? "secret_candidate" : "pii_candidate",
      ),
    );
    assert.ok(
      run.flow.diagnostics.some(
        ({ code }) => code === "code_function_self_binding_unresolved",
      ),
    );
  }
  const parameter = code(
    "const name='outer'; const helper=function name(name){return name;}; let result=helper('parameter'); return {json:{result}};",
  );
  assert.equal(parameter.output("/result").constant, "parameter");
  const self = code(
    "const name='outer'; const helper=function name(){return name;}; let result=helper(); return {json:{result}};",
  ).output("/result");
  assert.equal(self.constant, undefined);
  assert.ok(self.sensitivityClasses.includes("unknown"));
  assert.ok(
    self.diagnosticCodes.includes("code_function_self_binding_unresolved"),
  );
});

test("Aggregate flattening preserves sensitive leaf candidates from object and array possibilities", () => {
  const value = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.items", outputFieldName: "values" },
        ],
      },
      options: { mergeLists: true },
    }),
  ]).output("/values/0/password");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(value.sensitivityClasses.includes("unknown"));
  for (const expected of [
    "/body/items",
    "/body/items/password",
    "/body/items/0/password",
  ]) {
    assert.ok(value.origins.some(({ fieldPath }) => fieldPath === expected));
  }
  assert.equal(value.constant, undefined);
  assert.equal(value.guards.length, 0);
  assert.ok(
    value.diagnosticCodes.includes("aggregate_flatten_shape_unverified"),
  );
});

test("Aggregate reindexing retains supplied descendant policy classes without claiming an exact position", () => {
  for (const options of [{}, { keepMissing: false }, { mergeLists: true }]) {
    const path = options.mergeLists ? "/values/0/label" : "/values/0/0/label";
    const run = analyze([
      source(),
      node("Aggregate", "aggregate", 1, {
        fieldsToAggregate: {
          fieldToAggregate: [
            { fieldToAggregate: "body.values", outputFieldName: "values" },
          ],
        },
        options,
      }),
      node("Send", "httpRequest", 4.4, {
        method: "POST",
        url: "https://example.invalid/ingest",
        sendBody: true,
        contentType: "json",
        specifyBody: "json",
        jsonBody: options.mergeLists
          ? "={{ {value:$json.values[0].label} }}"
          : "={{ {value:$json.values[0][0].label} }}",
      }),
    ]);
    const sourceKey = run.context.nodeByName.get("Input").key;
    const sinkKey = run.context.nodeByName.get("Send").key;
    const value = run.flow.output(
      run.context.nodeByName.get("Aggregate").key,
      path,
    );
    for (const field of ["/body/values/1/label", "body.values.99999.label"]) {
      const evidence = {
        classifications: [{ nodeKey: sourceKey, field, dataClass: "internal" }],
        policy: {
          egress: [
            {
              id: "public-only",
              nodeKey: sinkKey,
              sink: "http",
              mode: "allowlist",
              destinations: ["https://example.invalid/"],
              allowedDataClasses: ["public"],
            },
          ],
        },
      };
      const classes = transferDataClasses(value, evidence);
      assert.ok(classes.includes("internal"));
      assert.ok(classes.includes("unknown"));
      assert.equal(
        assessDestination(
          evidence,
          sinkKey,
          "http",
          "https://example.invalid/",
          classes,
        ).status,
        "disallowed",
      );
      assert.notEqual(value.status, "resolved");
      assert.equal(value.constant, undefined);
      assert.equal(value.guards.length, 0);
      assert.ok(
        value.origins.some((origin) => origin.includesDescendants === true),
      );
      const rules = analyzeExtendedSinks(run.context, run.flow, evidence).map(
        (rule) => ruleResultSchema.parse(rule),
      );
      const findings = rules.flatMap((rule) => rule.findings);
      const disallowed = findings.find((finding) =>
        finding.evidence.some(
          ({ code }) => code === "trusted_policy_transfer_disallowed",
        ),
      );
      assert.ok(disallowed);
      assert.equal(disallowed.claim, "configuration");
      assert.ok(disallowed.assumptions.includes("transfer_not_proof_of_leak"));
      assert.ok(
        rules.some((rule) =>
          rule.diagnostics.some(
            ({ code }) => code === "payload_provenance_unresolved",
          ),
        ),
      );
      assert.ok(
        findings
          .filter((finding) =>
            finding.evidence.some(
              ({ code }) =>
                code === "data_field_transferred" ||
                code === "whole_object_transferred",
            ),
          )
          .every((finding) => finding.claim === "candidate"),
      );
      const report = JSON.stringify(rules);
      assert.ok(!report.includes("includesDescendants"));
      assert.ok(!report.includes(field));
    }
    for (const [nodeKey, field] of [
      [sourceKey, "/body/valuesMore/1/label"],
      [sourceKey, "/body/values~1suffix/1/label"],
      [sinkKey, "/body/values/1/label"],
    ]) {
      assert.ok(
        !transferDataClasses(value, {
          classifications: [{ nodeKey, field, dataClass: "internal" }],
        }).includes("internal"),
      );
    }
    assert.throws(
      () =>
        transferDataClasses(value, {
          classifications: [
            {
              nodeKey: sourceKey,
              field: "/body/values/~2",
              dataClass: "internal",
            },
          ],
        }),
      /invalid_evidence/,
    );
  }
});

test("Aggregate exact preserved indexes do not acquire descendant candidates from other positions", () => {
  const run = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.values", outputFieldName: "values" },
        ],
      },
      options: { keepMissing: true },
    }),
  ]);
  const evidence = {
    classifications: [
      {
        nodeKey: run.context.nodeByName.get("Input").key,
        field: "/body/values/1/label",
        dataClass: "internal",
      },
    ],
  };
  const first = run.output("/values/0/0/label");
  assert.ok(
    first.origins.every(({ fieldPath }) => fieldPath.endsWith("/0/label")),
  );
  assert.ok(!transferDataClasses(first, evidence).includes("internal"));
  assert.ok(
    transferDataClasses(run.output("/values/0/1/label"), evidence).includes(
      "internal",
    ),
  );
});

test("Aggregate runtime duplicate keys are checked separately from saved output names", () => {
  for (const fields of [
    [
      { fieldToAggregate: "body.label", outputFieldName: "left" },
      { fieldToAggregate: "body.label", outputFieldName: "right" },
    ],
    [
      {
        fieldToAggregate: "body.label",
        renameField: false,
        outputFieldName: "left",
      },
      {
        fieldToAggregate: "body.label",
        renameField: false,
        outputFieldName: "right",
      },
    ],
    [
      { fieldToAggregate: "body.a", renameField: true },
      { fieldToAggregate: "body.b", renameField: true },
    ],
    [
      {
        fieldToAggregate: "body.a",
        renameField: false,
        outputFieldName: "saved",
      },
      {
        fieldToAggregate: "body.b",
        renameField: true,
        outputFieldName: "body.a",
      },
    ],
  ]) {
    const value = analyze([
      source(),
      node("Aggregate", "aggregate", 1, {
        fieldsToAggregate: { fieldToAggregate: fields },
      }),
    ]).output("/right/0");
    assert.ok(
      value.diagnosticCodes.includes("aggregate_duplicate_field_unresolved"),
    );
    assert.notEqual(value.status, "resolved");
    assert.notEqual(value.fieldsComplete, true);
    assert.equal(value.constant, undefined);
  }
  const valid = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          {
            fieldToAggregate: "body.label",
            renameField: true,
            outputFieldName: "left",
          },
          {
            fieldToAggregate: "body.label",
            renameField: true,
            outputFieldName: "right",
          },
        ],
      },
    }),
  ]).output("/right/0");
  assert.ok(
    !valid.diagnosticCodes.includes("aggregate_duplicate_field_unresolved"),
  );
  assert.ok(valid.origins.some(({ fieldPath }) => fieldPath === "/body/label"));
  const collision = analyze([
    source(),
    node("Aggregate", "aggregate", 1, {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.label", outputFieldName: "same" },
          { fieldToAggregate: "body.other", outputFieldName: "same" },
        ],
      },
    }),
  ]).output("/same/0");
  assert.ok(collision.diagnosticCodes.includes("aggregate_fields_unresolved"));
});

test("Aggregate whole lists, objects and serialized aliases retain only the selected candidate subtrees", () => {
  for (const configuration of [
    {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.values", outputFieldName: "values" },
        ],
      },
    },
    {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.values", outputFieldName: "values" },
        ],
      },
      options: { mergeLists: true },
    },
    {
      fieldsToAggregate: {
        fieldToAggregate: [
          { fieldToAggregate: "body.values", outputFieldName: "values" },
        ],
      },
      options: { keepMissing: true },
    },
    { aggregate: "aggregateAllItemData", destinationFieldName: "values" },
    {
      aggregate: "aggregateAllItemData",
      destinationFieldName: "values",
      fieldsToInclude: "body",
      fieldsToExclude: "other",
    },
  ]) {
    for (const expression of [
      "={{ {value:$json.values} }}",
      "={{ {value:JSON.stringify($json.values)} }}",
      "={{ $json }}",
      "alias",
      "serialized-alias",
    ]) {
      const nodes = [
        source(),
        node("Aggregate", "aggregate", 1, configuration),
      ];
      if (expression.includes("alias"))
        nodes.push(
          node("Alias", "code", 2, {
            jsCode:
              expression === "alias"
                ? "const selected=$json.values; return {json:{data:selected}};"
                : "const selected=$json.values; return {json:{data:JSON.stringify(selected)}};",
          }),
        );
      nodes.push(
        node("Send", "httpRequest", 4.4, {
          method: "POST",
          url: "https://example.invalid/ingest",
          sendBody: true,
          contentType: "json",
          specifyBody: "json",
          jsonBody: expression.includes("alias")
            ? "={{ {value:$json.data} }}"
            : expression,
        }),
      );
      const run = analyze(nodes);
      const sourceKey = run.context.nodeByName.get("Input").key;
      const sinkKey = run.context.nodeByName.get("Send").key;
      const evidence = {
        classifications: [
          {
            nodeKey: sourceKey,
            field: "/body/values/1/label",
            dataClass: "internal",
          },
        ],
        policy: {
          egress: [
            {
              id: "public-only",
              nodeKey: sinkKey,
              sink: "http",
              mode: "allowlist",
              destinations: ["https://example.invalid/"],
              allowedDataClasses: ["public"],
            },
          ],
        },
      };
      const rules = analyzeExtendedSinks(run.context, run.flow, evidence);
      assert.ok(
        rules.some((rule) =>
          rule.findings.some((finding) =>
            finding.evidence.some(
              ({ code }) => code === "trusted_policy_transfer_disallowed",
            ),
          ),
        ),
        JSON.stringify({ configuration, expression }),
      );
      assert.ok(
        rules.some((rule) =>
          rule.diagnostics.some(
            ({ code }) => code === "payload_provenance_unresolved",
          ),
        ),
      );
      const selected = run.flow.output(
        run.context.nodeByName.get("Aggregate").key,
        "/values",
      );
      const publicClasses = transferDataClasses(selected, {
        classifications: [
          {
            nodeKey: sourceKey,
            field: "/body/values/1/label",
            dataClass: "public",
          },
        ],
      });
      assert.ok(publicClasses.includes("unknown"));
      assert.equal(
        assessDestination(
          evidence,
          sinkKey,
          "http",
          "https://example.invalid/",
          publicClasses,
        ).status,
        "unknown",
      );
    }
  }
  for (const fields of [
    { fieldsToInclude: "other" },
    { fieldsToInclude: "body", fieldsToExclude: "body" },
    { fieldsToExclude: "body" },
  ]) {
    const run = analyze([
      source(),
      node("Aggregate", "aggregate", 1, {
        aggregate: "aggregateAllItemData",
        destinationFieldName: "values",
        ...fields,
      }),
    ]);
    const value = run.output("/values");
    const classes = transferDataClasses(value, {
      classifications: [
        {
          nodeKey: run.context.nodeByName.get("Input").key,
          field: "/body/values/1/label",
          dataClass: "internal",
        },
      ],
    });
    assert.ok(!classes.includes("internal"), JSON.stringify(fields));
    assert.ok(classes.includes("unknown"));
    if (!fields.fieldsToInclude)
      assert.ok(
        value.diagnosticCodes.includes("aggregate_excluded_unknown_fields"),
      );
  }
  const unchanged = analyze([source()]);
  assert.ok(
    unchanged
      .output("/body/values")
      .origins.every((origin) => origin.includesDescendants !== true),
  );
});
