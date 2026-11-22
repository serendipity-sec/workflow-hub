import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow, valueFlowLimits } from "../dist/value-flow.js";

const node = (name, type, version, parameters = {}) => ({
  id: name,
  name,
  type: "n8n-nodes-base." + type,
  typeVersion: version,
  parameters,
});
const web = (name = "Input") => node(name, "webhook", 2.1, {});
const pass = (name = "Sink") => node(name, "noOp", 1);
const edge = (name, index = 0) => ({ node: name, type: "main", index });
const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((item, index) => [
        item.name,
        { main: [[edge(nodes[index + 1].name)]] },
      ]),
  ),
});
function setup(document, annotations = []) {
  const context = createContext(Buffer.from(JSON.stringify(document)));
  const key = (name) => context.nodeByName.get(name).key;
  const flow = buildValueFlow(context, {
    sourceAnnotations: annotations.map((item) => ({
      ...item,
      nodeKey: key(item.node),
    })),
  });
  return {
    flow,
    key,
    resolve: (value, name = "Sink") => flow.resolve(key(name), value),
    output: (field, name = "Sink", port = 0) =>
      flow.output(key(name), field, port),
  };
}
const assignment = (name, value, type = "string") => ({
  id: name,
  name,
  value,
  type,
});
const set = (assignments, extra = {}) =>
  node("Map", "set", 3.4, { assignments: { assignments }, ...extra });
const filter = (field = "body.id", type = "number", rightValue = 3) => ({
  combinator: "and",
  options: { version: 2, typeValidation: "strict", caseSensitive: true },
  conditions: [
    {
      leftValue: `={{ $json.${field} }}`,
      rightValue,
      operator: { type, operation: "equals" },
    },
  ],
});

test("current and named references preserve fields, paths and separate trust from sensitivity", () => {
  const run = setup(chain(web(), pass()));
  for (const expression of [
    "={{ $json.body.email }}",
    "={{ $json['body']['email'] }}",
    "={{ $('Input').first().json.body.email }}",
    "={{ $('Input').item.json.body.email }}",
    "={{ $node['Input'].json.body.email }}",
    "={{ $input.item.json.body.email }}",
  ]) {
    const value = run.resolve(expression);
    assert.equal(value.status, "resolved");
    assert.equal(value.origins[0].fieldPath, "/body/email");
    assert.equal(value.sensitivity, "pii_candidate");
    assert.deepEqual(value.sensitivityBasis, ["field_name_inference"]);
    assert.equal(value.trust, "external");
  }
  assert.equal(run.resolve("={{ $json.body.item }}").sensitivity, "unknown");
  assert.equal(
    run.resolve("{{ $json.body.email }}").sensitivity,
    "public_literal",
  );
});

test("literal bracket keys remain distinct from dotted paths and prototypes are unresolved", () => {
  const run = setup(chain(web(), pass()));
  assert.equal(
    run.resolve("={{ $json['a.b'][0] }}").origins[0].fieldPath,
    "/a.b/0",
  );
  assert.notEqual(
    run.resolve("={{ $json.a.b[0] }}").valueId,
    run.resolve("={{ $json['a.b'][0] }}").valueId,
  );
  assert.equal(
    run.resolve("={{ $json.__proto__.password }}").status,
    "unknown",
  );
});

test("trusted annotations aggregate into whole objects without turning external input inherently sensitive", () => {
  const run = setup(chain(web(), pass()), [
    {
      node: "Input",
      fieldPath: "body.session",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
    {
      node: "Input",
      fieldPath: "body.label",
      sensitivity: "public_literal",
      provenance: "operator",
    },
  ]);
  assert.equal(
    run.resolve("={{ $json.body.session }}").sensitivity,
    "secret_candidate",
  );
  const whole = run.resolve("={{ $json }}");
  assert.equal(whole.sensitivity, "secret_candidate");
  assert.ok(whole.sensitivityBasis.includes("trusted_schema_annotation"));
  assert.equal(whole.fields["/body/session"].sensitivity, "secret_candidate");
  assert.equal(
    run.resolve("={{ $json.body.label }}").sensitivity,
    "public_literal",
  );
  assert.equal(run.resolve("={{ $json.body.label }}").trust, "external");
  assert.equal(
    run.resolve("={{ $json.body }}").sensitivity,
    "secret_candidate",
  );
});

test("credential references are symbolic candidates and never read the process environment", () => {
  const run = setup(chain(web(), pass()));
  const value = run.resolve("={{ $env.SYNTHETIC_NOT_READ }}");
  assert.equal(value.sensitivity, "secret_candidate");
  assert.equal(value.origins[0].kind, "credential");
  assert.equal(value.origins[0].fieldPath, "/env/SYNTHETIC_NOT_READ");
});

test("canonical annotation conflicts retain the more sensitive possibility", () => {
  const run = setup(chain(web(), pass()), [
    {
      node: "Input",
      fieldPath: "/body/password",
      sensitivity: "public_literal",
      provenance: "operator",
    },
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ]);
  const value = run.resolve("={{ $json.body.password }}");
  assert.equal(value.sensitivity, "secret_candidate");
  assert.equal(value.status, "partial");
  assert.ok(value.diagnosticCodes.includes("source_annotation_conflict"));
});

test("raw-body and unsupported source ports cannot support numeric guard evidence", () => {
  const source = web();
  source.parameters.options = { rawBody: true };
  const run = setup(
    chain(source, node("Guard", "if", 2.2, { conditions: filter() }), pass()),
  );
  const value = run.resolve("={{ $json.body.id }}");
  assert.notEqual(value.status, "resolved");
  assert.equal(value.guards.length, 0);
});

test("Set 3.4 maps only selected fields by default and retains renamed provenance", () => {
  const run = setup(
    chain(
      web(),
      set([
        assignment("contact", "={{ $json.body.email }}"),
        assignment("label", "constant"),
      ]),
      pass(),
    ),
  );
  const contact = run.resolve("={{ $json.contact }}");
  assert.equal(contact.origins[0].fieldPath, "/body/email");
  assert.equal(contact.sensitivity, "pii_candidate");
  assert.ok(contact.paths[0].includes(run.key("Map")));
  assert.equal(run.resolve("={{ $json.body }}").presence, "absent");
  const whole = run.resolve("={{ $json }}");
  assert.equal(whole.sensitivity, "pii_candidate");
  assert.ok(whole.fields["/contact"]);
});

test("Set legacy defaults, includeOtherFields and literal dotted names retain version distinctions", () => {
  for (const version of [1, 2]) {
    const mapping = node("Map", "set", version, {
      values: {
        string: [{ name: "contact", value: "={{ $json.body.email }}" }],
      },
    });
    let run = setup(chain(web(), mapping, pass()));
    assert.equal(
      run.resolve("={{ $json.body.other }}").origins[0].fieldPath,
      "/body/other",
    );
    mapping.parameters.keepOnlySet = true;
    run = setup(chain(web(), mapping, pass()));
    assert.equal(run.resolve("={{ $json.body.other }}").presence, "absent");
  }
  const run = setup(
    chain(
      web(),
      set([assignment("a.b", "={{ $json.body.token }}")], {
        includeOtherFields: true,
        options: { dotNotation: false },
      }),
      pass(),
    ),
  );
  assert.equal(
    run.resolve("={{ $json['a.b'] }}").sensitivity,
    "secret_candidate",
  );
  assert.equal(run.resolve("={{ $json.a.b }}").origins[0].fieldPath, "/a/b");
});

test("Set raw JSON and bounded object expressions preserve mapped sensitivity", () => {
  const run = setup(
    chain(
      web(),
      node("Map", "set", 3.4, {
        mode: "raw",
        jsonOutput: "={{ { contact: $json.body.email, fixed: 1 } }}",
      }),
      pass(),
    ),
  );
  assert.equal(
    run.resolve("={{ $json.contact }}").sensitivity,
    "pii_candidate",
  );
  assert.equal(run.resolve("={{ $json.fixed }}").sensitivity, "public_literal");
  assert.equal(run.resolve("={{ $json.other }}").presence, "absent");
});

test("raw JSON field limits never turn an omitted sensitive field into a public absent value", () => {
  const padding = Object.fromEntries(
    Array.from({ length: valueFlowLimits.fields }, (_, index) => [
      "field" + index,
      "literal",
    ]),
  );
  const run = setup(
    chain(
      web(),
      node("Map", "set", 3.4, {
        mode: "raw",
        jsonOutput: JSON.stringify({ ...padding, password: "synthetic" }),
      }),
      pass(),
    ),
  );
  assert.equal(run.output("", "Map").fieldsComplete, false);
  const omitted = run.resolve("={{ $json.password }}");
  assert.notEqual(omitted.status, "resolved");
  assert.equal(omitted.presence, "unknown");
  assert.equal(omitted.sensitivity, "unknown");
  assert.ok(omitted.sensitivityClasses.includes("unknown"));
  assert.ok(omitted.diagnosticCodes.includes("flow_field_limit"));
  assert.ok(omitted.diagnosticCodes.includes("field_projection_partial"));

  const bounded = setup(
    chain(
      web(),
      node("Map", "set", 3.4, {
        mode: "raw",
        jsonOutput: JSON.stringify(padding),
      }),
      pass(),
    ),
  );
  assert.equal(bounded.output("", "Map").fieldsComplete, true);
  assert.equal(bounded.resolve("={{ $json.password }}").presence, "absent");
});

test("nested literal and expression arrays preserve uncertainty at the field bound", () => {
  const values = Array.from(
    { length: valueFlowLimits.fields },
    () => "literal",
  );
  for (const expression of [false, true]) {
    for (const extra of [false, true]) {
      const array = extra ? [...values, "synthetic@example.invalid"] : values;
      const raw = JSON.stringify({ values: array });
      const run = setup(
        chain(
          web(),
          node("Map", "set", 3.4, {
            mode: "raw",
            jsonOutput: expression ? `={{ ${raw} }}` : raw,
          }),
          pass(),
        ),
      );
      const projected = run.resolve(
        `={{ $json.values[${valueFlowLimits.fields}] }}`,
      );
      if (extra) {
        assert.notEqual(projected.status, "resolved");
        assert.equal(projected.presence, "unknown");
        assert.ok(projected.sensitivityClasses.includes("unknown"));
        assert.ok(projected.diagnosticCodes.includes("flow_field_limit"));
      } else {
        assert.equal(projected.status, "resolved");
        assert.equal(projected.presence, "absent");
      }
    }
  }
});

test("truncated expression mappings preserve known classes and cannot hide later overwrites", () => {
  const padding = Array.from(
    { length: valueFlowLimits.fields - 1 },
    (_, index) => `field${index}: 'literal'`,
  ).join(", ");
  for (const first of ["'literal'", "$json.body.password"]) {
    const run = setup(
      chain(
        web(),
        node("Map", "set", 3.4, {
          mode: "raw",
          jsonOutput: `={{ { password: ${first}, ${padding}, password: $json.body.email } }}`,
        }),
        pass(),
      ),
    );
    const value = run.resolve("={{ $json.password }}");
    assert.notEqual(value.status, "resolved");
    assert.equal(value.presence, "unknown");
    assert.ok(value.sensitivityClasses.includes("unknown"));
    assert.ok(value.diagnosticCodes.includes("flow_field_limit"));
    if (first !== "'literal'") {
      assert.equal(value.sensitivity, "secret_candidate");
      assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    }
  }
});

test("too many manual mappings leave field existence unknown", () => {
  const assignments = Array.from(
    { length: valueFlowLimits.fields },
    (_, index) => assignment("field" + index, "literal"),
  );
  assignments.push(assignment("password", "={{ $json.body.password }}"));
  const value = setup(chain(web(), set(assignments), pass())).resolve(
    "={{ $json.password }}",
  );
  assert.equal(value.presence, "unknown");
  assert.notEqual(value.status, "resolved");
  assert.ok(value.sensitivityClasses.includes("unknown"));
  assert.ok(value.diagnosticCodes.includes("flow_field_limit"));
});

test("object aggregation, serialization and concatenation retain every sensitivity class", () => {
  const run = setup(
    chain(
      web(),
      set([
        assignment("secret", "={{ $json.body.password }}"),
        assignment("personal", "={{ $json.body.email }}"),
        assignment("label", "public"),
      ]),
      pass(),
    ),
  );
  for (const expression of [
    "={{ $json }}",
    "={{ JSON.stringify($json) }}",
    "={{ $json.secret + $json.personal + $json.label }}",
    "={{ [ $json.secret, $json.personal, $json.label ] }}",
  ]) {
    const value = run.resolve(expression);
    assert.equal(value.sensitivity, "secret_candidate");
    assert.deepEqual(
      new Set(value.sensitivityClasses),
      new Set(["secret_candidate", "pii_candidate", "public_literal"]),
    );
  }
  assert.deepEqual(run.resolve("={{ $json.secret }}").sensitivityClasses, [
    "secret_candidate",
  ]);
  assert.deepEqual(run.resolve("={{ $json.personal }}").sensitivityClasses, [
    "pii_candidate",
  ]);
  assert.deepEqual(run.resolve("={{ $json.label }}").sensitivityClasses, [
    "public_literal",
  ]);
});

test("source annotations and opaque projections retain mixed classifications with unknown", () => {
  const run = setup(chain(web(), pass()), [
    {
      node: "Input",
      fieldPath: "body.s",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
    {
      node: "Input",
      fieldPath: "body.p",
      sensitivity: "pii_candidate",
      provenance: "schema",
    },
  ]);
  const value = run.resolve("={{ JSON.stringify($json.body) }}");
  assert.deepEqual(
    new Set(value.sensitivityClasses),
    new Set(["secret_candidate", "pii_candidate", "unknown"]),
  );
  const mapped = setup(
    chain(
      web(),
      set([
        assignment(
          "payload",
          "={{ mystery($json.body.password, $json.body.email) }}",
          "object",
        ),
      ]),
      pass(),
    ),
  );
  const projected = mapped.resolve("={{ $json.payload.nested }}");
  assert.notEqual(projected.status, "resolved");
  assert.ok(
    projected.diagnosticCodes.includes("expression_semantics_unsupported"),
  );
  assert.ok(projected.diagnosticCodes.includes("field_projection_partial"));
  assert.deepEqual(
    new Set(projected.sensitivityClasses),
    new Set(["secret_candidate", "pii_candidate", "unknown"]),
  );
});

test("Set unknown dynamic names cannot hide an upstream sensitive possibility", () => {
  const run = setup(
    chain(
      web(),
      set([assignment("={{ $json.field }}", "value")], {
        includeOtherFields: true,
      }),
      pass(),
    ),
    [
      {
        node: "Input",
        fieldPath: "body.hidden",
        sensitivity: "secret_candidate",
        provenance: "operator",
      },
    ],
  );
  const value = run.resolve("={{ $json }}");
  assert.notEqual(value.status, "resolved");
  assert.equal(value.sensitivity, "secret_candidate");
});

test("IF guards bind the exact value and branch rather than the presence of an IF node", () => {
  const guard = node("Guard", "if", 2.2, { conditions: filter() });
  const run = setup(chain(web(), guard, pass()));
  const checked = run.resolve("={{ $json.body.id }}");
  assert.ok(checked.guards.some(({ kind }) => kind === "number_type"));
  assert.ok(
    checked.guards.some(
      ({ kind, literal }) => kind === "equals_literal" && literal === 3,
    ),
  );
  assert.equal(run.resolve("={{ $json.body.other }}").guards.length, 0);
  assert.equal(
    run.resolve("={{ $('Input').first().json.body.id }}").guards.length,
    0,
  );
  assert.equal(run.resolve("={{ $json.body.id + 'suffix' }}").guards.length, 0);
});

test("strict numeric false branch retains type constraint without asserting equality", () => {
  const document = chain(
    web(),
    node("Guard", "if", 2.2, { conditions: filter() }),
    pass(),
  );
  document.connections.Guard.main = [null, [edge("Sink")]];
  const value = setup(document).resolve("={{ $json.body.id }}");
  assert.ok(value.guards.some(({ kind }) => kind === "number_type"));
  assert.ok(value.guards.some(({ kind }) => kind === "not_equals_literal"));
  assert.ok(!value.guards.some(({ kind }) => kind === "equals_literal"));
});

test("dynamic comparator values never become literal destination allowlists", () => {
  const guard = node("Guard", "if", 2.2, {
    conditions: filter("body.host", "string", "={{ $json.body.allowed }}"),
  });
  const value = setup(chain(web(), guard, pass())).resolve(
    "={{ $json.body.host }}",
  );
  assert.equal(value.guards.length, 0);
});

test("bypass joins drop non-universal guards and unsupported filter semantics stay explicit", () => {
  const guard = node("Guard", "if", 2.2, { conditions: filter() });
  const document = chain(web(), guard, pass());
  document.connections.Input.main[0].push(edge("Sink"));
  assert.equal(
    setup(document).resolve("={{ $json.body.id }}").guards.length,
    0,
  );
  guard.parameters.looseTypeValidation = true;
  const value = setup(chain(web(), guard, pass())).resolve(
    "={{ $json.body.id }}",
  );
  assert.notEqual(value.status, "resolved");
  assert.equal(value.guards.length, 0);
});

test("Switch rule outputs can carry exact string constraints but numeric fallback ports cannot", () => {
  const route = node("Route", "switch", 3.2, {
    rules: {
      values: [
        { conditions: filter("body.host", "string", "example.invalid") },
      ],
    },
    options: { fallbackOutput: "extra" },
  });
  let run = setup(chain(web(), route, pass()));
  assert.ok(
    run
      .resolve("={{ $json.body.host }}")
      .guards.some(({ kind }) => kind === "equals_literal"),
  );
  route.parameters.options.fallbackOutput = 0;
  run = setup(chain(web(), route, pass()));
  assert.equal(run.resolve("={{ $json.body.host }}").guards.length, 0);
  assert.ok(
    run
      .resolve("={{ $json.body.host }}")
      .diagnosticCodes.includes("switch_fallback_reuses_output"),
  );
});

test("Merge append and selected branch preserve possible origins without inventing row correspondence", () => {
  const merge = node("Merge", "merge", 3.2, { mode: "append" });
  const document = {
    nodes: [web("A"), web("B"), merge, pass()],
    connections: {
      A: { main: [[edge("Merge", 0)]] },
      B: { main: [[edge("Merge", 1)]] },
      Merge: { main: [[edge("Sink")]] },
    },
  };
  let run = setup(document);
  assert.equal(run.resolve("={{ $json.body.value }}").origins.length, 2);
  merge.parameters = { mode: "chooseBranch", useDataOfInput: 2 };
  run = setup(document);
  assert.deepEqual(
    run
      .resolve("={{ $json.body.value }}")
      .origins.map(({ nodeKey }) => nodeKey),
    [run.key("B")],
  );
  merge.parameters = { mode: "combine", combineBy: "combineByPosition" };
  run = setup(document);
  const value = run.resolve("={{ $json.body.value }}");
  assert.equal(value.status, "partial");
  assert.ok(value.diagnosticCodes.includes("merge_item_alignment_unverified"));
  assert.equal(value.guards.length, 0);
});

test("database output has its own source and never inherits Webhook trust or sensitivity blindly", () => {
  const run = setup(
    chain(
      web(),
      node("Database", "postgres", 2.8, {
        operation: "executeQuery",
        query: "SELECT label FROM synthetic",
      }),
      pass(),
    ),
  );
  const value = run.resolve("={{ $json }}");
  assert.deepEqual(
    value.origins.map(({ kind }) => kind),
    ["database"],
  );
  assert.equal(value.sensitivity, "unknown");
  assert.equal(value.trust, "unknown");
});

test("subworkflow trigger input is an external possibility with unresolved caller arguments", () => {
  const run = setup(
    chain(node("Input", "executeWorkflowTrigger", 1.1), pass()),
  );
  const value = run.resolve("={{ $json.customer.email }}");
  assert.equal(value.trust, "external");
  assert.equal(value.status, "partial");
  assert.equal(value.origins[0].kind, "subworkflow");
  assert.ok(
    value.diagnosticCodes.includes("subworkflow_argument_context_unresolved"),
  );
  assert.equal(value.guards.length, 0);
});

test("symbolic concatenation, arrays and conversions retain provenance without executing expressions", () => {
  const run = setup(chain(web(), pass()));
  assert.ok(
    run
      .resolve("={{ encodeURIComponent($json.body.email) }}")
      .transforms.some(({ kind }) => kind === "url_component_encoding"),
  );
  assert.ok(
    run
      .resolve("={{ Number($json.body.id) }}")
      .transforms.some(({ kind }) => kind === "numeric_conversion"),
  );
  assert.equal(
    run.resolve("={{ [ $json.body.email, 'literal' ] }}").sensitivity,
    "pii_candidate",
  );
  assert.equal(
    run.resolve("=prefix/{{ $json.body.token }}").sensitivity,
    "secret_candidate",
  );
  delete globalThis.__valueFlowExecuted;
  assert.notEqual(
    run.resolve("={{ globalThis.__valueFlowExecuted = true }}").status,
    "resolved",
  );
  assert.equal(globalThis.__valueFlowExecuted, undefined);
});

test("whole-input serialization and console-input expressions retain trusted sensitive fields", () => {
  const run = setup(chain(web(), pass()), [
    {
      node: "Input",
      fieldPath: "body.hidden",
      sensitivity: "pii_candidate",
      provenance: "operator",
    },
  ]);
  for (const expression of [
    "={{ JSON.stringify($json) }}",
    "={{ $input.all() }}",
  ]) {
    const value = run.resolve(expression);
    assert.equal(value.sensitivity, "pii_candidate");
    assert.equal(value.fullObject, true);
  }
});

test("single-return Code mappings are interpreted as syntax; arbitrary Code remains opaque", () => {
  const code = node("Code", "code", 2, {
    jsCode: "return [{ json: { email: $input.first().json.body.email } }];",
  });
  let run = setup(chain(web(), code, pass()));
  assert.equal(run.resolve("={{ $json.email }}").sensitivity, "pii_candidate");
  code.parameters.jsCode =
    "globalThis.__valueFlowExecuted = true; return $input.all();";
  run = setup(chain(web(), code, pass()), [
    {
      node: "Input",
      fieldPath: "body.hidden",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ]);
  const value = run.resolve("={{ $json }}");
  assert.notEqual(value.status, "resolved");
  assert.equal(value.sensitivity, "secret_candidate");
  assert.equal(globalThis.__valueFlowExecuted, undefined);
});

test("cycles terminate with explicit uncertainty and unconnected direct references are rejected", () => {
  const document = {
    nodes: [pass("A"), pass("Sink"), web("Orphan")],
    connections: {
      A: { main: [[edge("Sink")]] },
      Sink: { main: [[edge("A")]] },
    },
  };
  const run = setup(document);
  const value = run.resolve("={{ $json.body.email }}");
  assert.notEqual(value.status, "resolved");
  assert.ok(value.diagnosticCodes.includes("cyclic_dataflow"));
  assert.ok(
    run
      .resolve("={{ $('Orphan').first().json.body.email }}")
      .diagnosticCodes.includes("direct_reference_unconnected"),
  );
});
