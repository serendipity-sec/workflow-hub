import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { analyzeExtendedSinks } from "../dist/extended-sinks.js";
import { analyzeAdvancedRisks } from "../dist/advanced-risks.js";
import { buildValueFlow, valueFlowLimits } from "../dist/value-flow.js";
import { assessDestination } from "../dist/assessment-policy.js";

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
    context,
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

test("strict numeric false equality does not prove a number because null and missing values can pass", () => {
  const document = chain(
    web(),
    node("Guard", "if", 2.2, { conditions: filter() }),
    pass(),
  );
  document.connections.Guard.main = [null, [edge("Sink")]];
  const value = setup(document).resolve("={{ $json.body.id }}");
  assert.ok(!value.guards.some(({ kind }) => kind === "number_type"));
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

test("expression mode without interpolation is fixed text while malformed delimiters stay unknown", () => {
  const run = setup(chain(web(), pass()));
  for (const text of ["=fixed text", "=printf constant\n", "="]) {
    const value = run.resolve(text);
    assert.equal(value.status, "resolved");
    assert.deepEqual(value.sensitivityClasses, ["public_literal"]);
    assert.equal(
      value.origins.some((origin) => origin.kind === "webhook"),
      false,
    );
  }
  assert.notEqual(run.resolve("=prefix {{ missing").status, "resolved");
});

test("immutable Code constant and clock output does not inherit unrelated upstream personal data", () => {
  const source = web();
  const formatter = node("Formatter", "code", 2, {
    jsCode: `
    const today = new Date().toLocaleDateString(undefined, { weekday: 'long', year: 'numeric' });
    const message = 'No records to display.';
    return { json: { summary: message, today, title: \`Overview - \${today}\`, output: \`\${today}: \${message}\` } };
  `,
  });
  const run = setup(chain(source, formatter, pass()), [
    {
      node: "Input",
      fieldPath: "body.email",
      sensitivity: "pii_candidate",
      provenance: "schema",
    },
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ]);
  for (const expression of [
    "={{ $json }}",
    "={{ $json.summary }}",
    "={{ $json.title }}",
    "={{ $json.output }}",
  ]) {
    const value = run.resolve(expression);
    assert.equal(value.status, "resolved");
    assert.deepEqual(value.sensitivityClasses, ["public_literal"]);
    assert.ok(value.origins.every((origin) => origin.kind === "literal"));
  }
  assert.ok(
    run
      .resolve("={{ $json.today }}")
      .sensitivityBasis.includes("runtime_clock"),
  );
  assert.equal(run.resolve("={{ $json.body.email }}").presence, "absent");
});

test("clock formatting preserves the sensitivity of quoted literal output and format arguments", () => {
  for (const value of [
    '"synthetic@example.invalid"',
    "$now.toFormat(\"'synthetic@example.invalid'\")",
    "$today.toFormat(\"yyyy 'synthetic@example.invalid'\")",
  ]) {
    const formatter = node("Formatter", "code", 2, {
      jsCode: `return { json: { formatted: ${value} } };`,
    });
    const run = setup(chain(web(), formatter, pass()));
    const projected = run.resolve("={{ $json.formatted }}");
    assert.equal(projected.status, "resolved");
    assert.ok(projected.sensitivityClasses.includes("pii_candidate"));
    assert.equal(projected.sensitivity, "pii_candidate");
    assert.equal(projected.fullObject, false);
    assert.ok(projected.sensitivityBasis.includes("literal_format_inference"));
  }
  const run = setup(
    chain(
      web(),
      node("Formatter", "code", 2, {
        jsCode: 'return {json: {formatted: $now.toFormat("yyyy-MM-dd")}};',
      }),
      pass(),
    ),
  );
  assert.deepEqual(run.resolve("={{ $json.formatted }}").sensitivityClasses, [
    "public_literal",
  ]);
});

test("Code immutable aliases preserve selected input fields and both supported item wrapper forms", () => {
  for (const wrapper of ["{ json: result }", "[{ json: result }]"]) {
    const formatter = node("Formatter", "code", 2, {
      jsCode: `
      const contact = $input.first().json.body.email;
      const fixed = 'label';
      const result = { contact, fixed };
      return ${wrapper};
    `,
    });
    const run = setup(chain(web(), formatter, pass()));
    assert.equal(
      run.resolve("={{ $json.contact }}").sensitivity,
      "pii_candidate",
    );
    assert.deepEqual(run.resolve("={{ $json.fixed }}").sensitivityClasses, [
      "public_literal",
    ]);
    assert.equal(
      run.resolve("={{ $json.contact }}").origins[0].fieldPath,
      "/body/email",
    );
  }
});

test("Code object properties and immutable aliases retain field-name sensitivity hints", () => {
  for (const jsCode of [
    'return [{json: {password: "synthetic-password", phone: "2025550123", label: "public"}}];',
    'const payload = {password: "synthetic-password", phone: "2025550123", label: "public"}; return [{json: payload}];',
  ]) {
    const run = setup(
      chain(web(), node("Formatter", "code", 2, { jsCode }), pass()),
    );
    const password = run.resolve("={{ $json.password }}");
    const phone = run.resolve("={{ $json.phone }}");
    assert.equal(password.status, "resolved");
    assert.equal(password.sensitivity, "secret_candidate");
    assert.ok(password.sensitivityBasis.includes("field_name_inference"));
    assert.equal(phone.sensitivity, "pii_candidate");
    assert.ok(phone.sensitivityBasis.includes("field_name_inference"));
    assert.equal(password.sensitivityClasses.includes("pii_candidate"), false);
    assert.equal(phone.sensitivityClasses.includes("secret_candidate"), false);
    assert.deepEqual(run.resolve("={{ $json.label }}").sensitivityClasses, [
      "public_literal",
    ]);
    const whole = run.resolve("={{ $json }}");
    assert.ok(whole.sensitivityClasses.includes("secret_candidate"));
    assert.ok(whole.sensitivityClasses.includes("pii_candidate"));
  }
});

test("object field hints add to rather than overwrite the value's sensitivity classes", () => {
  const run = setup(
    chain(
      web(),
      node("Formatter", "code", 2, {
        jsCode: `
    const payload = {phone: $json.body.password, password: $json.body.email, token: $json.body.other};
    return {json: payload};
  `,
      }),
      pass(),
    ),
  );
  for (const field of ["phone", "password"]) {
    const value = run.resolve(`={{ $json.${field} }}`);
    assert.equal(value.sensitivity, "secret_candidate");
    assert.deepEqual(
      new Set(value.sensitivityClasses),
      new Set(["secret_candidate", "pii_candidate"]),
    );
  }
  const unknown = run.resolve("={{ $json.token }}");
  assert.ok(unknown.sensitivityClasses.includes("unknown"));
  assert.ok(unknown.sensitivityClasses.includes("secret_candidate"));
});

test("Gmail serialization of Code objects reports both classes while selected fields stay precise", () => {
  for (const [message, expectedSecret, expectedPersonal] of [
    ["={{ JSON.stringify($json) }}", true, true],
    ["={{ $json.password }}", true, false],
    ["={{ $json.phone }}", false, true],
    ["={{ $json.label }}", false, false],
  ]) {
    const run = setup(
      chain(
        web(),
        node("Formatter", "code", 2, {
          jsCode:
            'const payload = {password: "synthetic-password", phone: "2025550123", label: "public"}; return [{json: payload}];',
        }),
        node("Mail", "gmail", 2.2, {
          sendTo: "recipient@example.invalid",
          message,
        }),
      ),
    );
    const rules = analyzeExtendedSinks(run.context, run.flow);
    const codes = rules.flatMap((rule) =>
      rule.findings.flatMap((finding) =>
        finding.evidence.map((item) => item.code),
      ),
    );
    assert.equal(
      codes.includes("secret_candidate_transferred"),
      expectedSecret,
    );
    assert.equal(
      codes.includes("personal_data_candidate_transferred"),
      expectedPersonal,
    );
    assert.equal(JSON.stringify(rules).includes("synthetic-password"), false);
    assert.equal(JSON.stringify(rules).includes("2025550123"), false);
  }
});

test("opaque calls, clock inputs, shadowing and mutation never become constant Code output proof", () => {
  for (const jsCode of [
    "const value = mysterious(); return {json: {message: 'fixed'}};",
    "const Date = customDate; return {json: {today: new Date().toDateString()}};",
    "const value = {}; value.contact = $json.body.email; return {json: value};",
    "const today = new Date($json.body.email).toDateString(); return {json: {today}};",
    "const today = new Date().toLocaleDateString($json.body.email); return {json: {today}};",
    "const today = new Date().toLocaleDateString({get key() { globalThis.__valueFlowExecuted = true; }}); return {json: {today}};",
  ]) {
    const run = setup(
      chain(web(), node("Formatter", "code", 2, { jsCode }), pass()),
      [
        {
          node: "Input",
          fieldPath: "body.email",
          sensitivity: "pii_candidate",
          provenance: "schema",
        },
      ],
    );
    const value = run.resolve("={{ $json }}");
    assert.notEqual(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("unknown"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  }
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

test("optional field/index reads and logical defaults preserve every possible sensitive origin", () => {
  const run = setup(chain(web(), pass()));
  const optional = run.resolve("={{ $json.body.items?.[0]?.email }}");
  assert.equal(optional.status, "resolved");
  assert.equal(optional.presence, "unknown");
  assert.equal(optional.origins[0].fieldPath, "/body/items/0/email");
  assert.ok(optional.sensitivityClasses.includes("pii_candidate"));
  for (const operator of ["||", "??"]) {
    const value = run.resolve(
      `={{ $json.body.password ${operator} $json.body.email ${operator} 'empty' }}`,
    );
    assert.equal(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.ok(value.sensitivityClasses.includes("public_literal"));
    assert.equal(value.guards.length, 0);
    assert.equal(value.origins.length, 3);
  }
  const guarded = setup(
    chain(web(), node("Guard", "if", 2.2, { conditions: filter() }), pass()),
  );
  assert.equal(guarded.resolve("={{ $json.body?.id }}").guards.length, 0);
  assert.equal(guarded.resolve("={{ $json.body.id || 0 }}").guards.length, 0);
});

test("pure Code optional aliases keep summary origins separate from a constant clock title across IF 2.3", () => {
  const formatter = node("Formatter", "code", 2, {
    jsCode: `
    const summary = $input.first().json.body.items?.[0]?.email || $input.first().json.body.email || 'No content';
    const entries = [{label: 'public'}];
    const payload = {summary, docTitle: 'Overview ' + new Date().toDateString(), label: entries[0].label};
    return {json: payload};
  `,
  });
  const conditions = filter("body.enabled", "boolean", true);
  conditions.options.version = 3;
  const send = node("Sink", "gmail", 2.2, {
    sendTo: "synthetic@example.invalid",
    subject: "={{ $json.docTitle }}",
    message: "={{ $json.summary }}",
  });
  const run = setup(
    chain(web(), formatter, node("Guard", "if", 2.3, { conditions }), send),
  );
  const title = run.resolve(send.parameters.subject);
  assert.equal(title.status, "resolved");
  assert.deepEqual(title.sensitivityClasses, ["public_literal"]);
  assert.deepEqual(title.diagnosticCodes, []);
  assert.deepEqual(run.resolve("={{ $json.label }}").sensitivityClasses, [
    "public_literal",
  ]);
  const summary = run.resolve(send.parameters.message);
  assert.ok(summary.sensitivityClasses.includes("pii_candidate"));
  assert.ok(
    summary.origins.some(
      ({ fieldPath }) => fieldPath === "/body/items/0/email",
    ),
  );
  const findings = analyzeExtendedSinks(run.context, run.flow).flatMap(
    (rule) => rule.findings,
  );
  assert.ok(
    findings.some(
      (finding) =>
        finding.location.pointer.endsWith("/message") &&
        finding.evidence.some(
          (evidence) => evidence.code === "personal_data_candidate_transferred",
        ),
    ),
  );
  assert.ok(
    !findings.some(
      (finding) =>
        finding.location.pointer.endsWith("/subject") &&
        finding.evidence.some(
          (evidence) => evidence.code === "personal_data_candidate_transferred",
        ),
    ),
  );
});

test("optional and fallback syntax never permits calls, side effects or dynamic indices to prove public output", () => {
  for (const jsCode of [
    "const payload = malicious?.(); return {json: {label: 'public'}};",
    "const payload = $json.body.email || (globalThis.__valueFlowExecuted = true); return {json: {label: 'public'}};",
    "const payload = [$json.body.email]; return {json: {label: payload[mysterious()]}};",
  ]) {
    const run = setup(
      chain(web(), node("Formatter", "code", 2, { jsCode }), pass()),
      [
        {
          node: "Input",
          fieldPath: "body.email",
          sensitivity: "pii_candidate",
          provenance: "schema",
        },
      ],
    );
    const value = run.resolve("={{ $json.label }}");
    assert.notEqual(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  }
  const run = setup(chain(web(), pass()));
  assert.notEqual(run.resolve("={{ $json.body?.read() }}").status, "resolved");
  assert.equal(globalThis.__valueFlowExecuted, undefined);
});

test("all filter versions restrict numeric safety to finite equality outcomes", () => {
  for (const filterVersion of [1, 2, 3]) {
    for (const [operation, port, expected] of [
      ["equals", 0, true],
      ["equals", 1, false],
      ["notEquals", 0, false],
      ["notEquals", 1, true],
      ["gt", 0, false],
      ["lt", 1, false],
    ]) {
      const conditions = filter("body.id", "number", 3);
      conditions.options.version = filterVersion;
      conditions.conditions[0].operator.operation = operation;
      const document = chain(
        web(),
        node("Guard", "if", 2.3, { conditions }),
        pass(),
      );
      document.connections.Guard.main =
        port === 0 ? [[edge("Sink")]] : [null, [edge("Sink")]];
      const value = setup(document).resolve("={{ $json.body.id }}");
      assert.equal(value.status, "resolved");
      assert.equal(
        value.guards.some(({ kind }) => kind === "number_type"),
        expected,
      );
    }
  }
});

test("filter version defaults and Switch 3.3/3.4 type validation follow the pinned runtime", () => {
  const conditions = filter("body.host", "string", "example.invalid");
  delete conditions.options.version;
  let run = setup(chain(web(), node("Guard", "if", 2, { conditions }), pass()));
  assert.equal(run.resolve("={{ $json.body.host }}").status, "resolved");
  for (const [version, filterVersion] of [
    [3.3, 2],
    [3.4, 3],
  ]) {
    const selected = structuredClone(conditions);
    selected.options.version = filterVersion;
    const route = node("Route", "switch", version, {
      rules: { values: [{ conditions: selected }] },
      options: {},
    });
    run = setup(chain(web(), route, pass()));
    assert.ok(
      run
        .resolve("={{ $json.body.host }}")
        .guards.some(({ kind }) => kind === "equals_literal"),
    );
    route.parameters.looseTypeValidation = true;
    const value = setup(chain(web(), route, pass())).resolve(
      "={{ $json.body.host }}",
    );
    assert.ok(
      value.diagnosticCodes.includes("branch_type_validation_unresolved"),
    );
    assert.equal(value.guards.length, 0);
  }
});

test("bounded Code output caching avoids repeated whole-object analysis without changing classification", () => {
  const properties = Array.from(
    { length: 48 },
    (_, i) => `field${i}: 'public'`,
  ).join(",");
  const run = setup(
    chain(
      web(),
      node("Formatter", "code", 2, {
        jsCode: `return {json: {${properties}, password: $json.body.password}};`,
      }),
      pass(),
    ),
  );
  for (let index = 0; index < 48; index++) {
    const value = run.resolve(`={{ $json.field${index} }}`);
    assert.equal(value.status, "resolved");
    assert.deepEqual(value.sensitivityClasses, ["public_literal"]);
  }
  assert.ok(
    run
      .resolve("={{ $json.password }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  const first = run.resolve("={{ $json.password }}");
  first.sensitivityClasses.length = 0;
  assert.ok(
    run
      .resolve("={{ $json.password }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  assert.ok(
    !run.flow.diagnostics.some(({ code }) => code === "flow_budget_exceeded"),
  );
});

test("Code and expression caches stay scoped to node, source annotations and execution options", () => {
  const jsCode =
    "const input = $json.body.value; return {json: {value: input, label: 'public'}};";
  const document = {
    nodes: [
      web("A"),
      web("B"),
      node("CodeA", "code", 2, { jsCode }),
      node("CodeB", "code", 2, { jsCode }),
      pass("SinkA"),
      pass("SinkB"),
    ],
    connections: {
      A: { main: [[edge("CodeA")]] },
      B: { main: [[edge("CodeB")]] },
      CodeA: { main: [[edge("SinkA")]] },
      CodeB: { main: [[edge("SinkB")]] },
    },
  };
  const annotations = [
    {
      node: "A",
      fieldPath: "body.value",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
    {
      node: "B",
      fieldPath: "body.value",
      sensitivity: "public_literal",
      provenance: "operator",
    },
  ];
  const run = setup(document, annotations);
  for (let iteration = 0; iteration < 2; iteration++) {
    assert.equal(
      run.resolve("={{ $json.value }}", "SinkA").sensitivity,
      "secret_candidate",
    );
    assert.equal(
      run.resolve("={{ $json.value }}", "SinkB").sensitivity,
      "public_literal",
    );
  }
  const unclassified = setup(document);
  assert.ok(
    unclassified
      .resolve("={{ $json.value }}", "SinkB")
      .sensitivityClasses.includes("unknown"),
  );
  for (const option of [
    { disabled: true },
    { continueOnFail: true },
    { alwaysOutputData: true },
    { onError: "continueRegularOutput" },
  ]) {
    const altered = structuredClone(document);
    Object.assign(altered.nodes[3], option);
    const value = setup(altered, annotations).resolve(
      "={{ $json.label }}",
      "SinkB",
    );
    assert.notEqual(value.status, "resolved");
    assert.ok(
      value.diagnosticCodes.includes("node_execution_semantics_unresolved"),
    );
  }
  const context = createContext(
    Buffer.from(JSON.stringify(chain(web(), pass()))),
  );
  const fields = buildValueFlow(context);
  const sinkKey = context.nodeByName.get("Sink").key;
  assert.deepEqual(
    fields.resolve(sinkKey, "synthetic", { fieldName: "label" })
      .sensitivityClasses,
    ["public_literal"],
  );
  assert.ok(
    fields
      .resolve(sinkKey, "synthetic", { fieldName: "password" })
      .sensitivityClasses.includes("secret_candidate"),
  );
});

test("raw Code expressions preserve nested objects, template delimiters and parentheses without template parsing", () => {
  const run = setup(chain(web(), pass()));
  for (const expression of [
    "({payload:{contact:$json.body.email}})",
    "`fixed }} ${$json.body.email}`",
    "(($json).body.email)",
    "(($json.body.items?.[0]?.email) ?? 'none')",
  ]) {
    const value = run.flow.resolveExpression(run.key("Sink"), expression);
    assert.equal(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.deepEqual(value.diagnosticCodes, []);
  }
  assert.equal(
    run.flow.resolve(run.key("Sink"), "$json.body.email").sensitivity,
    "public_literal",
  );
  assert.equal(
    run.flow.resolveExpression(run.key("Sink"), "$json.body.email").sensitivity,
    "pii_candidate",
  );
  const first = run.flow.resolveExpression(run.key("Sink"), "$json.body.email");
  first.sensitivityClasses.length = 0;
  assert.ok(
    run.flow
      .resolveExpression(run.key("Sink"), "$json.body.email")
      .sensitivityClasses.includes("pii_candidate"),
  );
});

test("raw Code expression invalid syntax, size, AST, depth and request limits stay explicit", () => {
  const run = setup(chain(web(), pass()));
  const resolveRaw = (expression) =>
    run.flow.resolveExpression(run.key("Sink"), expression);
  assert.ok(
    resolveRaw("$json[").diagnosticCodes.includes(
      "expression_parse_unavailable",
    ),
  );
  assert.ok(
    resolveRaw("$json; 1").diagnosticCodes.includes(
      "expression_syntax_unsupported",
    ),
  );
  assert.ok(
    resolveRaw(
      " ".repeat(valueFlowLimits.expressionCharacters + 1),
    ).diagnosticCodes.includes("expression_size_limit"),
  );
  assert.ok(
    resolveRaw(
      "[" +
        Array.from({ length: valueFlowLimits.astNodes + 1 }, () => "0").join(
          ",",
        ) +
        "]",
    ).diagnosticCodes.includes("expression_ast_limit"),
  );
  assert.ok(
    resolveRaw(
      "(".repeat(valueFlowLimits.recursion + 1) +
        "0" +
        ")".repeat(valueFlowLimits.recursion + 1),
    ).diagnosticCodes.includes("flow_budget_exceeded"),
  );
  const assignment = resolveRaw("globalThis.__valueFlowExecuted = true");
  assert.notEqual(assignment.status, "resolved");
  assert.equal(globalThis.__valueFlowExecuted, undefined);
  let exhausted;
  for (let index = 0; index <= valueFlowLimits.requests; index++) {
    exhausted = resolveRaw(String(index));
    if (exhausted.diagnosticCodes.includes("flow_budget_exceeded")) break;
  }
  assert.ok(exhausted.diagnosticCodes.includes("flow_budget_exceeded"));
});

test("projecting logical object alternatives preserves classes and never appends fields to mapped origins", () => {
  for (const operator of ["||", "??"]) {
    for (const [left, right, selection, expected] of [
      [
        "{value: $json.body.password}",
        "{value: 'public'}",
        "value",
        ["secret_candidate"],
      ],
      [
        "{value: 'synthetic@example.invalid'}",
        "{}",
        "value",
        ["pii_candidate"],
      ],
      [
        "{value: $json.body.password}",
        "{value: $json.body.email}",
        "value",
        ["secret_candidate", "pii_candidate"],
      ],
      [
        "[{value: $json.body.password}]",
        "[{value: $json.body.email}]",
        "[0].value",
        ["secret_candidate", "pii_candidate"],
      ],
      [
        "{nested: {value: $json.body.password}}",
        "{nested: {value: $json.body.email}}",
        "nested.value",
        ["secret_candidate", "pii_candidate"],
      ],
    ]) {
      const property = selection.startsWith("[") ? selection : "." + selection;
      const jsCode = `const a = ${left} ${operator} ${right}; return {json: {result: a${property}}};`;
      const run = setup(
        chain(web(), node("Formatter", "code", 2, { jsCode }), pass()),
      );
      const value = run.resolve("={{ $json.result }}");
      assert.equal(value.status, "partial");
      assert.ok(value.diagnosticCodes.includes("field_projection_partial"));
      for (const expectedClass of expected)
        assert.ok(value.sensitivityClasses.includes(expectedClass));
      assert.ok(value.sensitivityClasses.includes("unknown"));
      assert.ok(
        !value.origins.some(({ fieldPath }) =>
          /\/(?:password|email)\//.test(fieldPath),
        ),
      );
      assert.equal(value.guards.length, 0);
      const directRun = setup(chain(web(), pass()));
      const direct = directRun.flow.resolveExpression(
        directRun.key("Sink"),
        `(${left} ${operator} ${right})${property}`,
      );
      for (const expectedClass of expected)
        assert.ok(direct.sensitivityClasses.includes(expectedClass));
      assert.notEqual(direct.status, "resolved");
    }
    const publicRun = setup(
      chain(
        web(),
        node("Formatter", "code", 2, {
          jsCode: `const a = {value: 'public'} ${operator} {value: 'other'}; return {json: {result: a.value, fixed: 'constant'}};`,
        }),
        pass(),
      ),
    );
    const publicProjection = publicRun.resolve("={{ $json.result }}");
    assert.equal(publicProjection.status, "partial");
    assert.ok(
      !publicProjection.sensitivityClasses.includes("secret_candidate"),
    );
    assert.ok(!publicProjection.sensitivityClasses.includes("pii_candidate"));
    assert.deepEqual(
      publicRun.resolve("={{ $json.fixed }}").sensitivityClasses,
      ["public_literal"],
    );
  }
});

test("scalar logical projections preserve sensitivity with explicit uncertainty", () => {
  const run = setup(chain(web(), pass()));
  for (const operator of ["||", "??"]) {
    for (const [expression, expected] of [
      [`($json.body.password ${operator} 'public')[0]`, ["secret_candidate"]],
      [
        `('synthetic@example.invalid' ${operator} 'public')[0]`,
        ["pii_candidate"],
      ],
      [
        `($json.body.password ${operator} $json.body.email).length`,
        ["secret_candidate", "pii_candidate"],
      ],
    ]) {
      const value = run.flow.resolveExpression(run.key("Sink"), expression);
      assert.equal(value.status, "partial");
      assert.ok(value.diagnosticCodes.includes("field_projection_partial"));
      for (const kind of expected)
        assert.ok(value.sensitivityClasses.includes(kind));
      assert.ok(
        !value.origins.some(({ fieldPath }) =>
          /\/(?:password|email)\//.test(fieldPath),
        ),
      );
      assert.equal(value.guards.length, 0);
    }
  }
});

test("null, missing, string and empty values never receive numeric proof on non-equality outcomes", () => {
  for (const filterVersion of [1, 2, 3]) {
    for (const value of [null, undefined, "3", "", [], false]) {
      for (const [operation, port] of [
        ["equals", 1],
        ["notEquals", 0],
        ["gte", 0],
      ]) {
        const conditions = filter("body.id", "number", 3);
        conditions.options.version = filterVersion;
        conditions.conditions[0].operator.operation = operation;
        const mapping = node("Map", "set", 3.4, {
          mode: "raw",
          jsonOutput: JSON.stringify({ body: { id: value } }),
        });
        const document = chain(
          web(),
          mapping,
          node("Guard", "if", 2.3, { conditions }),
          pass(),
        );
        document.connections.Guard.main =
          port === 0 ? [[edge("Sink")]] : [null, [edge("Sink")]];
        const run = setup(document);
        const result = run.resolve("={{ $json.body.id }}");
        assert.ok(!result.guards.some(({ kind }) => kind === "number_type"));
        assert.equal(run.resolve("={{ $json.body.other }}").guards.length, 0);
      }
    }
  }
});

test("SQL interpolation candidates remain on a strict false equality path that can carry null", () => {
  for (const filterVersion of [1, 2, 3]) {
    const conditions = filter("body.id", "number", 3);
    conditions.options.version = filterVersion;
    const database = node("Database", "postgres", 2.8, {
      operation: "executeQuery",
      query: "SELECT * FROM records WHERE id = {{ $json.body.id }}",
    });
    const document = chain(
      web(),
      node("Guard", "if", 2.3, { conditions }),
      database,
    );
    document.connections.Guard.main = [null, [edge("Database")]];
    const run = setup(document);
    const codes = analyzeAdvancedRisks(run.context, run.flow)
      .flatMap((rule) => rule.findings)
      .flatMap((finding) => finding.evidence.map((evidence) => evidence.code));
    assert.ok(codes.includes("sql_text_input_candidate"));
    assert.ok(!codes.includes("sql_numeric_value_guard_observed"));
  }
});

test("Switch dynamic or invalid fallback selectors preserve input with no guard on any supported version", () => {
  for (const version of [3, 3.1, 3.2, 3.3, 3.4, 3.5]) {
    for (const fallbackOutput of [
      "={{ 0 }}",
      "={{ $json.body.output }}",
      null,
      false,
      0.5,
      -1,
      2,
      "2",
      "00",
      "0.0",
      "unknown",
      {},
      [],
    ]) {
      const conditions = filter("body.id", "number", 3);
      conditions.options.version = 3;
      const route = node("Route", "switch", version, {
        rules: { values: [{ conditions }] },
        options: { fallbackOutput },
      });
      const run = setup(chain(web(), route, pass()));
      const value = run.resolve("={{ $json.body.id }}");
      assert.equal(value.status, "partial");
      assert.ok(
        value.diagnosticCodes.includes("switch_fallback_selector_unresolved"),
      );
      assert.equal(value.guards.length, 0);
      assert.ok(
        value.origins.some(
          ({ nodeKey, fieldPath }) =>
            nodeKey === run.key("Input") && fieldPath === "/body/id",
        ),
      );
    }
  }
});

test("Switch whole dynamic options and fallback reuse cannot inherit upstream or rule guards", () => {
  for (const options of [
    "={{ {fallbackOutput: 0} }}",
    null,
    false,
    [],
    { fallbackOutput: "={{ 0 }}" },
    { fallbackOutput: 0 },
  ]) {
    const conditions = filter("body.id", "number", 3);
    const route = node("Route", "switch", 3.4, {
      rules: { values: [{ conditions }] },
      options,
    });
    const run = setup(
      chain(web(), node("Upstream", "if", 2.2, { conditions }), route, pass()),
    );
    const value = run.resolve("={{ $json.body.id }}");
    assert.equal(value.status, "partial");
    assert.equal(value.guards.length, 0);
    assert.ok(
      value.diagnosticCodes.some((code) =>
        [
          "switch_options_unresolved",
          "switch_fallback_selector_unresolved",
          "switch_fallback_reuses_output",
        ].includes(code),
      ),
    );
  }
});

test("Switch static fallback profiles only attach the selected rule's proven guard", () => {
  for (const fallbackOutput of [undefined, "none", "extra", 1, "1", 0, "0"]) {
    const selected = filter("body.id", "number", 3);
    selected.options.version = 3;
    const route = node("Route", "switch", 3.4, {
      rules: {
        values: [
          { conditions: selected },
          { conditions: filter("body.id", "number", 4) },
        ],
      },
      options: fallbackOutput === undefined ? {} : { fallbackOutput },
    });
    const document = chain(web(), route, pass());
    const value = setup(document).resolve("={{ $json.body.id }}");
    const reusesPort = fallbackOutput === 0 || fallbackOutput === "0";
    assert.equal(value.status, reusesPort ? "partial" : "resolved");
    assert.equal(
      value.guards.some(({ kind }) => kind === "number_type"),
      !reusesPort,
    );
    assert.equal(
      value.guards.some(({ kind }) => kind === "equals_literal"),
      !reusesPort,
    );
    if (fallbackOutput === "extra") {
      document.connections.Route.main = [null, null, [edge("Sink")]];
      const fallback = setup(document).resolve("={{ $json.body.id }}");
      assert.equal(fallback.status, "resolved");
      assert.equal(fallback.guards.length, 0);
    }
  }
});

const boundedCode = (jsCode, annotations = []) =>
  setup(
    chain(web(), node("Formatter", "code", 2, { jsCode }), pass()),
    annotations,
  );

test("internal scalar constants never leak through dates, object wrappers or unknown transforms", () => {
  const run = setup(chain(web(), pass()));
  assert.equal(run.resolve("={{ 'SELECT ' + '1' }}").constant, "SELECT 1");
  assert.equal(run.resolve("={{ $json.body.query }}").constant, undefined);
  assert.equal(
    run.flow.resolveExpression(run.key("Sink"), "({query:'SELECT 1'})")
      .constant,
    undefined,
  );
  assert.equal(
    run.flow.resolveExpression(run.key("Sink"), "['SELECT 1']").constant,
    undefined,
  );
  assert.equal(
    run.flow.resolveExpression(run.key("Sink"), "' SELECT 1 '.trim()").constant,
    undefined,
  );
  const clock = boundedCode(
    "const today=new Date().toDateString(); return {json:{today}};",
  );
  assert.equal(clock.resolve("={{ $json.today }}").constant, undefined);
  const constant = boundedCode(
    "let query='SELECT '; query += '1'; return {json:{query}};",
  );
  assert.equal(constant.resolve("={{ $json.query }}").constant, "SELECT 1");
});

test("bounded let, string methods and JSON parse retain sensitive data through both exception outcomes", () => {
  const run = boundedCode(
    `let text=$json.body.email; text=text.trim().replace(/x/g,''); let result; try {result=JSON.parse(text);} catch(error) {result={fallback:text};} return {json:{result,fixed:'public'}};`,
  );
  const result = run.resolve("={{ $json.result }}");
  assert.ok(result.sensitivityClasses.includes("pii_candidate"));
  assert.notEqual(result.status, "resolved");
  const fixed = run.resolve("={{ $json.fixed }}");
  assert.equal(fixed.status, "resolved");
  assert.deepEqual(fixed.sensitivityClasses, ["public_literal"]);
  assert.ok(
    !run.flow.diagnostics.some(
      ({ code }) => code === "code_try_state_unresolved",
    ),
  );
});

test("object writes retain candidates and mark every returned projection opaque", () => {
  const alias = boundedCode(
    "const out={fixed:'public'}; const alias=out; alias.value=$json.body.password; return {json:out};",
  );
  assert.ok(
    alias
      .resolve("={{ $json.value }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  const separate = boundedCode(
    "const a={value:$json.body.password}; const b={value:$json.body.password}; b.value='public'; return {json:{first:a.value,second:b.value}};",
  );
  assert.ok(
    separate
      .resolve("={{ $json.first }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  const second = separate.resolve("={{ $json.second }}");
  assert.equal(second.status, "partial");
  assert.ok(second.sensitivityClasses.includes("secret_candidate"));
  assert.equal(second.constant, undefined);
  assert.ok(
    separate.flow.diagnostics.some(
      ({ code }) => code === "code_object_mutation_unresolved",
    ),
  );
  const pushed = boundedCode(
    "const a={x:'safe'}; const b=[]; b.push(a); a.x=$json.body.email; return {json:{v:b[0].x,fixed:'public'}};",
  );
  for (const field of ["v", "fixed"]) {
    const projected = pushed.resolve(`={{ $json.${field} }}`);
    assert.equal(projected.status, "partial");
    assert.ok(projected.sensitivityClasses.includes("pii_candidate"));
    assert.equal(projected.constant, undefined);
  }
  assert.ok(
    pushed.flow.diagnostics.some(
      ({ code }) => code === "code_object_mutation_unresolved",
    ),
  );
});

test("bounded if alternatives retain secret and personal classes without tainting independent fields", () => {
  const run = boundedCode(
    "let result=$json.body.password; if($json.body.flag){result=$json.body.email;} return {json:{result,fixed:'public'}};",
  );
  const result = run.resolve("={{ $json.result }}");
  assert.ok(result.sensitivityClasses.includes("secret_candidate"));
  assert.ok(result.sensitivityClasses.includes("pii_candidate"));
  assert.equal(result.guards.length, 0);
  assert.deepEqual(run.resolve("={{ $json.fixed }}").sensitivityClasses, [
    "public_literal",
  ]);
});

test("map summarizes every possible item and preserves current input wrapper fields", () => {
  const run = boundedCode(
    "return $input.all().map(item=>({json:{contact:item.json.body.email,fixed:'public'}}));",
  );
  const value = run.resolve("={{ $json.contact }}");
  assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  assert.ok(value.origins.some(({ fieldPath }) => fieldPath === "/body/email"));
  assert.deepEqual(run.resolve("={{ $json.fixed }}").sensitivityClasses, [
    "public_literal",
  ]);
  const later = boundedCode(
    "const values=[{value:'public'},{value:$json.body.password}]; return values.map(item=>({json:{result:item.value}}));",
  );
  assert.ok(
    later
      .resolve("={{ $json.result }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
});

test("multiple Code return items never discard sensitive later items", () => {
  const run = boundedCode(
    "return [{json:{value:'public'}},{json:{value:$json.body.password}},{json:{value:$json.body.email}}];",
  );
  const value = run.resolve("={{ $json.value }}");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  const malformed = boundedCode(
    "return {0:{json:{value:'public'}},secret:$json.body.password};",
  );
  const rejected = malformed.resolve("={{ $json.value }}");
  assert.notEqual(rejected.status, "resolved");
  assert.ok(rejected.sensitivityClasses.includes("secret_candidate"));
});

test("for-of and push preserve zero-iteration uncertainty and possible input classifications", () => {
  const run = boundedCode(
    "const result=[]; for(const item of $input.all()){result.push({json:{contact:item.json.body.email}});} return result;",
  );
  const value = run.resolve("={{ $json.contact }}");
  assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  assert.ok(
    run.flow.diagnostics.some(
      ({ code }) => code === "code_loop_summary_partial",
    ),
  );
});

test("spread ordering never proves an overwritten field public or loses classified unknown contents", () => {
  const annotations = [
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ];
  const before = boundedCode(
    "let out={...$json.body,fixed:'public'}; return {json:out};",
    annotations,
  );
  assert.deepEqual(before.resolve("={{ $json.fixed }}").sensitivityClasses, [
    "public_literal",
  ]);
  const after = boundedCode(
    "let out={fixed:'public',...$json.body}; return {json:out};",
    annotations,
  );
  const value = after.resolve("={{ $json.fixed }}");
  assert.notEqual(value.status, "resolved");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  const arraySpread = boundedCode(
    "let list=[...$json.body.password]; return {json:{result:list[7]}};",
    annotations,
  );
  assert.ok(
    arraySpread
      .resolve("={{ $json.result }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
});

test("pure local helpers retain data while closure writes and external calls stay opaque", () => {
  const pure = boundedCode(
    "function clean(value){return value.trim().replace(/x/g,'');} let result=clean($json.body.email); return {json:{result,fixed:'public'}};",
  );
  assert.ok(
    pure
      .resolve("={{ $json.result }}")
      .sensitivityClasses.includes("pii_candidate"),
  );
  assert.deepEqual(pure.resolve("={{ $json.fixed }}").sensitivityClasses, [
    "public_literal",
  ]);
  const annotations = [
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ];
  for (const source of [
    "let result='public'; function mutate(){result=$json.body.password; return 'public';} mutate(); return {json:{result}};",
    "let result=fetch('https://example.invalid'); return {json:{fixed:'public'}};",
    "let result='public'; while($json.body.flag){result=$json.body.password;} return {json:{result}};",
    "let result='public'; globalThis.__valueFlowExecuted=true; return {json:{result}};",
  ]) {
    const value = boundedCode(source, annotations).resolve("={{ $json }}");
    assert.notEqual(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  }
  assert.equal(globalThis.__valueFlowExecuted, undefined);
});

test("service read responses are new unknown external origins and AI generation retains prompt candidates", () => {
  for (const service of [
    node("Service", "gmail", 2.2, { operation: "getAll" }),
    node("Service", "airtable", 2.1, { operation: "search" }),
    node("Service", "googleSheets", 4.6, { operation: "read" }),
    node("Service", "httpRequest", 4.2, { url: "https://example.invalid" }),
  ]) {
    const run = setup(chain(web(), service, pass()));
    const value = run.resolve("={{ $json.email }}");
    assert.equal(value.status, "partial");
    assert.equal(value.trust, "external");
    assert.ok(value.sensitivityClasses.includes("unknown"));
    assert.ok(
      value.origins.every(({ nodeKey }) => nodeKey === run.key("Service")),
    );
  }
  const ai = {
    ...node("Model", "unused", 2.2, {
      promptType: "define",
      text: "={{ $json.body.password }}",
      options: { passthroughBinaryImages: false },
    }),
    type: "@n8n/n8n-nodes-langchain.agent",
  };
  const run = setup(chain(web(), ai, pass()));
  const output = run.resolve("={{ $json.output }}");
  assert.equal(output.status, "partial");
  assert.ok(output.sensitivityClasses.includes("secret_candidate"));
  assert.ok(output.sensitivityClasses.includes("unknown"));
  assert.equal(output.guards.length, 0);
  assert.equal(output.constant, undefined);
});

test("nested object and array aliases cannot retain stale public copies after mutation", () => {
  for (const source of [
    "function identity(value){return value;} const inner={value:'public'}; const out=identity(inner); inner.value=$json.body.password; return {json:{result:out.value}};",
    "const inner={value:'public'}; function read(){return inner;} const out=read(); inner.value=$json.body.password; return {json:{result:out.value}};",
    "const inner={value:'public'}; let out; out=inner; inner.value=$json.body.password; return {json:{result:out.value}};",
    "const inner={value:'public'}; const out={inner}; inner.value=$json.body.password; return {json:{result:out.inner.value}};",
    "const inner={value:'public'}; const out=[inner]; inner.value=$json.body.email; return {json:{result:out[0].value}};",
    "const inner=['public']; const out={inner}; inner.push($json.body.password); return {json:{result:out.inner}};",
  ]) {
    const run = boundedCode(source);
    const value = run.resolve("={{ $json.result }}");
    assert.equal(value.status, "partial");
    assert.ok(
      value.sensitivityClasses.includes(
        source.includes("email") ? "pii_candidate" : "secret_candidate",
      ),
    );
    assert.equal(value.constant, undefined);
    assert.ok(
      run.flow.diagnostics.some(({ code }) =>
        [
          "code_nested_alias_mutation_unresolved",
          "code_closure_capture_unresolved",
        ].includes(code),
      ),
    );
  }
});

test("helpers with outer variable captures stay opaque across shadowing callers and branches", () => {
  const run = boundedCode(
    "let value=$json.body.password; function read(){return value;} function wrapper(value){return read();} const result=wrapper('public'); return {json:{result}};",
  );
  const value = run.resolve("={{ $json.result }}");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(value.constant, undefined);
  assert.equal(value.status, "partial");
  assert.ok(
    run.flow.diagnostics.some(
      ({ code }) => code === "code_closure_capture_unresolved",
    ),
  );
  const updated = boundedCode(
    "let value='public'; function read(){return value;} value=$json.body.email; let result=read(); return {json:{result}};",
  );
  assert.ok(
    updated
      .resolve("={{ $json.result }}")
      .sensitivityClasses.includes("pii_candidate"),
  );
  const branch = boundedCode(
    "let value='public'; let result='public'; function read(){return value;} if($json.body.flag){value=$json.body.password;result=read();} return {json:{result}};",
  );
  assert.ok(
    branch
      .resolve("={{ $json.result }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  const shadow = boundedCode(
    "let value='public'; function read(){return value;} function wrapper(value){return read();} let result='public'; if($json.body.flag){value=$json.body.password; result=wrapper('public');} return {json:{result}};",
  );
  const classified = shadow.resolve("={{ $json.result }}");
  assert.equal(classified.status, "partial");
  assert.ok(classified.sensitivityClasses.includes("secret_candidate"));
});

test("loop-carried assignments preserve later-iteration inputs even when first assignment is unchanged", () => {
  const run = boundedCode(
    "let previous='public'; let result='public'; for(const item of [$json.body.password,$json.body.email]){result=previous;previous=item;} return {json:{result,fixed:'public'}};",
  );
  const value = run.resolve("={{ $json.result }}");
  assert.equal(value.status, "partial");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(value.sensitivityClasses.includes("pii_candidate"));
  assert.equal(value.constant, undefined);
  assert.deepEqual(run.resolve("={{ $json.fixed }}").sensitivityClasses, [
    "public_literal",
  ]);
  assert.ok(
    run.flow.diagnostics.some(
      ({ code }) => code === "code_loop_carried_state_unverified",
    ),
  );
});

test("array truncation and unresolved writes retain known RHS candidates in the returned value", () => {
  const entries = Array.from({ length: 128 }, () => "'public'").join(",");
  for (const source of [
    `const out=[${entries}]; out.push($json.body.password,$json.body.email); return {json:{result:out}};`,
    `let out=[${entries},$json.body.password,$json.body.email]; return {json:{result:out}};`,
    "const out={value:'public'}; out[$json.body.key]=$json.body.password+$json.body.email; return {json:{result:out}};",
    "let out={[$json.body.key]:$json.body.password+$json.body.email}; return {json:{result:out}};",
  ]) {
    const value = boundedCode(source).resolve("={{ $json.result }}");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.equal(value.constant, undefined);
  }
});

test("prototype mutations stay opaque and never mutate analysis dictionaries", () => {
  const annotations = [
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
  ];
  for (const source of [
    "let out={__proto__:$json.body}; return {json:{result:out.password}};",
    "let out={}; out['__proto__']=$json.body; return {json:{result:out.password}};",
    "let out={'__proto__':{password:$json.body.password}}; return {json:{result:out.password}};",
  ]) {
    const run = boundedCode(source, annotations);
    const value = run.resolve("={{ $json.result }}");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.equal(value.constant, undefined);
    assert.ok(
      run.flow.diagnostics.some(
        ({ code }) => code === "code_prototype_semantics_unresolved",
      ),
    );
  }
  assert.equal(Object.prototype.password, undefined);
  for (const source of [
    "const out={__proto__:{password:$json.body.password}}; return [{json:{result:out.password}}];",
    "return [{json:{__proto__:{password:$json.body.password}}}];",
  ]) {
    const run = boundedCode(source);
    const value = run.resolve("={{ $json.result }}");
    assert.notEqual(value.status, "resolved");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  }
});

test("abstract shape and constant budgets stop exponential construction before allocation", () => {
  const source = [
    "let a0={value:$json.body.password};",
    ...Array.from(
      { length: 10 },
      (_, i) => `let a${i + 1}={left:a${i},right:a${i}};`,
    ),
    "return {json:{result:a10}};",
  ].join("");
  const shape = boundedCode(source);
  const value = shape.resolve("={{ $json.result }}");
  assert.equal(value.status, "partial");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(
    shape.flow.diagnostics.some(
      ({ code }) => code === "code_value_shape_limit",
    ),
  );
  assert.ok(JSON.stringify(value).length < 65536);
  const text = boundedCode(
    "let x='x';" + "x=x+x;".repeat(18) + "return {json:{x}};",
  );
  const huge = text.resolve("={{ $json.x }}");
  assert.equal(huge.status, "partial");
  assert.equal(huge.constant, undefined);
  assert.ok(
    text.flow.diagnostics.some(
      ({ code }) => code === "constant_inference_size_limit",
    ),
  );
});

test("unsupported object properties retain computed-key, RHS and spread classifications", () => {
  const run = setup(chain(web(), pass()), [
    {
      node: "Input",
      fieldPath: "body.password",
      sensitivity: "secret_candidate",
      provenance: "schema",
    },
    {
      node: "Input",
      fieldPath: "body.email",
      sensitivity: "pii_candidate",
      provenance: "schema",
    },
  ]);
  for (const expression of [
    "({[$json.body.email]:$json.body.password}).x",
    "({...$json.body}).x",
    "({...{}, result:$json.body.password, contact:$json.body.email}).result",
    "({['public']:'public', result:$json.body.password, contact:$json.body.email}).result",
    "({__proto__:{},result:$json.body.password,contact:$json.body.email}).result",
    "({...{}, password:'synthetic-private', email:'synthetic@example.test'}).missing",
  ]) {
    const value = run.flow.resolveExpression(run.key("Sink"), expression);
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.equal(value.constant, undefined);
  }
  const crowded = `({...{}, secret:$json.body.password, ${Array.from({ length: 128 }, (_, index) => `v${index}:'public'`).join(",")}}).missing`;
  const limited = run.flow.resolveExpression(run.key("Sink"), crowded);
  assert.equal(limited.status, "partial");
  assert.ok(limited.sensitivityClasses.includes("secret_candidate"));
  assert.ok(limited.sensitivityClasses.includes("unknown"));
  assert.ok(limited.diagnosticCodes.includes("flow_field_limit"));
  for (const source of [
    "return [{json:{result: ({[$json.body.email]:$json.body.password}).x}}];",
    "const a={...$json.body.password}; return [{json:{result:a.x}}];",
  ]) {
    const value = boundedCode(source).resolve("={{ $json.result }}");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.equal(value.constant, undefined);
  }
});

test("try catch never loses an intermediate sensitive assignment on the exception path", () => {
  const run = boundedCode(
    "let x='safe'; try{x=$env.SECRET;JSON.parse($json.body.text);}catch(e){return{json:{v:x}};}return{json:{v:'safe'}};",
  );
  const value = run.resolve("={{ $json.v }}");
  assert.equal(value.status, "partial");
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(value.constant, undefined);
  assert.ok(
    run.flow.diagnostics.some(
      ({ code }) => code === "code_try_state_unresolved",
    ),
  );
});

test("JS and n8n template constants preserve literal-substitution order for destination policy", () => {
  const expected = "https://blocked.example/https://allowed.example/";
  const code = boundedCode(
    "let x='https://allowed.example/';return{json:{v:`https://blocked.example/${x}`}};",
  );
  const raw = setup(chain(web(), pass()));
  const values = [
    code.resolve("={{ $json.v }}"),
    raw.flow.resolveExpression(
      raw.key("Sink"),
      "`https://blocked.example/${'https://allowed.example/'}`",
    ),
    raw.resolve("=https://blocked.example/{{ 'https://allowed.example/' }}"),
  ];
  for (const value of values) {
    assert.equal(value.constant, expected);
    const policy = {
      policy: {
        egress: [
          {
            id: "route",
            nodeKey: "sink",
            sink: "http",
            mode: "allowlist",
            destinations: ["https://allowed.example/"],
            allowedDataClasses: ["public"],
          },
        ],
      },
    };
    assert.equal(
      assessDestination(policy, "sink", "http", value.constant, ["public"])
        .status,
      "disallowed",
    );
  }
  assert.equal(
    raw.resolve("=prefix{{ 'a' }}middle{{ 'b' }}suffix").constant,
    "prefixamiddlebsuffix",
  );
  assert.equal(
    raw.flow.resolveExpression(
      raw.key("Sink"),
      "`prefix${'a'}middle${'b'}suffix`",
    ).constant,
    "prefixamiddlebsuffix",
  );
  assert.equal(raw.resolve("= {{ 'public' }} ").constant, " public ");
});

test("unsupported statement profiles retain lexical credential and personal source candidates", () => {
  const prefix = "const x=$env.SECRET; const person=$json.body.email;";
  for (const statement of [
    "while(false){}",
    "for(let i=0;i<0;i++){}",
    "for(const key in {}){}",
    "do{}while(false);",
    "switch(false){case true:break;}",
    "async function ignored(){await Promise.resolve($credentials.apiKey);}",
    "function* ignored(){yield $credentials.apiKey;}",
    "class Ignored { constructor(){globalThis.__valueFlowExecuted=true;} }",
    "import('synthetic-never-imported');",
  ]) {
    const run = boundedCode(prefix + statement + "return {json:{v:x}};");
    const value = run.resolve("={{ $json.v }}");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.ok(value.origins.some(({ kind }) => kind === "credential"));
    assert.equal(value.constant, undefined);
    assert.equal(value.fields, undefined);
    assert.equal(value.fieldsComplete, false);
    assert.deepEqual(value.guards, []);
    assert.ok(
      run.flow.diagnostics.some(
        ({ code }) => code === "code_source_observations_only",
      ),
    );
  }
  assert.equal(globalThis.__valueFlowExecuted, undefined);
});

test("opaque observations include bare credentials, template text and field-name personal candidates", () => {
  for (const expression of ["$env", "$credentials", "`${$env.SECRET}`"]) {
    const value = boundedCode(
      `const x=${expression}; while(false){} return {json:{v:x}};`,
    ).resolve("={{ $json.v }}");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.origins.some(({ kind }) => kind === "credential"));
    assert.equal(value.status, "partial");
  }
  for (const expression of [
    "{phone:'2025550123'}",
    "`synthetic@example.invalid`",
  ]) {
    const value = boundedCode(
      `const x=${expression}; while(false){} return {json:{v:x}};`,
    ).resolve("={{ $json.v }}");
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.equal(value.status, "partial");
  }
});

test("AST, source-size and syntax limits retain observed candidates without precise output claims", () => {
  const prefix = "const x=$env.SECRET;const person=$json.body.email;";
  for (const [source, diagnostic] of [
    [
      prefix +
        `const many=[${Array.from({ length: 2300 }, () => "0").join(",")}];while(false){}return {json:{v:x}};`,
      "code_ast_profile_limit",
    ],
    [prefix + "return {", "code_parse_unavailable"],
    [
      prefix + "/*" + "x".repeat(66000) + "*/return {json:{v:x}};",
      "code_source_size_limit",
    ],
    [
      prefix +
        "const phone='unused'; await unavailable(); return {json:{v:x}};",
      "code_call_effect_unresolved",
    ],
  ]) {
    const run = boundedCode(source);
    const value = run.resolve("={{ $json.v }}");
    assert.equal(value.status, "partial");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.sensitivityClasses.includes("pii_candidate"));
    assert.ok(value.origins.some(({ kind }) => kind === "credential"));
    assert.equal(value.constant, undefined);
    assert.deepEqual(value.guards, []);
    assert.ok(run.flow.diagnostics.some(({ code }) => code === diagnostic));
  }
  const plain = boundedCode(
    "const x='public';/*" + "x".repeat(66000) + "*/return{json:{v:x}};",
  );
  assert.notEqual(plain.resolve("={{ $json.v }}").status, "resolved");
  assert.ok(
    plain.flow.diagnostics.some(
      ({ code }) => code === "code_source_size_limit",
    ),
  );
});

test("opaque lexical observations do not treat comments strings regexes or ordinary keys as root reads", () => {
  for (const ending of [
    "while(false){}return {json:{v:'public'}};",
    "return {",
  ]) {
    const source =
      "// $env.SECRET $json.body.email\nconst a='$env.SECRET'; const b={$env:'public',$credentials:'public'};const pattern=/\\$env.SECRET/;" +
      ending;
    const value = boundedCode(source).resolve("={{ $json.v }}");
    assert.equal(value.sensitivityClasses.includes("secret_candidate"), false);
    assert.equal(value.sensitivityClasses.includes("pii_candidate"), false);
    assert.equal(
      value.origins.some(({ kind }) => kind === "credential"),
      false,
    );
    assert.notEqual(value.status, "resolved");
  }
});

test("source observations separate scoped bindings and inactive language fields from actual global reads", () => {
  for (const source of [
    "function f($env){return $env.ordinary;} while(false){} return {json:{v:'public'}};",
    "function f(){if(false){var $env;}return $env.ordinary;}while(false){}return{json:{v:'public'}};",
    "const C=class $env{m(){return $env.ordinary;}};while(false){}return{json:{v:'public'}};",
    "const $env={ordinary:'public'};while(false){}return {json:{v:$env.ordinary}};",
    "{const {$env}=object;while(false){} const x=$env.ordinary;}return{json:{v:'public'}};",
    "const x=object?.$env; )",
    "const x={$env(){return 'public';}}; )",
    "function f($env){return 'public';} )",
    "const {$env}=object; )",
    "let $env={ordinary:'public'};const x=$env.ordinary; )",
    "const {ordinary:$env}=object;const x=$env.ordinary; )",
  ]) {
    const value = boundedCode(source).resolve("={{ $json.v }}");
    assert.equal(value.sensitivityClasses.includes("secret_candidate"), false);
    assert.equal(
      value.origins.some(({ kind }) => kind === "credential"),
      false,
    );
    assert.notEqual(value.status, "resolved");
  }
  for (const source of [
    "function unused($env){} const x=$env.SECRET;while(false){}return{json:{v:x}};",
    "const C=class $env{m(){return $env.ordinary;}};const x=$env.SECRET;while(false){}return{json:{v:x}};",
    "{const $env={ordinary:'public'};const ignored=$env.ordinary;} const x=$env.SECRET;while(false){}return{json:{v:x}};",
  ]) {
    const value = boundedCode(source).resolve("={{ $json.v }}");
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.origins.some(({ kind }) => kind === "credential"));
  }
  const inactive = setup(
    chain(
      web(),
      node("Formatter", "code", 2, {
        language: "python",
        pythonCode: "return []",
        jsCode: "const x=$env.SECRET;/*" + "x".repeat(66000) + "*/",
      }),
      pass(),
    ),
  );
  const value = inactive.resolve("={{ $json.v }}");
  assert.equal(value.sensitivityClasses.includes("secret_candidate"), false);
  assert.ok(
    inactive.flow.diagnostics.some(
      ({ code }) => code === "code_language_unresolved",
    ),
  );
  assert.equal(
    inactive.flow.diagnostics.some(
      ({ code }) => code === "code_source_size_limit",
    ),
    false,
  );
});
