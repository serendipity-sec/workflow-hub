import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  applyRemediation,
  createRemediationPlans,
  remediationPlansSchema,
} from "../dist/assessment-change.js";
import { inspectSqlOperation } from "../dist/advanced-risks.js";
import { createContext } from "../dist/static-context.js";
import { analyzeFlow } from "../dist/static-flow.js";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fixture = (query, overrides = {}) => ({
  nodes: [
    {
      id: "fixture-webhook",
      name: "fixture-webhook",
      type: "n8n-nodes-base.webhook",
      typeVersion: 2,
      parameters: { httpMethod: "POST", responseMode: "onReceived" },
    },
    {
      id: "fixture-db",
      name: "fixture-db",
      type: "n8n-nodes-base.postgres",
      typeVersion: 2.8,
      parameters: { operation: "executeQuery", query },
      ...overrides,
    },
  ],
  connections: {
    "fixture-webhook": {
      main: [[{ node: "fixture-db", type: "main", index: 0 }]],
    },
  },
});
const encode = (workflow) => Buffer.from(JSON.stringify(workflow));
const plans = (bytes) => {
  const context = createContext(bytes);
  const findings = analyzeFlow(context).flatMap((rule) => rule.findings);
  return remediationPlansSchema.parse(
    createRemediationPlans(context, findings, hash(bytes)),
  );
};
const autoPlan = (bytes) => plans(bytes).find((plan) => plan.automatic);

test("extended SQL lookup binds nested current values and an exactly quoted value", () => {
  const query =
    "=SELECT customer_id, owner FROM public.records WHERE customer_id = {{ $json.body.customerId }} AND owner = '{{ $json.body.owner }}';";
  const bytes = encode(fixture(query));
  const snapshot = Buffer.from(bytes);
  const plan = autoPlan(bytes);
  assert.ok(plan);
  assert.equal(plan.kind, "bind_postgres_lookup_values");
  assert.equal(plan.normalBehavior, "requires_validation");
  assert.equal(plan.execution, "not_run");
  const revised = applyRemediation(bytes, plan);
  const original = JSON.parse(bytes);
  const changed = JSON.parse(revised);
  assert.equal(
    changed.nodes[1].parameters.query,
    "SELECT customer_id, owner FROM public.records WHERE customer_id = $1 AND owner = $2;",
  );
  assert.equal(
    changed.nodes[1].parameters.options.queryReplacement,
    "={{ [$json.body.customerId, $json.body.owner] }}",
  );
  assert.deepEqual(bytes, snapshot);
  assert.deepEqual(changed.nodes[0], original.nodes[0]);
  assert.deepEqual(changed.connections, original.connections);
  assert.equal(autoPlan(revised), undefined);
  const description = inspectSqlOperation(changed.nodes[1].parameters.query);
  assert.equal(description.status, "parsed");
  assert.deepEqual(description.operations, ["select"]);
  assert.equal(description.valueParameterCount, 2);
  const exposed = JSON.stringify(plan);
  for (const raw of ["customerId", "public.records", "owner", query])
    assert.equal(exposed.includes(raw), false);
});

test("extended SQL lookup preserves fixed SQL and value ordering without evaluation", () => {
  const query =
    " SELECT * FROM records\nWHERE id = {{ $json['query'][\"id\"] }}\nAND item = {{ $json.body.items[0].id }} AND tenant = {{ $json.tenant }} ";
  const bytes = encode(fixture(query));
  const plan = autoPlan(bytes);
  assert.ok(plan);
  const changed = JSON.parse(applyRemediation(bytes, plan));
  assert.equal(
    changed.nodes[1].parameters.query,
    " SELECT * FROM records\nWHERE id = $1\nAND item = $2 AND tenant = $3 ",
  );
  assert.equal(
    changed.nodes[1].parameters.options.queryReplacement,
    "={{ [$json['query'][\"id\"], $json.body.items[0].id, $json.tenant] }}",
  );
});

test("the original id lookup keeps the historical plan and output bytes", () => {
  const bytes = encode(
    fixture("=SELECT owner FROM records WHERE id = {{ $json.body.id }}"),
  );
  const plan = autoPlan(bytes);
  assert.equal(plan.kind, "bind_postgres_lookup_value");
  assert.ok(
    plan.preconditions.includes("single_unquoted_current_body_id_lookup"),
  );
  const changed = JSON.parse(applyRemediation(bytes, plan));
  assert.equal(
    changed.nodes[1].parameters.options.queryReplacement,
    "={{ [$json.body.id] }}",
  );
});

test("extended SQL patch refuses expressions and SQL outside its fixed value grammar", () => {
  const queries = [
    "SELECT * FROM records WHERE id = '{{ $json.body.id }} suffix'",
    "SELECT * FROM records WHERE id = 'prefix {{ $json.body.id }}'",
    'SELECT * FROM records WHERE id = "{{ $json.body.id }}"',
    "SELECT * FROM records WHERE id = E'{{ $json.body.id }}'",
    "SELECT * FROM records WHERE id = '{{ $json.body.id }}'::integer",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} OR tenant = {{ $json.tenant }}",
    "SELECT * FROM records WHERE id = {{ $json.body.id }}; DELETE FROM records",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} -- trailing",
    "SELECT * FROM records WHERE id = /* prefix */ {{ $json.body.id }}",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} AND tenant = $1",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} AND tenant = 'fixed'",
    "SELECT * FROM {{ $json.body.table }} WHERE id = {{ $json.body.id }}",
    "SELECT {{ $json.body.column }} FROM records WHERE id = {{ $json.body.id }}",
    "SELECT * FROM records WHERE id = {{ $json.body.id.toString() }}",
    "SELECT * FROM records WHERE id = {{ $json[$json.field] }}",
    "SELECT * FROM records WHERE id = {{ $json?.body?.id }}",
    "SELECT * FROM records WHERE id = {{ $JSON.body.id }}",
    "SELECT * FROM records WHERE id = {{ $json.body.id || 1 }}",
    "SELECT * FROM records WHERE id = {{ $('fixture-webhook').first().json.body.id }}",
    "UPDATE records SET owner = '{{ $json.body.owner }}' WHERE id = {{ $json.body.id }}",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} FOR UPDATE",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} ORDER BY id",
    "SELECT * FROM records WHERE id = {{ $json.body.id }} AND",
    "SELECT * FROM records WHERE id = {{ $json.a.b.c.d.e.f.g.h.i }}",
    "SELECT * FROM records WHERE id = {{ $json.__proto__.id }}",
    "SELECT * FROM records WHERE id = {{ $json['constructor'].id }}",
    'SELECT * FROM records WHERE id = {{ $json.body["prototype"].id }}',
  ];
  for (const query of queries) {
    assert.equal(autoPlan(encode(fixture(query))), undefined, query);
  }
});

test("extended SQL patch refuses option semantics, disabled nodes and prior versions", () => {
  const query = "SELECT * FROM records WHERE id = '{{ $json.body.id }}'";
  const variations = [
    fixture(query, { typeVersion: 2.4 }),
    fixture(query, { typeVersion: 2.5 }),
    fixture(query, { typeVersion: 2.6 }),
    fixture(query, { typeVersion: 2.9 }),
    fixture(query, { disabled: true }),
    fixture(query, {
      parameters: {
        operation: "executeQuery",
        query,
        options: { queryReplacement: "={{ [$json.body.id] }}" },
      },
    }),
    fixture(query, {
      parameters: {
        operation: "executeQuery",
        query,
        options: { queryBatching: "transaction" },
      },
    }),
    fixture(query, {
      parameters: {
        operation: "executeQuery",
        query,
        options: { treatQueryParametersInSingleQuotesAsText: true },
      },
    }),
    fixture(query, {
      parameters: { operation: "executeQuery", query, unknownParameter: true },
    }),
  ];
  for (const workflow of variations)
    assert.equal(autoPlan(encode(workflow)), undefined);
});

test("extended lookup is bounded and plans cannot be reused for changed bytes", () => {
  const query = (count) =>
    "SELECT * FROM records WHERE " +
    Array.from(
      { length: count },
      (_, index) => `field${index} = {{ $json.body.field${index} }}`,
    ).join(" AND ");
  const bytes = encode(fixture(query(8)));
  const plan = autoPlan(bytes);
  assert.ok(plan);
  const revised = JSON.parse(applyRemediation(bytes, plan));
  assert.equal(
    inspectSqlOperation(revised.nodes[1].parameters.query).valueParameterCount,
    8,
  );
  assert.equal(autoPlan(encode(fixture(query(9)))), undefined);
  assert.throws(
    () => applyRemediation(Buffer.from(bytes.toString() + " "), plan),
    { code: "remediation_input_mismatch" },
  );
  assert.throws(
    () => applyRemediation(bytes, { ...plan, preconditions: ["invented"] }),
    { code: "invalid_remediation_plan" },
  );
});
