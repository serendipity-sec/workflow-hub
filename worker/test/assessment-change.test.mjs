import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  applyRemediation,
  compareDefinitions,
  createRemediationPlans,
  definitionComparisonSchema,
  remediationPlansSchema,
} from "../dist/assessment-change.js";
import { parseEvidence } from "../dist/assessment-evidence.js";
import { createContext } from "../dist/static-context.js";
import { analyzeSettings } from "../dist/static-settings.js";
import { analyzeFlow } from "../dist/static-flow.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const encode = (value) => Buffer.from(JSON.stringify(value));
const node = (id, type, parameters = {}, typeVersion = 1) => ({
  id,
  name: `fixture-${id}`,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const workflow = (nodes, connections = {}, extra = {}) => ({
  nodes,
  connections,
  ...extra,
});
const kinds = (value) => value.changes.map(({ kind }) => kind);
const compare = (before, after, ...evidence) =>
  definitionComparisonSchema.parse(
    compareDefinitions(encode(before), encode(after), ...evidence),
  );
const settingsPlans = (bytes) => {
  const context = createContext(bytes);
  const findings = analyzeSettings(context).flatMap(({ findings }) => findings);
  return remediationPlansSchema.parse(
    createRemediationPlans(context, findings, hash(bytes)),
  );
};
const sqlPlans = (bytes) => {
  const context = createContext(bytes);
  const findings = analyzeFlow(context).flatMap(({ findings }) => findings);
  return remediationPlansSchema.parse(
    createRemediationPlans(context, findings, hash(bytes)),
  );
};

test("informational protections and capabilities do not create correction plans", () => {
  const input = encode(
    workflow([
      node("request", "webhook", { authentication: "headerAuth" }, 2),
      node("command", "executeCommand", { command: "echo fixture" }, 1),
    ]),
  );
  const context = createContext(input);
  const information = analyzeSettings(context)
    .flatMap((rule) => rule.findings)
    .filter((finding) => finding.severity === "info");
  assert.ok(information.length > 0);
  assert.deepEqual(
    createRemediationPlans(context, information, hash(input)),
    [],
  );
});
const queryWorkflow = (
  query = "=SELECT owner FROM records WHERE id = {{ $json.body.id }}",
  options,
) =>
  workflow(
    [
      node(
        "webhook",
        "webhook",
        { httpMethod: "POST", responseMode: "onReceived" },
        2,
      ),
      node(
        "postgres",
        "postgres",
        {
          operation: "executeQuery",
          query,
          ...(options === undefined ? {} : { options }),
        },
        2.8,
      ),
    ],
    {
      "fixture-webhook": {
        main: [[{ node: "fixture-postgres", type: "main", index: 0 }]],
      },
    },
  );

test("definition comparison ignores object and node ordering but preserves exact byte identities", () => {
  const first = node("first", "noOp");
  const second = node("second", "noOp");
  const before = workflow([first, second]);
  const after = { connections: {}, nodes: [second, first] };
  const result = compare(before, after);
  assert.equal(result.byteIdentity, "different");
  assert.deepEqual(result.changes, []);
  assert.equal(result.securityEquivalent, "not_claimed");
  assert.equal(result.behaviorPreserved, "not_verified");
  assert.equal(
    compareDefinitions(
      encode(before),
      Buffer.from(JSON.stringify(before, null, 2)),
    ).changes.length,
    0,
  );
});

test("SEC-VERSION-04 fixed auth, URL, recipient and database declarations are compared without values", () => {
  const before = workflow([
    node(
      "http",
      "httpRequest",
      { url: "https://secret-old.invalid/a", authentication: "none" },
      4.2,
    ),
    node(
      "mail",
      "emailSend",
      {
        toEmail: "private-old@example.invalid",
        options: { ccEmail: "private-cc@example.invalid" },
      },
      2,
    ),
    node("db", "postgres", { operation: "select" }, 2.8),
  ]);
  const after = structuredClone(before);
  after.nodes[0].parameters = {
    url: "https://secret-new.invalid/b",
    authentication: "genericCredentialType",
    genericAuthType: "httpHeaderAuth",
  };
  after.nodes[1].parameters.options.ccEmail = "private-new@example.invalid";
  after.nodes[2].parameters.operation = "deleteTable";
  const result = compare(before, after);
  for (const kind of [
    "authentication_changed",
    "destination_changed",
    "recipient_changed",
    "database_operation_changed",
  ])
    assert.ok(kinds(result).includes(kind), kind);
  assert.ok(
    result.changes
      .find(({ kind }) => kind === "destination_changed")
      .codes.includes("destination_origin_changed"),
  );
  for (const raw of [
    "secret-old.invalid",
    "secret-new.invalid",
    "private-old@example.invalid",
    "private-cc@example.invalid",
    "private-new@example.invalid",
    "deleteTable",
  ])
    assert.equal(JSON.stringify(result).includes(raw), false);
  const sameOrigin = structuredClone(before);
  sameOrigin.nodes[0].parameters.url =
    "https://secret-old.invalid/changed?q=private";
  assert.ok(
    compare(before, sameOrigin)
      .changes.find(({ kind }) => kind === "destination_changed")
      .codes.includes("request_target_path_or_query_changed"),
  );
});

test("recipient comparison does not misclassify unrelated email options", () => {
  const before = workflow([
    node(
      "mail",
      "emailSend",
      { toEmail: "synthetic@example.invalid", options: {} },
      2,
    ),
  ]);
  const after = structuredClone(before);
  after.nodes[0].parameters.options.appendAttribution = false;
  const result = compare(before, after);
  assert.equal(kinds(result).includes("recipient_changed"), false);
  assert.ok(kinds(result).includes("node_configuration_changed"));
});

test("executeQuery SQL AST detects SELECT to DELETE despite unchanged node operation", () => {
  const before = workflow([
    node(
      "db",
      "postgres",
      {
        operation: "executeQuery",
        query: "SELECT owner FROM records WHERE id = $1",
        options: { queryReplacement: "={{ [$json.body.id] }}" },
      },
      2.8,
    ),
  ]);
  const after = structuredClone(before);
  after.nodes[0].parameters.query = "DELETE FROM records WHERE id = $1";
  const result = compare(before, after);
  assert.ok(kinds(result).includes("database_operation_changed"));
  assert.equal(
    result.diagnostics.includes("database_operation_semantics_unresolved"),
    false,
  );
  const dynamic = structuredClone(before);
  dynamic.nodes[0].parameters.query = "={{ $json.body.query }}";
  assert.ok(
    compare(before, dynamic).diagnostics.includes(
      "database_operation_semantics_unresolved",
    ),
  );
  assert.equal(JSON.stringify(result).includes("records"), false);
});

test("SEC-VERSION-03 removals, disablement, guard edits and branch changes require recheck", () => {
  const before = workflow(
    [
      node("entry", "webhook", {}, 2),
      node("guard", "if", { conditions: { combinator: "and" } }, 2.2),
      node("command", "executeCommand", { command: "fixed-fixture-command" }),
    ],
    {
      "fixture-entry": {
        main: [[{ node: "fixture-guard", type: "main", index: 0 }]],
      },
      "fixture-guard": {
        main: [[{ node: "fixture-command", type: "main", index: 0 }], []],
      },
    },
  );
  const disabled = structuredClone(before);
  disabled.nodes[2].disabled = true;
  disabled.nodes[1].parameters.conditions.combinator = "or";
  disabled.connections["fixture-guard"].main = [
    [],
    [{ node: "fixture-command", type: "main", index: 0 }],
  ];
  const result = compare(before, disabled);
  for (const kind of ["node_disabled", "guard_changed", "connections_changed"])
    assert.ok(kinds(result).includes(kind), kind);
  assert.ok(result.changes.every(({ recheck }) => recheck === "required"));
  const removed = compare(
    before,
    workflow(before.nodes.slice(0, 2), {
      "fixture-entry": before.connections["fixture-entry"],
    }),
  );
  assert.ok(
    removed.changes
      .find(({ kind }) => kind === "node_removed")
      .codes.includes("node_removed_not_verified_remediation"),
  );
  const newIdentity = structuredClone(before);
  newIdentity.nodes[2].id = "different-node-identity";
  const unmatched = compare(before, newIdentity);
  assert.equal(unmatched.status, "inconclusive");
  assert.ok(
    unmatched.diagnostics.includes("node_identity_matching_incomplete"),
  );
});

test("SEC-ENV-01 same workflow bytes still compare changed policies, packages and runtime evidence", () => {
  const bytes = encode(workflow([node("noop", "noOp")]));
  const source = {
    id: "source",
    kind: "declaration",
    method: "user_declaration",
    recordedAt: "2026-11-22T00:00:00.000Z",
  };
  const metadata = {
    schemaVersion: "1.0.0",
    inputSha256: hash(bytes),
    sources: [source],
    runtime: {
      sourceId: source.id,
      environmentId: "private-env",
      n8nVersion: "2.0.0",
    },
    packages: [
      { name: "private-package", version: "1.0.0", sourceId: source.id },
    ],
    policy: {
      id: "private-policy",
      version: "1.0.0",
      sourceId: source.id,
      purpose: "private purpose",
      defaultDecision: "allow",
      unknownDecision: "inconclusive",
    },
  };
  const after = structuredClone(metadata);
  after.runtime.n8nVersion = "2.0.1";
  after.packages[0].version = "1.1.0";
  after.policy.version = "1.1.0";
  const result = compareDefinitions(
    bytes,
    bytes,
    parseEvidence(metadata, hash(bytes)),
    parseEvidence(after, hash(bytes)),
  );
  assert.equal(result.byteIdentity, "same");
  for (const kind of [
    "environment_changed",
    "packages_changed",
    "policy_changed",
  ])
    assert.ok(kinds(result).includes(kind));
  for (const raw of [
    "private-env",
    "private-package",
    "private-policy",
    "private purpose",
  ])
    assert.equal(JSON.stringify(result).includes(raw), false);
  assert.throws(
    () =>
      compareDefinitions(
        bytes,
        Buffer.from(bytes.toString() + " "),
        undefined,
        parseEvidence(after, hash(bytes)),
      ),
    { code: "evidence_input_mismatch" },
  );
});

test("TLS plan edits only the supported option and requires exact original bytes", () => {
  const bytes = encode(
    workflow([
      node(
        "http",
        "httpRequest",
        {
          url: "https://fixture.invalid",
          options: { allowUnauthorizedCerts: true, timeout: 5000 },
        },
        4.2,
      ),
      node(
        "code",
        "code",
        { jsCode: "throw new Error('uploaded-code-must-not-run')" },
        2,
      ),
    ]),
  );
  const snapshot = Buffer.from(bytes);
  const plan = settingsPlans(bytes).find(
    ({ kind }) => kind === "enable_tls_verification",
  );
  assert.ok(plan);
  assert.equal(plan.automatic, true);
  const edited = applyRemediation(bytes, plan);
  const parsed = JSON.parse(edited);
  assert.equal(
    parsed.nodes[0].parameters.options.allowUnauthorizedCerts,
    false,
  );
  assert.equal(parsed.nodes[0].parameters.options.timeout, 5000);
  assert.equal(
    parsed.nodes[1].parameters.jsCode,
    JSON.parse(bytes).nodes[1].parameters.jsCode,
  );
  assert.deepEqual(bytes, snapshot);
  assert.equal(
    analyzeSettings(createContext(edited))
      .flatMap(({ findings }) => findings)
      .some((finding) =>
        finding.evidence.some(
          ({ code }) => code === "tls_certificate_validation_disabled",
        ),
      ),
    false,
  );
  assert.throws(
    () => applyRemediation(Buffer.from(bytes.toString() + " "), plan),
    { code: "remediation_input_mismatch" },
  );
  assert.throws(
    () => applyRemediation(bytes, { ...plan, checks: ["invented_check"] }),
    { code: "invalid_remediation_plan" },
  );
  assert.throws(
    () =>
      applyRemediation(bytes, {
        ...plan,
        arbitraryPatch: { path: "/nodes", value: [] },
      }),
    { code: "invalid_remediation_plan" },
  );
});

test("narrow Postgres plan binds the actual operand and rescans the exact new definition", () => {
  const bytes = encode(queryWorkflow());
  const original = Buffer.from(bytes);
  const plan = sqlPlans(bytes).find(
    ({ kind }) => kind === "bind_postgres_lookup_value",
  );
  assert.ok(plan);
  const edited = applyRemediation(bytes, plan);
  const parameters = JSON.parse(edited).nodes[1].parameters;
  assert.equal(parameters.query, "SELECT owner FROM records WHERE id = $1");
  assert.equal(parameters.options.queryReplacement, "={{ [$json.body.id] }}");
  assert.deepEqual(bytes, original);
  const sql = analyzeFlow(createContext(edited)).find(
    ({ category }) => category === "sql",
  );
  assert.equal(
    sql.findings.some((finding) =>
      finding.evidence.some(({ code }) => code.includes("interpolation")),
    ),
    false,
  );
  assert.equal(plan.normalBehavior, "requires_validation");
  assert.equal(plan.execution, "not_run");
  assert.equal(JSON.stringify(plan).includes("records"), false);
  assert.ok(
    kinds(compareDefinitions(bytes, edited)).includes(
      "node_configuration_changed",
    ),
  );
});

test("legacy narrow SQL plan excludes quoted, compound, existing-binding and unknown-version queries", () => {
  const variants = [
    queryWorkflow("SELECT owner FROM records WHERE id = '{{ $json.body.id }}'"),
    queryWorkflow(
      "SELECT owner FROM records WHERE id = {{ $json.body.id }}; DELETE FROM records",
    ),
    queryWorkflow(
      "SELECT owner FROM records WHERE id = {{ $json.body.id }} OR owner = 'x'",
    ),
    queryWorkflow(undefined, { queryReplacement: "={{ [$json.body.other] }}" }),
    queryWorkflow(undefined, { queryBatching: "transaction" }),
  ];
  const older = queryWorkflow();
  older.nodes[1].typeVersion = 2.6;
  variants.push(older);
  const direct = queryWorkflow(
    "SELECT owner FROM records WHERE id = {{ $('fixture-webhook').first().json.body.id }}",
  );
  variants.push(direct);
  for (const value of variants)
    assert.equal(
      sqlPlans(encode(value)).some(
        ({ kind }) => kind === "bind_postgres_lookup_value",
      ),
      false,
    );
  const manual = settingsPlans(
    encode(
      workflow([
        node("command", "executeCommand", {
          command: "={{ $json.body.command }}",
        }),
      ]),
    ),
  )[0];
  assert.ok(manual && !manual.automatic);
  assert.throws(
    () =>
      applyRemediation(
        encode(
          workflow([
            node("command", "executeCommand", {
              command: "={{ $json.body.command }}",
            }),
          ]),
        ),
        manual,
      ),
    { code: "manual_remediation_required" },
  );
});
