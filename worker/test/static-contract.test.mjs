import assert from "node:assert/strict";
import { test } from "node:test";
import { limits } from "../dist/contract.js";
import { WorkflowError } from "../dist/n8n.js";
import { createContext, safeLocation } from "../dist/static-context.js";
import {
  categories,
  locationFor,
  reportStatus,
  ruleResultSchema,
  stableId,
  staticReportSchema,
  staticResultVersions,
} from "../dist/static-contract.js";

const encode = (value) => Buffer.from(JSON.stringify(value));
const node = (id = "source", extra = {}) => ({
  id,
  name: id,
  type: "n8n-nodes-base.webhook",
  typeVersion: 2,
  parameters: {},
  ...extra,
});
const document = (nodes = [node()]) => ({ nodes, connections: {} });
const root = { nodeKey: null, pointer: "" };
const emptyRule = (category) => ({
  ruleId: `TEST_${category.toUpperCase()}`,
  category,
  profileVersion: "1.0.0",
  coverage: [
    { location: root, status: "checked", findingIds: [], diagnosticIds: [] },
  ],
  findings: [],
  diagnostics: [],
});
const envelope = (rules = categories.map(emptyRule)) => ({
  ...staticResultVersions,
  inputSha256: "1".repeat(64),
  execution: "not_run",
  status: reportStatus(rules),
  rules,
});

test("static context retains content independently of historical SQL support", () => {
  const value = document([
    node("custom", {
      type: "synthetic-community.integration",
      typeVersion: 99,
      disabled: true,
      parameters: { unsupported: "synthetic-private-value" },
      notes: "synthetic-note",
    }),
  ]);
  value.pinData = {
    "private-name": [{ json: { email: "fixture@example.invalid" } }],
  };
  value.settings = { saveDataSuccessExecution: "all" };
  const context = createContext(encode(value));
  assert.deepEqual(context.document, value);
  assert.equal(context.nodes[0].disabled, true);
  assert.equal(context.topology, "complete");
  assert.equal(context.nodeByKey.get(context.nodes[0].key), context.nodes[0]);
  assert.equal(context.nodeByName.get("custom"), context.nodes[0]);
  assert.ok(
    context.fields.some(
      ({ kind, value }) => kind === "key" && value === "private-name",
    ),
  );
  assert.ok(
    context.fields.some(({ value }) => value === "fixture@example.invalid"),
  );
  assert.deepEqual(
    context.fields.map(({ index }) => index),
    context.fields.map((_, index) => index),
  );
});

test("content locations never copy uploaded keys, pinData names or credential names", () => {
  const value = document([
    node("first", {
      parameters: {
        headerParameters: {
          parameters: [{ name: "x-private", value: "synthetic-token" }],
        },
        "secret/in/key~": "value",
      },
      credentials: {
        "private-credential-type": { name: "private-account-name" },
      },
    }),
  ]);
  value.pinData = {
    "private-node-name": { "secret/key": "private@example.invalid" },
  };
  value["private@example.invalid"] = "value";
  const context = createContext(encode(value));
  const safe = JSON.stringify(context.fields.map(({ location }) => location));
  for (const text of ["private", "secret", "synthetic-token", "~1", "~0"])
    assert.equal(safe.includes(text), false, text);
  assert.equal(
    context.fields.find(({ value }) => value === "synthetic-token").location
      .pointer,
    "/nodes/0/parameters/headerParameters/parameters/0/value",
  );
  assert.deepEqual(
    safeLocation(context, "/pinData/private-node-name/secret~1key"),
    { nodeKey: null, pointer: "/pinData" },
  );
  assert.deepEqual(safeLocation(context, "/private@example.invalid"), root);
});

test("static context preserves structural parser limits and never evaluates content", () => {
  assert.throws(
    () =>
      createContext(Buffer.from('{"nodes":[],"nodes":[],"connections":{}}')),
    (error) => error instanceof WorkflowError && error.code === "duplicate_key",
  );
  assert.throws(
    () => createContext(Buffer.alloc(limits.fileBytes + 1, 32)),
    (error) => error.code === "file_too_large",
  );
  assert.throws(
    () => createContext(Buffer.from([0xff])),
    (error) => error.code === "invalid_utf8",
  );
  const value = document([
    node("code", {
      type: "n8n-nodes-base.code",
      typeVersion: 2,
      parameters: {
        jsCode:
          "globalThis.__static_context_must_not_execute = true; throw new Error('executed');",
      },
    }),
  ]);
  delete globalThis.__static_context_must_not_execute;
  const context = createContext(encode(value));
  assert.equal(globalThis.__static_context_must_not_execute, undefined);
  assert.equal(context.nodes.length, 1);
});

test("numeric object keys are redacted while actual array offsets remain usable", () => {
  const value = document([
    node("first", {
      parameters: {
        1012345678: "phone-key",
        options: { 1234567890123456: "account-key" },
        headerParameters: {
          parameters: [{ name: "authorization", value: "test-value" }],
        },
      },
    }),
  ]);
  const context = createContext(encode(value));
  const locations = context.fields.map(({ location }) => location);
  assert.equal(JSON.stringify(locations).includes("1012345678"), false);
  assert.equal(JSON.stringify(locations).includes("1234567890123456"), false);
  assert.equal(
    context.fields.find(({ value }) => value === "test-value").location.pointer,
    "/nodes/0/parameters/headerParameters/parameters/0/value",
  );
  assert.equal(
    context.fields.find(({ value }) => value === "account-key").location
      .pointer,
    "/nodes/0/parameters/options",
  );
});

test("non-main edges remain explicit while unrelated content remains inspectable", () => {
  const value = document([
    node("a", { type: "synthetic.a" }),
    node("b", { type: "synthetic.b" }),
  ]);
  value.connections = {
    a: { ai_tool: [[{ node: "b", type: "ai_tool", index: 0 }]] },
  };
  const context = createContext(encode(value));
  assert.equal(context.edges.length, 0);
  assert.equal(context.unsupportedEdges[0].channel, "ai_tool");
  assert.equal(context.topology, "partial");
  assert.ok(context.fields.length > 0);
});

test("finding identity is stable across reorder and value changes without hashing values", () => {
  const before = createContext(encode(document([node("a"), node("b")])));
  const after = createContext(
    encode(
      document([
        node("b"),
        node("a", { parameters: { token: "changed-secret" } }),
      ]),
    ),
  );
  assert.equal(
    stableId(
      "TEST_SECRETS",
      locationFor(before.nodes[0], "/parameters"),
      "literal_candidate",
    ),
    stableId(
      "TEST_SECRETS",
      locationFor(after.nodes[1], "/parameters"),
      "literal_candidate",
    ),
  );
  assert.notEqual(stableId("TEST_SECRETS", root), stableId("TEST_PII", root));
});

test("rule contract rejects forged evidence, unreferenced findings and false checked coverage", () => {
  const rule = emptyRule("secrets");
  const finding = {
    id: stableId(rule.ruleId, root),
    ruleId: rule.ruleId,
    category: rule.category,
    severity: "medium",
    claim: "candidate",
    location: root,
    evidence: [{ code: "secret_candidate", location: root }],
    assumptions: ["key_validity_not_checked"],
    remediation: { code: "remove_literal", checks: ["rescan_exact_file"] },
  };
  rule.findings.push(finding);
  assert.equal(ruleResultSchema.safeParse(rule).success, false);
  rule.coverage[0].findingIds.push(finding.id);
  assert.equal(ruleResultSchema.safeParse(rule).success, true);
  assert.equal(
    ruleResultSchema.safeParse({
      ...rule,
      findings: [{ ...finding, raw: "private-token" }],
    }).success,
    false,
  );
  assert.equal(
    ruleResultSchema.safeParse({
      ...rule,
      findings: [{ ...finding, ruleId: "OTHER_RULE" }],
    }).success,
    false,
  );
  const diagnostic = {
    id: stableId(rule.ruleId, root, "unsupported"),
    code: "unsupported_profile",
    location: root,
  };
  rule.diagnostics.push(diagnostic);
  rule.coverage[0].diagnosticIds.push(diagnostic.id);
  assert.equal(ruleResultSchema.safeParse(rule).success, false);
  rule.coverage[0].status = "partial";
  assert.equal(ruleResultSchema.safeParse(rule).success, true);
});

test("report requires all ten categories, consistent versions and truthful completion", () => {
  const report = envelope();
  assert.equal(staticReportSchema.safeParse(report).success, true);
  assert.equal(
    staticReportSchema.safeParse({ ...report, rules: report.rules.slice(1) })
      .success,
    false,
  );
  assert.equal(
    staticReportSchema.safeParse({ ...report, contractVersion: "1.0.0" })
      .success,
    false,
  );
  assert.equal(
    staticReportSchema.safeParse({ ...report, execution: "completed" }).success,
    false,
  );
  assert.equal(
    staticReportSchema.safeParse({
      ...report,
      rules: [...report.rules, report.rules[0]],
    }).success,
    false,
  );
  const rule = report.rules[0];
  const diagnostic = {
    id: stableId(rule.ruleId, root, "unavailable"),
    code: "tool_unavailable",
    location: root,
  };
  rule.diagnostics.push(diagnostic);
  rule.coverage[0].status = "unsupported";
  rule.coverage[0].diagnosticIds.push(diagnostic.id);
  assert.equal(reportStatus(report.rules), "partial");
  assert.equal(staticReportSchema.safeParse(report).success, false);
  report.status = "partial";
  assert.equal(staticReportSchema.safeParse(report).success, true);
  assert.equal(
    staticReportSchema.safeParse({
      ...staticResultVersions,
      inputSha256: "0".repeat(64),
      execution: "not_run",
      status: "error",
      code: "invalid_json",
    }).success,
    true,
  );
});
