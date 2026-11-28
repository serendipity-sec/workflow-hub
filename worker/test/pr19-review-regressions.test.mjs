import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { analyzeStatic } from "../dist/analysis/static-engine.js";
import { createContext } from "../dist/workflow/static-context.js";
import { compareStatic } from "../dist/analysis/static-compare.js";
import {
  reportStatus,
  stableId,
  staticReportSchema,
} from "../dist/contracts/static-contract.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";
import { analyzeAdvancedRisks } from "../dist/rules/advanced-risks.js";
import { assessBytes } from "../dist/assessment/assessment-engine.js";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { parseEvidence } from "../dist/assessment/assessment-evidence.js";
import {
  evaluatePolicy,
  policyEvaluationSchema,
} from "../dist/assessment/assessment-policy.js";
import { buildServiceReport } from "../dist/service/service-report.js";
import { newOutputPath } from "../validation/output-files.mjs";

const encode = (value) => Buffer.from(JSON.stringify(value));
const hash = (value) => createHash("sha256").update(value).digest("hex");
const node = (name, type, typeVersion = 1, parameters = {}) => ({
  id: name,
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((item, index) => [
        item.name,
        { main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});
const scanner = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};
const tools = async () => ({
  gitleaks: scanner,
  native: {
    tool: "native_inspection",
    version: "1.0.0",
    modes: ["nlp", "python"].map((mode) => ({
      mode,
      status: "completed",
      findings: [],
      diagnostics: [],
      versions: {
        python: "3.12.10",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    })),
  },
});
const scan = (document) =>
  staticReportSchema.parse(analyzeStatic(encode(document), scanner));
const ctx = (document) => createContext(encode(document));
const codes = (rules) =>
  rules.flatMap((rule) =>
    rule.findings.flatMap((finding) =>
      finding.evidence.map((entry) => entry.code),
    ),
  );

test("distinct private content fields retain distinct stable identities and masked evidence", () => {
  const make = (parameters) => chain(node("N", "noOp", 1, parameters));
  const before = scan(
    make({ password: "synthetic-one", token: "synthetic-two" }),
  );
  const findings = before.rules.find(
    (rule) => rule.category === "secrets",
  ).findings;
  assert.equal(findings.length, 2);
  assert.equal(new Set(findings.map((entry) => entry.id)).size, 2);
  assert.deepEqual(findings[0].location, findings[1].location);
  const next = scan(make({ token: "synthetic-two" }));
  assert.equal(
    next.rules.find((rule) => rule.category === "secrets").findings[0].id,
    findings[1].id,
  );
  assert.ok(!JSON.stringify(before).includes("synthetic-one"));
});

test("content identity changes are incomparable with the historical masked-location profile", () => {
  const current = scan(
    chain(node("N", "noOp", 1, { password: "synthetic-value" })),
  );
  const historical = structuredClone(current);
  const content = historical.rules.find((rule) => rule.category === "secrets");
  content.profileVersion = "1.0.0";
  const finding = content.findings[0];
  const priorId = finding.id;
  finding.id = stableId(
    content.ruleId,
    finding.location,
    "literal_credential_field",
  );
  assert.notEqual(finding.id, priorId);
  for (const coverage of content.coverage)
    coverage.findingIds = coverage.findingIds.map((id) =>
      id === priorId ? finding.id : id,
    );
  staticReportSchema.parse(historical);
  assert.equal(
    current.rules.find((rule) => rule.category === "secrets").profileVersion,
    "1.1.0",
  );
  const comparison = compareStatic(historical, current);
  assert.equal(comparison.basis, "same_input");
  assert.equal(comparison.rechecks[0].status, "inconclusive");
  assert.equal(comparison.newFindings[0].status, "inconclusive");
});

test("malformed selectors cannot crash independent inspection or gain a read profile", async () => {
  const malformed = { toString: null, valueOf: null };
  for (const [type, version, field] of [
    ["supabase", 1, "operation"],
    ["postgres", 2.8, "operation"],
    ["gmail", 2.1, "operation"],
    ["code", 2, "language"],
    ["removeDuplicates", 2, "compare"],
    ["readWriteFile", 1, "operation"],
    ["airtable", 2.1, "operation"],
    ["googleSheets", 4.7, "operation"],
  ]) {
    const result = await assessBytes(
      encode(
        chain(
          node("N", type, version, {
            [field]: malformed,
            password: "synthetic-value",
          }),
        ),
      ),
      { collectTools: tools },
    );
    assert.notEqual(result.status, "error", type);
    assert.ok(
      codes(result.files[0].base.rules).includes("literal_credential_field"),
      type,
    );
  }
  const context = ctx(
    chain(node("Read", "supabase", 1, { operation: ["get"] })),
  );
  const value = buildValueFlow(context).output(context.nodes[0].key, "/email");
  assert.notEqual(value.status, "resolved");
});

test("SQL candidate merging retains a later supported external source", () => {
  const context = ctx(
    chain(
      node("Input", "webhook", 2.1),
      node("DB", "postgres", 2.8, {
        operation: "executeQuery",
        query:
          "=SELECT * FROM t WHERE a={{ 'fixed' }} AND b={{ $json.body.id }}",
      }),
    ),
  );
  const rules = analyzeAdvancedRisks(context);
  const finding = rules
    .flatMap((rule) => rule.findings)
    .find((item) =>
      item.evidence.some((entry) => entry.code === "sql_text_input_candidate"),
    );
  assert.equal(finding?.claim, "supported_path");
  assert.ok(
    finding.evidence.some(
      (entry) => entry.location.nodeKey === context.nodes[0].key,
    ),
  );
});

test("named function expressions leave outer network aliases intact", () => {
  const context = ctx(
    chain(
      node("Code", "code", 2, {
        jsCode:
          "const send=fetch; const helper=function send() {}; send('https://example.invalid'); return [];",
      }),
    ),
  );
  assert.ok(
    codes(analyzeAdvancedRisks(context)).includes(
      "javascript_network_call_capability",
    ),
  );
});

test("implicit helper returns remain alternatives to explicit constant returns", () => {
  const context = ctx(
    chain(
      node("Input", "webhook", 2.1),
      node("Code", "code", 2, {
        jsCode:
          "function f(flag) { if (flag) return 'fixed'; } return [{json:{x:f($json.flag)}}];",
      }),
    ),
  );
  const value = buildValueFlow(context).output(context.nodes[1].key, "/x");
  assert.notEqual(value.constant, "fixed");
});

test("selected Set fields map input paths to actual flattened output names", () => {
  for (const dotNotation of [true, false]) {
    const context = ctx(
      chain(
        node("Input", "webhook", 2.1),
        node("Map", "set", 3.4, {
          includeOtherFields: true,
          include: "selected",
          includeFields: "body.email",
          options: { dotNotation },
        }),
      ),
    );
    const value = buildValueFlow(context).output(
      context.nodes[1].key,
      dotNotation ? "/email" : "/body.email",
    );
    assert.ok(
      value.origins.some(
        (origin) =>
          origin.fieldPath === (dotNotation ? "/body/email" : "/body.email"),
      ),
    );
    assert.notEqual(value.presence, "absent");
  }
});

test("binary Set assignments retain uncertain JSON metadata instead of proving absence", () => {
  const context = ctx(
    chain(
      node("Input", "webhook", 2.1),
      node("Map", "set", 3.4, {
        assignments: {
          assignments: [{ name: "attachment", type: "binary", value: "data" }],
        },
      }),
    ),
  );
  const value = buildValueFlow(context).output(
    context.nodes[1].key,
    "/attachment",
  );
  assert.notEqual(value.presence, "absent");
  assert.ok(
    value.diagnosticCodes.includes("set_binary_json_assignment_unverified"),
  );
});

test(
  "nested annotations build each child once and preserve the deepest sensitivity",
  { timeout: 5000 },
  () => {
    const context = ctx(chain(node("Input", "webhook", 2.1)));
    const sourceAnnotations = Array.from({ length: 32 }, (_, index) => ({
      nodeKey: context.nodes[0].key,
      fieldPath: "/x".repeat(index + 1),
      sensitivity: index === 31 ? "secret_candidate" : "public_literal",
      provenance: "operator",
    }));
    const value = buildValueFlow(context, { sourceAnnotations }).output(
      context.nodes[0].key,
      "",
    );
    assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  },
);

test("transport finding overflow preserves bounded findings and other categories", () => {
  for (const count of [85, 86]) {
    const nodes = Array.from({ length: count }, (_, index) =>
      node(String(index), "httpRequest", 4.2, {
        url: "http://synthetic:synthetic@example.invalid",
        options: { allowUnauthorizedCerts: true },
        ...(index === 0 ? { password: "synthetic-value" } : {}),
      }),
    );
    const report = scan({ nodes, connections: {} });
    assert.notEqual(report.status, "error");
    const rule = report.rules.find((entry) => entry.category === "transport");
    assert.equal(rule.findings.length, Math.min(256, count * 3));
    assert.ok(
      report.rules.find((entry) => entry.category === "secrets").findings
        .length > 0,
    );
    if (count === 86)
      assert.ok(
        rule.diagnostics.some(
          (entry) => entry.code === "definition_finding_limit",
        ),
      );
  }
});

test("error-payload diagnostic overflow keeps the report and independent secret evidence", () => {
  const nodes = Array.from({ length: 86 }, (_, index) =>
    node(String(index), "stopAndError", 1, {
      errorType: "future",
      ...(index === 0 ? { password: "synthetic-value" } : {}),
    }),
  );
  const report = scan({ nodes, connections: {} });
  assert.notEqual(report.status, "error");
  assert.ok(report.rules.every((rule) => rule.diagnostics.length <= 256));
  assert.ok(codes(report.rules).includes("literal_credential_field"));
  assert.ok(
    report.rules.some((rule) =>
      rule.diagnostics.some(
        (entry) => entry.code === "definition_diagnostic_limit",
      ),
    ),
  );
});

test("partial scopes override broad checked scopes in both comparison directions", () => {
  const before = scan(
    chain(node("N", "noOp", 1, { password: "synthetic-value" })),
  );
  const location = before.rules.find((entry) => entry.category === "secrets")
    .findings[0].location;
  for (const gapLocation of [location, { nodeKey: null, pointer: "/nodes" }]) {
    const after = scan(chain(node("N", "noOp")));
    const rule = after.rules.find((entry) => entry.category === "secrets");
    const diagnostic = {
      id: hash("unsupported field"),
      code: "native_invalid_report",
      location: gapLocation,
    };
    rule.diagnostics.push(diagnostic);
    rule.coverage.push({
      location: gapLocation,
      status: "unsupported",
      findingIds: [],
      diagnosticIds: [diagnostic.id],
    });
    after.status = reportStatus(after.rules);
    staticReportSchema.parse(after);
    assert.equal(
      compareStatic(before, after).rechecks[0].status,
      "inconclusive",
    );
    assert.equal(
      compareStatic(after, before).newFindings[0].status,
      "inconclusive",
    );
  }
});

test("compare-static accepts valid static reports larger than the legacy SQL output cap", async () => {
  const report = scan({
    nodes: Array.from({ length: 25 }, (_, i) =>
      node(String(i), "httpRequest", 4.2, {
        url: "http://synthetic:synthetic@example.invalid",
        options: { allowUnauthorizedCerts: true },
      }),
    ),
    connections: {},
  });
  const serialized = JSON.stringify(report);
  assert.ok(Buffer.byteLength(serialized) > 128 * 1024);
  const directory = await mkdtemp(join(tmpdir(), "pr19-compare-"));
  try {
    const path = join(directory, "report.json");
    await writeFile(path, serialized);
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        fileURLToPath(new URL("../dist/cli.js", import.meta.url)),
        "compare-static",
        path,
        path,
      ],
      { env: {}, timeout: 10000, windowsHide: true },
    );
    const comparison = JSON.parse(stdout);
    assert.equal(comparison.basis, "same_input");
    assert.ok(comparison.rechecks.length > 0);
    assert.ok(
      comparison.rechecks.every((item) => item.status === "persisting"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("base failure preserves independently established extension policy blocks", () => {
  const report = scan(
    chain(node("HTTP", "httpRequest", 4.2, { url: "http://example.invalid" })),
  );
  const extension = report.rules.filter(
    (rule) => rule.category === "transport",
  );
  const evidence = parseEvidence(
    {
      schemaVersion: "1.0.0",
      inputSha256: report.inputSha256,
      sources: [
        {
          id: "s",
          kind: "declaration",
          method: "user_declaration",
          recordedAt: "2026-11-28T00:00:00.000Z",
        },
      ],
      policy: {
        id: "p",
        version: "1",
        sourceId: "s",
        purpose: "synthetic",
        defaultDecision: "block",
        unknownDecision: "inconclusive",
      },
    },
    report.inputSha256,
  );
  const base = { ...report, status: "error", code: "analyzer_output_limit" };
  delete base.rules;
  const result = policyEvaluationSchema.parse(
    evaluatePolicy(base, extension, evidence, "2026-11-28T01:00:00.000Z"),
  );
  assert.equal(result.status, "analysis_failed");
  assert.equal(result.decision, "block");
  assert.ok(result.findingDecisions.length > 0);
  assert.equal(result.publication.status, "hold");
});

test("schema-valid analyzed external reports with failed tools produce a partial service result", async () => {
  const report = await assessBytes(encode(chain(node("N", "noOp"))), {
    collectTools: tools,
  });
  for (const file of report.files) {
    file.base.status = "analyzed";
    for (const rule of [...file.base.rules, ...file.extensionRules]) {
      rule.diagnostics = [];
      for (const coverage of rule.coverage) {
        coverage.diagnosticIds = [];
        if (["partial", "unsupported"].includes(coverage.status))
          coverage.status = "checked";
      }
    }
    file.tools.gitleaks = {
      ...scanner,
      status: "error",
      reason: "tool_timeout",
    };
  }
  report.status = "analyzed";
  assessmentReportSchema.parse(report);
  const service = buildServiceReport(report);
  assert.equal(service.executionStatus, "completed_with_errors");
  assert.equal(service.assessmentStatus, "partial");
  assert.equal(service.analysisStatus, "review_required");
});

test("assessment snapshots caller bytes and observes cancellation after tool collection", async () => {
  const input = encode(chain(node("N", "noOp")));
  const expectedHash = hash(input);
  const result = await assessBytes(input, {
    collectTools: async () => {
      input.fill(0);
      return tools();
    },
  });
  assert.notEqual(result.status, "error");
  assert.equal(result.inputSha256, expectedHash);
  const controller = new AbortController();
  const cancelled = await assessBytes(encode(chain(node("N", "noOp"))), {
    signal: controller.signal,
    collectTools: async () => {
      controller.abort();
      return tools();
    },
  });
  assert.equal(cancelled.status, "error");
  assert.equal(cancelled.code, "cancelled");
});

test("validation outputs reject frozen directories and preexisting artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "pr19-output-"));
  try {
    const frozen = join(directory, "frozen");
    await mkdir(frozen);
    const manifest = join(frozen, "downloads.json");
    await writeFile(manifest, "frozen");
    await assert.rejects(newOutputPath(manifest, [frozen]));
    await assert.rejects(
      newOutputPath(join(frozen, "new", "output.json"), [frozen]),
    );
    assert.equal(await readFile(manifest, "utf8"), "frozen");
    const output = await newOutputPath(join(directory, "results", "run.json"), [
      frozen,
    ]);
    await writeFile(output, "new", { flag: "wx" });
    await assert.rejects(newOutputPath(output, [frozen]));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
