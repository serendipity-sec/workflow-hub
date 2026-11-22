import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeStatic } from "../dist/static-engine.js";
import { createContext } from "../dist/static-context.js";
import {
  categories,
  staticReportSchema,
  staticResultVersions,
} from "../dist/static-contract.js";

// All expected facts below are declared before any scan. They are selected
// pattern/capability labels, not labels of real vulnerabilities or safe files.
// The external scanner is a controlled, sanitized fixture. Native Gitleaks
// measurements belong to verify-static-tools.mjs, not this rule-level corpus.
const hash = (value) => createHash("sha256").update(value).digest("hex");
const node = (id, kind, typeVersion, parameters = {}, extra = {}) => ({
  id,
  name: id,
  type: `n8n-nodes-base.${kind}`,
  typeVersion,
  parameters,
  ...extra,
});
const webhook = () => node("Input", "webhook", 2, { httpMethod: "POST" });
const request = (url, options = {}) =>
  node("Request", "httpRequest", 4.2, { url, options });
const inert = (extra = {}) => node("Inert", "noOp", 1, {}, extra);
const document = (...nodes) => ({ nodes, connections: {} });
const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((from, index) => [
        from.name,
        { main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});
const fact = (id, category, code, present, input, claim) => ({
  id,
  category,
  input,
  expected: { kind: "fact", code, present, ...(claim ? { claim } : {}) },
});
const samples = [
  fact(
    "literal_credential",
    "secrets",
    "literal_credential_field",
    true,
    document(
      node("Credential", "noOp", 1, { password: "synthetic-placeholder" }),
    ),
    "candidate",
  ),
  fact(
    "credential_reference",
    "secrets",
    "literal_credential_field",
    false,
    document(
      inert({
        credentials: { postgres: { id: "synthetic-credential-reference" } },
      }),
    ),
  ),
  fact(
    "email_format",
    "pii",
    "email_candidate",
    true,
    document(inert({ notes: "synthetic.person@example.invalid" })),
    "candidate",
  ),
  fact(
    "ordinary_text",
    "pii",
    "email_candidate",
    false,
    document(inert({ notes: "ordinary text; version 2.48.7" })),
  ),
  fact(
    "webhook_default_auth",
    "request_auth",
    "webhook_authentication_default_none",
    true,
    document(webhook()),
    "configuration",
  ),
  fact(
    "webhook_header_auth",
    "request_auth",
    "webhook_authentication_default_none",
    false,
    document(
      node(
        "Input",
        "webhook",
        2,
        { authentication: "headerAuth" },
        {
          credentials: {
            httpHeaderAuth: { id: "synthetic-credential-reference" },
          },
        },
      ),
    ),
  ),
  fact(
    "http_destination",
    "egress",
    "configured_request_destination",
    true,
    document(request("https://example.invalid/resource")),
    "configuration",
  ),
  fact(
    "no_http_destination",
    "egress",
    "configured_request_destination",
    false,
    document(inert()),
  ),
  fact(
    "dynamic_authority",
    "ssrf",
    "dynamic_request_authority",
    true,
    chain(webhook(), request("={{ $json.body.url }}")),
    "supported_path",
  ),
  fact(
    "fixed_origin_dynamic_path",
    "ssrf",
    "dynamic_request_authority",
    false,
    chain(webhook(), request("=https://example.invalid/{{ $json.body.path }}")),
  ),
  fact(
    "sql_text_interpolation",
    "sql",
    "dynamic_sql_text",
    true,
    chain(
      webhook(),
      node("Database", "postgres", 2.8, {
        operation: "executeQuery",
        query: "SELECT label FROM items WHERE id = {{ $json.body.id }}",
      }),
    ),
    "supported_path",
  ),
  fact(
    "sql_fixed_text_value_parameter",
    "sql",
    "dynamic_sql_text",
    false,
    chain(
      webhook(),
      node("Database", "postgres", 2.8, {
        operation: "executeQuery",
        query: "SELECT label FROM items WHERE id = $1",
        options: { queryReplacement: "={{ [ $json.body.id ] }}" },
      }),
    ),
  ),
  fact(
    "command_input_expression",
    "code_execution",
    "webhook_body_used_in_command_expression",
    true,
    chain(
      webhook(),
      node("Command", "executeCommand", 1, {
        command: "=echo {{ $json.body.value }}",
      }),
    ),
    "supported_path",
  ),
  fact(
    "command_fixed_text",
    "code_execution",
    "webhook_body_used_in_command_expression",
    false,
    document(
      node("Command", "executeCommand", 1, {
        command: "echo synthetic-output",
      }),
    ),
  ),
  fact(
    "tls_validation_disabled",
    "transport",
    "tls_certificate_validation_disabled",
    true,
    document(
      request("https://example.invalid", { allowUnauthorizedCerts: true }),
    ),
    "configuration",
  ),
  fact(
    "tls_validation_enabled",
    "transport",
    "tls_certificate_validation_disabled",
    false,
    document(
      request("https://example.invalid", { allowUnauthorizedCerts: false }),
    ),
  ),
  fact(
    "whole_input_response",
    "output",
    "whole_input_response",
    true,
    chain(webhook(), node("Response", "respondToWebhook", 1.4)),
    "supported_path",
  ),
  fact(
    "selected_field_response",
    "output",
    "whole_input_response",
    false,
    chain(
      webhook(),
      node("Response", "respondToWebhook", 1.4, {
        respondWith: "json",
        responseBody: "={{ $json.body.id }}",
      }),
    ),
  ),
  fact(
    "external_node_declaration",
    "dependencies",
    "community_or_external_node_declared",
    true,
    document(
      node(
        "Community",
        "placeholder",
        1,
        {},
        { type: "synthetic-community.action" },
      ),
    ),
    "configuration",
  ),
  fact(
    "core_node_declaration",
    "dependencies",
    "community_or_external_node_declared",
    false,
    document(webhook()),
  ),
  fact(
    "whole_input_console",
    "output",
    "javascript_whole_input_log_call",
    true,
    document(
      node("Logger", "code", 2, {
        jsCode: "console.info(JSON.stringify($input.all())); return [];",
      }),
    ),
    "candidate",
  ),
  fact(
    "literal_loopback",
    "ssrf",
    "configured_nonpublic_destination",
    true,
    document(request("http://2130706433/synthetic")),
    "configuration",
  ),
  {
    ...fact(
      "sanitized_scanner_mapping",
      "secrets",
      "gitleaks_secret_candidate",
      true,
      document(inert({ notes: "synthetic-scanner-marker" })),
      "candidate",
    ),
    scannerMode: "mapped_candidate",
  },
  {
    id: "missing_secret_tool",
    category: "secrets",
    input: document(inert()),
    scannerMode: "unavailable",
    expected: {
      kind: "state",
      status: "partial",
      diagnostic: "tool_unavailable",
      coverage: "partial",
    },
  },
  {
    id: "unsupported_http_version",
    category: "ssrf",
    input: document(
      node("Unknown", "httpRequest", 999, { url: "={{ $json.body.url }}" }),
    ),
    expected: {
      kind: "state",
      status: "partial",
      diagnostic: "unsupported_node_version",
      coverage: "unsupported",
    },
  },
  {
    id: "duplicate_json_key",
    category: null,
    raw: '{"nodes":[],"nodes":[],"connections":{}}',
    expected: { kind: "state", status: "error", code: "duplicate_key" },
  },
  {
    id: "invalid_scanner_index",
    category: "secrets",
    input: document(inert()),
    scannerMode: "invalid_index",
    expected: { kind: "state", status: "error", code: "invalid_result" },
  },
];

const counts = () => ({
  factDenominator: 0,
  expectedPositive: 0,
  expectedNegative: 0,
  assertedTP: 0,
  assertedTN: 0,
  assertedFP: 0,
  assertedFN: 0,
  stateCases: 0,
  failed: 0,
  unsupported: 0,
  partial: 0,
  assertionFailures: 0,
});
const byCategory = Object.fromEntries(
  categories.map((category) => [category, counts()]),
);
const cleanScanner = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};
const results = [];
for (const sample of samples) {
  const bytes = Buffer.from(sample.raw ?? JSON.stringify(sample.input));
  let scanner = cleanScanner;
  if (sample.scannerMode === "mapped_candidate") {
    // Mapping an explicitly chosen fixture field is not a native secret scan.
    const field = createContext(bytes).fields.find(
      ({ kind, value }) =>
        kind === "value" && value === "synthetic-scanner-marker",
    );
    assert.ok(field, "declared scanner fixture field missing");
    scanner = {
      ...cleanScanner,
      findings: [{ fieldIndex: field.index, ruleId: "generic-api-key" }],
    };
  } else if (sample.scannerMode === "unavailable") {
    scanner = { ...cleanScanner, status: "error", reason: "tool_unavailable" };
  } else if (sample.scannerMode === "invalid_index") {
    scanner = {
      ...cleanScanner,
      findings: [{ fieldIndex: 99999, ruleId: "generic-api-key" }],
    };
  }
  const report = staticReportSchema.parse(analyzeStatic(bytes, scanner));
  const rule =
    report.status !== "error"
      ? report.rules.find(({ category }) => category === sample.category)
      : undefined;
  const targetFindings =
    rule?.findings.filter(({ evidence }) =>
      evidence.some(({ code }) => code === sample.expected.code),
    ) ?? [];
  const observed = targetFindings.length > 0;
  const diagnostics = rule?.diagnostics.map(({ code }) => code) ?? [];
  const coverage = Object.fromEntries(
    ["checked", "partial", "unsupported", "not_applicable"].map((status) => [
      status,
      rule?.coverage.filter((scope) => scope.status === status).length ?? 0,
    ]),
  );
  const tally = sample.category ? byCategory[sample.category] : undefined;
  const mismatches = [];
  if (report.execution !== "not_run")
    mismatches.push("unexpected_execution_state");
  if (report.inputSha256 !== hash(bytes))
    mismatches.push("input_hash_mismatch");
  if (tally) {
    tally.failed += Number(report.status === "error");
    tally.unsupported += Number(coverage.unsupported > 0);
    tally.partial += Number(coverage.partial > 0);
  }
  if (sample.expected.kind === "fact") {
    tally.factDenominator += 1;
    tally[sample.expected.present ? "expectedPositive" : "expectedNegative"] +=
      1;
    if (report.status === "error") mismatches.push("fact_case_analysis_failed");
    else {
      tally[
        sample.expected.present
          ? observed
            ? "assertedTP"
            : "assertedFN"
          : observed
            ? "assertedFP"
            : "assertedTN"
      ] += 1;
      if (observed !== sample.expected.present)
        mismatches.push("declared_fact_mismatch");
      if (
        sample.expected.claim &&
        !targetFindings.some(({ claim }) => claim === sample.expected.claim)
      )
        mismatches.push("claim_strength_mismatch");
    }
  } else {
    if (tally) tally.stateCases += 1;
    if (report.status !== sample.expected.status)
      mismatches.push("state_status_mismatch");
    if (
      sample.expected.code &&
      (report.status !== "error" || report.code !== sample.expected.code)
    )
      mismatches.push("state_error_code_mismatch");
    if (
      sample.expected.diagnostic &&
      !diagnostics.includes(sample.expected.diagnostic)
    )
      mismatches.push("state_diagnostic_missing");
    if (sample.expected.coverage && coverage[sample.expected.coverage] === 0)
      mismatches.push("state_coverage_mismatch");
  }
  if (tally) tally.assertionFailures += Number(mismatches.length > 0);
  results.push({
    case: sample.id,
    category: sample.category,
    expected: sample.expected,
    inputSha256: hash(bytes),
    reportSha256: hash(JSON.stringify(report)),
    scanner: "controlled_fixture",
    scannerMode: sample.scannerMode ?? "completed_empty",
    status: report.status,
    ...(report.status === "error" ? { code: report.code } : {}),
    targetFactObserved: observed,
    targetClaims: [...new Set(targetFindings.map(({ claim }) => claim))],
    coverage,
    diagnosticCodes: diagnostics,
    passed: mismatches.length === 0,
    mismatches,
  });
}

const factCases = results.filter(({ expected }) => expected.kind === "fact");
const output = {
  corpusVersion: "1.0.0",
  generatedAt: new Date().toISOString(),
  nodeVersion: process.version,
  ...staticResultVersions,
  scope: "synthetic_declared_rule_facts_only",
  scanner: "controlled_fixture",
  workflowExecution: "not_run",
  nativeScannerAccuracyMeasured: false,
  publicTemplateAccuracy: "unknown",
  realApiIntegration: "not_run",
  command: "node validation/verify-static-corpus.mjs [report path]",
  corpusDefinitionSha256: hash(JSON.stringify(samples)),
  scriptSha256: hash(await readFile(fileURLToPath(import.meta.url))),
  metricDefinition: {
    denominator:
      "One predeclared presence/absence assertion for one evidence code in one category per fact case; state cases excluded.",
    positive:
      "The selected declared configuration, capability or candidate pattern is present; not an exploitable vulnerability label.",
    negative:
      "The selected declared pattern is absent; not a clean-file or safety label. Other patterns may be present.",
    TP_TN_FP_FN:
      "Compare that predeclared fact with the selected evidence code only. Claim strength is asserted separately.",
    failed:
      "Target-category cases whose analyzer report is error, including expected rejection cases; not assertionFailures.",
    unsupported:
      "Target-category cases with at least one unsupported coverage row; can overlap a correctly observed capability fact.",
    partial:
      "Target-category cases with at least one partial coverage row; can overlap a fact or unsupported scope.",
    scanner:
      "Sanitized fixture reports exercise rule composition and mapping only; no native Gitleaks process runs here.",
  },
  evidenceSeparation: {
    nativeTools:
      "static-tool-results.json: separate 7-case native/tool-boundary evidence",
    legacySqlCorpus:
      "Existing 12-case SQL corpus is unchanged and has its own denominator.",
    publicTemplates:
      "The separate 5-template smoke run has unknown accuracy and contributes no TP/FP/FN labels here.",
  },
  summary: {
    cases: results.length,
    factDenominator: factCases.length,
    stateCases: results.length - factCases.length,
    assertedTP: Object.values(byCategory).reduce(
      (sum, item) => sum + item.assertedTP,
      0,
    ),
    assertedTN: Object.values(byCategory).reduce(
      (sum, item) => sum + item.assertedTN,
      0,
    ),
    assertedFP: Object.values(byCategory).reduce(
      (sum, item) => sum + item.assertedFP,
      0,
    ),
    assertedFN: Object.values(byCategory).reduce(
      (sum, item) => sum + item.assertedFN,
      0,
    ),
    analysisErrors: results.filter(({ status }) => status === "error").length,
    unsupportedTargetCases: results.filter(
      ({ coverage }) => coverage.unsupported > 0,
    ).length,
    partialTargetCases: results.filter(({ coverage }) => coverage.partial > 0)
      .length,
    passed: results.filter(({ passed }) => passed).length,
    assertionFailures: results.filter(({ passed }) => !passed).length,
  },
  byCategory,
  results,
};
const outputPath = resolve(
  process.argv[2] ?? "evidence-local/static-corpus-results.json",
);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, JSON.stringify(output, null, 2) + "\n");
console.log(JSON.stringify(output.summary));
assert.equal(
  output.summary.assertionFailures,
  0,
  "Static corpus assertions failed; inspect sanitized result artifact",
);
assert.ok(
  categories.every(
    (category) =>
      byCategory[category].expectedPositive > 0 &&
      byCategory[category].expectedNegative > 0,
  ),
);
