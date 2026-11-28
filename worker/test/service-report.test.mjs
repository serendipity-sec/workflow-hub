import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { assessBytes } from "../dist/assessment/assessment-engine.js";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { presentFindings } from "../dist/assessment/assessment-summary.js";
import {
  buildServiceReport,
  serviceReportSchema,
  serviceReportLimits,
} from "../dist/service/service-report.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const bytes = (value) => Buffer.from(JSON.stringify(value));
const node = (name, type, typeVersion = 1, parameters = {}) => ({
  id: name,
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const doc = (...nodes) => ({ nodes, connections: {} });
// These are unit fixtures; the parent integration runs real native tool checks.
const mockTools = async () => ({
  gitleaks: {
    tool: "gitleaks",
    version: "8.30.1",
    status: "completed",
    findings: [],
  },
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
const assess = (workflow, extra = {}) =>
  assessBytes(bytes(workflow), {
    collectTools: mockTools,
    now: "2026-11-23T00:00:00.000Z",
    ...extra,
  });

test("service report preserves partial and separates environment evidence from analysis gaps", async () => {
  const report = await assess(doc(node("Start", "manualTrigger")));
  const before = JSON.stringify(report);
  const service = buildServiceReport(report);
  assert.equal(service.assessmentStatus, report.status);
  assert.equal(service.analysisStatus, "complete");
  assert.equal(service.serviceScope.environmentInput, "not_requested");
  assert.equal(service.executionStatus, "completed");
  assert.equal(service.decision, report.decision);
  assert.equal(service.publication, "requires_service_authorization");
  assert.equal(service.vulnerabilityCount, "not_established");
  assert.ok(
    service.environmentChecks.some(
      (item) => item.code === "runtime_evidence_missing",
    ),
  );
  assert.ok(
    !service.analysisGaps.some(
      (item) => item.code === "runtime_evidence_missing",
    ),
  );
  assert.equal(JSON.stringify(report), before);
});

test("risk candidates and observations remain separate and retain exact file and evidence links", async () => {
  const report = await assess(
    doc(
      node("PRIVATE_NAME", "webhook", 2.1, { authentication: "none" }),
      node("PRIVATE_RECIPIENT", "httpRequest", 4.2, {
        url: "https://private.example.invalid",
        options: { allowUnauthorizedCerts: true },
      }),
    ),
  );
  const service = buildServiceReport(report);
  assert.ok(service.findings.length > 0);
  assert.ok(service.observations.length > 0);
  assert.ok(service.findings.every((item) => item.severity !== "info"));
  assert.ok(
    service.observations.every(
      (item) => item.severity === "info" && item.remediation.length === 0,
    ),
  );
  const tls = service.findings.find((item) =>
    item.evidence.some((evidence) =>
      evidence.explanation.includes("인증서 검증을 끄는"),
    ),
  );
  assert.ok(tls);
  assert.equal(tls.reference.inputSha256, report.inputSha256);
  assert.equal(tls.reference.analysisKey, report.files[0].analysisKey);
  assert.ok(
    report.files[0].base.rules
      .flatMap((rule) => rule.findings)
      .some((finding) => finding.id === tls.reference.id),
  );
  assert.ok(
    tls.remediation.some(
      (plan) =>
        plan.automatic &&
        plan.requiresRecheck &&
        plan.behaviorPreserved === "not_verified",
    ),
  );
  for (const secret of [
    "PRIVATE_NAME",
    "PRIVATE_RECIPIENT",
    "private.example.invalid",
  ])
    assert.ok(!JSON.stringify(service).includes(secret));
});

test("unknown diagnostic text and arbitrary field names cannot enter the user or LLM explanation", async () => {
  const report = await assess(doc(node("Start", "manualTrigger")));
  const rule = report.files[0].extensionRules.find(
    (item) => item.ruleId === "CONTEXT_RUNTIME_EVIDENCE",
  );
  const diagnostic = rule.diagnostics[0];
  diagnostic.code = "private_account_token_should_not_echo";
  diagnostic.location.pointer =
    "/settings/private_account_name_should_not_echo";
  assert.ok(assessmentReportSchema.safeParse(report).success);
  const service = buildServiceReport(report);
  const unknown = service.analysisGaps.find(
    (item) => item.reference.id === diagnostic.id,
  );
  assert.equal(unknown.code, "unrecognized_diagnostic");
  assert.equal(unknown.location.pointer, "/settings");
  assert.equal(service.staticCoverageStatus, "gaps_present");
  assert.ok(!JSON.stringify(service).includes("private_account"));
});

test("language scope notes remain visible without being reported as a tool failure or fixed coverage", async () => {
  const result = await mockTools();
  result.native.modes[0].diagnostics.push({
    fieldIndex: null,
    code: "nlp_english_model_profile",
  });
  const report = await assess(doc(node("Start", "manualTrigger")), {
    collectTools: async () => result,
  });
  const service = buildServiceReport(report);
  assert.ok(
    service.scopeNotes.some(
      (item) =>
        item.code === "nlp_english_model_profile" &&
        item.action.includes("한국어"),
    ),
  );
  assert.equal(service.executionStatus, "completed");
  assert.equal(service.assessmentStatus, "partial");
  assert.equal(service.analysisStatus, "complete");
  assert.ok(service.serviceScope.excludedScopeNoticeCount > 0);
});

test("new trigger and collection diagnostics retain their distinct unresolved conditions", async () => {
  const original = await assess(doc(node("Start", "manualTrigger")));
  for (const code of [
    "trigger_payload_schema_unverified",
    "trigger_input_connection_unresolved",
    "service_output_port_unresolved",
    "collection_cardinality_unverified",
    "code_collection_cardinality_unverified",
    "aggregate_options_unresolved",
    "aggregate_fields_unresolved",
    "aggregate_excluded_unknown_fields",
    "aggregate_mode_unresolved",
    "aggregate_dotted_key_resolution_unverified",
    "aggregate_array_property_unresolved",
    "aggregate_flatten_shape_unverified",
  ]) {
    const report = structuredClone(original);
    const rule = report.files[0].extensionRules.find(
      (item) => item.ruleId === "CONTEXT_RUNTIME_EVIDENCE",
    );
    rule.diagnostics[0].code = code;
    const result = buildServiceReport(report);
    const expectedGroup =
      code === "trigger_payload_schema_unverified"
        ? "environmentChecks"
        : "analysisGaps";
    assert.ok(result[expectedGroup].some((card) => card.code === code));
    assert.equal(result.assessmentStatus, "partial");
    assert.equal(
      result.analysisStatus,
      code === "trigger_payload_schema_unverified"
        ? "complete"
        : "review_required",
    );
  }
});

test("tool failure has a dedicated execution state even if an assessment report was produced", async () => {
  const tools = await mockTools();
  tools.gitleaks = {
    ...tools.gitleaks,
    status: "error",
    reason: "tool_unavailable",
  };
  const report = await assess(doc(node("Start", "manualTrigger")), {
    collectTools: async () => tools,
  });
  const service = buildServiceReport(report);
  assert.equal(service.executionStatus, "completed_with_errors");
  assert.equal(service.staticCoverageStatus, "gaps_present");
  assert.ok(
    service.analysisGaps.some((item) => item.code === "inspection_tool_failed"),
  );
  assert.notEqual(service.decision, "allow");
});

test("failed input remains failed and no findings are manufactured", async () => {
  const report = await assessBytes(Buffer.from("{"), {
    collectTools: mockTools,
  });
  const service = buildServiceReport(report);
  assert.equal(service.executionStatus, "failed");
  assert.equal(service.analysisStatus, "failed");
  assert.equal(service.staticCoverageStatus, "not_evaluated");
  assert.equal(service.findings.length, 0);
  assert.equal(service.counts.analysisGaps, 1);
  assert.equal(service.decision, "inconclusive");
});

test("missing child definitions are explicit gaps and analyzed child findings retain the child hash", async () => {
  const missing = await assess(
    doc(
      node("Call", "executeWorkflow", 1.4, {
        source: "database",
        workflowId: "synthetic-child",
      }),
    ),
  );
  const missingService = buildServiceReport(missing);
  assert.ok(
    missingService.analysisGaps.some(
      (item) => item.reference.kind === "subworkflow",
    ),
  );
  const child = doc(
    node("Child HTTP", "httpRequest", 4.2, { url: "http://example.invalid" }),
  );
  const parent = await assess(
    doc(
      node("Call", "executeWorkflow", 1.4, {
        source: "parameter",
        workflowJson: JSON.stringify(child),
      }),
    ),
  );
  assert.equal(parent.files.length, 2);
  const service = buildServiceReport(parent);
  const childFinding = service.findings.find(
    (item) => item.reference.analysisKey === parent.files[1].analysisKey,
  );
  assert.ok(childFinding);
  assert.equal(childFinding.reference.inputSha256, hash(bytes(child)));
  assert.equal(service.functions[1].depth, 1);
});

test("large reports disclose omitted diagnostics while retaining full totals and review-required status", async () => {
  const report = await assess(doc(node("Start", "manualTrigger")));
  for (const [index, rule] of report.files[0].extensionRules
    .slice(0, 2)
    .entries()) {
    rule.diagnostics = Array.from({ length: 256 }, (_, i) => ({
      id: hash(`synthetic-${index}-${i}`),
      code: "code_loop_summary_partial",
      location: { nodeKey: null, pointer: "" },
    }));
    rule.coverage = [
      {
        location: { nodeKey: null, pointer: "" },
        status: "partial",
        findingIds: rule.findings.map((finding) => finding.id),
        diagnosticIds: rule.diagnostics.map((diagnostic) => diagnostic.id),
      },
    ];
  }
  assert.ok(assessmentReportSchema.safeParse(report).success);
  const service = buildServiceReport(report);
  assert.equal(service.analysisGaps.length, serviceReportLimits.itemsPerGroup);
  assert.ok(service.counts.analysisGaps >= 512);
  assert.equal(
    service.omitted.analysisGaps,
    service.counts.analysisGaps - service.analysisGaps.length,
  );
  assert.equal(service.truncated, true);
  assert.equal(service.analysisStatus, "review_required");
  assert.ok(
    Buffer.byteLength(JSON.stringify(service)) <= serviceReportLimits.bytes,
  );
});

test("disabled capabilities are not presented as active workflow behavior", async () => {
  const disabled = {
    ...node("Hidden", "executeCommand", 1, { command: "synthetic" }),
    disabled: true,
  };
  const report = await assess(doc(node("Start", "manualTrigger"), disabled));
  const service = buildServiceReport(report);
  assert.equal(service.functions[0].nodeCount, 2);
  assert.equal(service.functions[0].activeNodeCount, 1);
  assert.deepEqual(service.functions[0].declaredCapabilities, ["수동 시작"]);
  assert.equal(service.functions[0].businessPurpose, "not_verified");
});

test("expanded explanations obey the byte budget without turning valid assessments into failures", async () => {
  const report = await assess(doc(node("Start", "manualTrigger")));
  const file = report.files[0];
  for (const [index, rule] of file.extensionRules.slice(0, 2).entries()) {
    rule.findings = Array.from({ length: 256 }, (_, n) => ({
      id: hash(`large-finding-${index}-${n}`),
      ruleId: rule.ruleId,
      category: rule.category,
      severity: index === 0 ? "medium" : "info",
      claim: "candidate",
      location: { nodeKey: null, pointer: "" },
      evidence: Array.from({ length: 32 }, () => ({
        code: "untranslated_synthetic_evidence",
        location: { nodeKey: null, pointer: "" },
      })),
      assumptions: [],
      remediation: { code: "manual_review", checks: ["recheck"] },
    }));
    rule.coverage = [
      {
        location: { nodeKey: null, pointer: "" },
        status: rule.diagnostics.length ? "partial" : "checked",
        findingIds: rule.findings.map((finding) => finding.id),
        diagnosticIds: rule.diagnostics.map((diagnostic) => diagnostic.id),
      },
    ];
  }
  file.findingPresentation = presentFindings(
    [...file.base.rules, ...file.extensionRules].flatMap(
      (rule) => rule.findings,
    ),
  );
  assert.ok(assessmentReportSchema.safeParse(report).success);
  const service = buildServiceReport(report);
  assert.equal(service.executionStatus, "completed");
  assert.ok(
    Buffer.byteLength(JSON.stringify(service)) <= serviceReportLimits.bytes,
  );
  assert.equal(service.counts.findings, 256);
  assert.ok(service.counts.observations >= 256);
  assert.ok(service.truncated);
  assert.ok(service.omitted.observations > 0);
});

test("input and output schema reject status, count, and extra-field tampering", async () => {
  const report = await assess(doc(node("Start", "manualTrigger")));
  assert.throws(() => buildServiceReport({ ...report, status: "analyzed" }));
  const service = buildServiceReport(report);
  assert.equal(
    serviceReportSchema.safeParse({
      ...service,
      analysisStatus: "review_required",
    }).success,
    false,
  );
  assert.equal(
    serviceReportSchema.safeParse({
      ...service,
      counts: { ...service.counts, findings: 123 },
    }).success,
    false,
  );
  assert.equal(
    serviceReportSchema.safeParse({ ...service, safe: true }).success,
    false,
  );
  const wrongFile = structuredClone(service);
  wrongFile.environmentChecks[0].reference.inputSha256 = "0".repeat(64);
  assert.equal(serviceReportSchema.safeParse(wrongFile).success, false);
});
