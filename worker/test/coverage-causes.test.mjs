import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { assessBytes } from "../dist/assessment-engine.js";
import { assessmentReportSchema } from "../dist/assessment-contract.js";
import {
  buildCoverageExplanation,
  classifyCoverageCause,
} from "../dist/coverage-causes.js";
import { reviewWithLlm, llmDefaults } from "../dist/llm-review.js";

const node = (name, type, typeVersion = 1, parameters = {}) => ({
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const assess = (...nodes) =>
  assessBytes(Buffer.from(JSON.stringify({ nodes, connections: {} })), {
    now: "2026-11-23T00:00:00.000Z",
    collectTools: async () => ({
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
    }),
  });

test("environment proof, omitted definitions, implementation and accepted scope remain distinct", () => {
  for (const code of [
    "runtime_evidence_missing",
    "dns_redirect_and_network_access_unverified",
    "installed_package_version_and_content_missing",
    "automatic_mapping_selection_unverified",
  ])
    assert.equal(classifyCoverageCause(code).kind, "environment_evidence");
  for (const code of [
    "subworkflow_definition_not_supplied",
    "ai_required_model_connection_missing",
    "binary_payload_unavailable",
  ])
    assert.equal(classifyCoverageCause(code).kind, "definition_input");
  for (const code of [
    "opaque_node_effects",
    "code_object_mutation_unresolved",
    "nonstandard_execution_semantics",
    "flow_budget_exceeded",
  ])
    assert.equal(classifyCoverageCause(code).kind, "analyzer_extension");
  for (const code of [
    "field_projection_partial",
    "payload_provenance_unresolved",
    "code_parse_unavailable",
    "expression_syntax_unsupported",
    "trusted_policy_transfer_unresolved",
    "ai_model_transfer_policy_unresolved",
  ])
    assert.equal(classifyCoverageCause(code).kind, "mixed_provenance");
  assert.equal(
    classifyCoverageCause("nlp_english_model_profile").scopeOnly,
    true,
  );
  assert.equal(
    classifyCoverageCause("code_bounded_flow_partial").scopeOnly,
    true,
  );
  assert.equal(
    classifyCoverageCause("model_attack_resistance_and_value_flow_unverified")
      .scopeOnly,
    false,
  );
  assert.equal(
    classifyCoverageCause("future_unknown_diagnostic").kind,
    "unclassified",
  );
});

test("all diagnostic occurrences survive card limits and original partial is unchanged", async () => {
  const report = await assess(
    ...Array.from({ length: 30 }, (_, index) =>
      node(`Private${index}`, "httpRequest", 4.2, {
        url: "https://private.example.invalid",
        options: {},
      }),
    ),
  );
  const before = JSON.stringify(report);
  const explanation = buildCoverageExplanation(report);
  const rules = report.files.flatMap((file) => [
    ...file.base.rules,
    ...file.extensionRules,
  ]);
  assert.equal(
    explanation.diagnosticOccurrences,
    rules.flatMap((rule) => rule.diagnostics).length,
  );
  assert.equal(
    Object.values(explanation.counts).reduce((a, b) => a + b, 0),
    explanation.diagnosticOccurrences,
  );
  assert.equal(
    explanation.reasons.reduce((n, r) => n + r.occurrences, 0),
    explanation.diagnosticOccurrences,
  );
  assert.ok(explanation.reasons.some((reason) => reason.omittedReferences > 0));
  for (const reason of explanation.reasons) {
    assert.equal(
      reason.referenceExamples.length + reason.omittedReferences,
      reason.occurrences,
    );
    for (const ref of reason.referenceExamples) {
      const file = report.files.find(
        (file) => file.analysisKey === ref.analysisKey,
      );
      const rule = [...file.base.rules, ...file.extensionRules].find(
        (rule) => rule.ruleId === ref.ruleId,
      );
      assert.ok(
        rule.diagnostics.some(
          (d) => d.id === ref.diagnosticId && d.code === reason.code,
        ),
      );
    }
  }
  assert.equal(explanation.assessmentStatus, "partial");
  assert.equal(explanation.decision, report.decision);
  assert.equal(explanation.verdictChanged, false);
  assert.equal(JSON.stringify(report), before);
  assert.ok(!JSON.stringify(explanation).includes("private.example.invalid"));
  assert.ok(!JSON.stringify(explanation).includes("Private0"));
});

test("a future diagnostic is retained as unclassified, never silently treated as environment", async () => {
  const report = await assess(node("Start", "manualTrigger"));
  const rule = report.files[0].extensionRules.find(
    (rule) => rule.diagnostics.length,
  );
  rule.diagnostics[0].code = "future_unknown_diagnostic";
  assessmentReportSchema.parse(report);
  const result = buildCoverageExplanation(report);
  assert.equal(result.counts.unclassified, 1);
  assert.ok(
    result.reasons.some(
      (reason) => reason.code === "future_unknown_diagnostic",
    ),
  );
});

test("failed scans have a failure cause, not an empty successful classification", async () => {
  const report = await assessBytes(Buffer.from("invalid"), {
    collectTools: async () => {
      throw new Error("must not run");
    },
  });
  const result = buildCoverageExplanation(report);
  assert.equal(result.assessmentStatus, "error");
  assert.equal(result.error, "invalid_input");
  assert.equal(result.decision, "inconclusive");
});

test("large imported diagnostic vocabularies have bounded details while preserving full counts", async () => {
  const report = await assess(node("Start", "manualTrigger"));
  const rules = report.files[0].base.rules
    .filter((rule) => rule.findings.length === 0)
    .slice(0, 2);
  for (const [r, rule] of rules.entries()) {
    const location = rule.coverage[0].location;
    rule.diagnostics = Array.from({ length: 150 }, (_, index) => ({
      id: createHash("sha256").update(`${r}:${index}`).digest("hex"),
      code: `future_${r}_${index}`,
      location,
    }));
    rule.coverage = [
      {
        location,
        status: "partial",
        findingIds: [],
        diagnosticIds: rule.diagnostics.map((d) => d.id),
      },
    ];
  }
  report.files[0].base.status = "partial";
  assessmentReportSchema.parse(report);
  const result = buildCoverageExplanation(report);
  assert.equal(result.reasons.length, 256);
  assert.ok(result.truncated && result.omittedReasonCodes > 0);
  assert.equal(result.counts.unclassified, 300);
  assert.equal(
    result.reasons.reduce((n, reason) => n + reason.occurrences, 0) +
      result.omittedReasonOccurrences,
    result.diagnosticOccurrences,
  );
  assert.equal(result.assessmentStatus, report.status);
});

test("LLM selected references get grounded actions without resolving a gap, and stale context is rejected", async () => {
  const report = await assess(node("Start", "manualTrigger"));
  const llm = await reviewWithLlm(report, {
    enabled: true,
    apiKey: "synthetic-test-key",
    fetch: async (_url, options) => {
      const payload = JSON.parse(options.body);
      const context = JSON.parse(payload.messages[1].content);
      const ref = context.references.find((ref) => ref.kind !== "finding");
      return new Response(
        JSON.stringify({
          model: llmDefaults.model,
          choices: [
            {
              finish_reason: "stop",
              message: {
                content: JSON.stringify({ focusReferenceIds: [ref.id] }),
              },
            },
          ],
        }),
      );
    },
  });
  assert.equal(llm.status, "generated");
  const result = buildCoverageExplanation(report, llm);
  assert.equal(result.llmAssistance.selectedDiagnosticActions.length, 1);
  assert.equal(
    result.llmAssistance.selectedDiagnosticActions[0].causeKind,
    "environment_evidence",
  );
  assert.equal(result.llmAssistance.analysisGapResolved, false);
  assert.equal(result.assessmentStatus, report.status);
  const other = await assess(node("Other", "manualTrigger"));
  assert.throws(() => buildCoverageExplanation(other, llm), /not bound/);
});
