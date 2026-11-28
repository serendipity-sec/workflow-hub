import { createHash } from "node:crypto";
import { assessmentReportSchema } from "../contracts/assessment-contract.js";
import { createLlmContext, llmReviewSchema } from "./llm-review.js";
import type { RuleResult } from "../contracts/static-contract.js";

import { causeKinds, classifyCoverageCause } from "./coverage-policy.js";
import type { Cause, CauseKind } from "./coverage-policy.js";
export { causeKinds, classifyCoverageCause } from "./coverage-policy.js";

export const coverageExplanationLimits = {
  reasonCodes: 256,
  referencesPerCode: 4,
} as const;
const digest = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
type Reference = {
  analysisKey: string;
  fileSha256: string;
  ruleId: string;
  diagnosticId: string;
  nodeIndex: number | null;
  coverageStatuses: string[];
};
type Reason = Cause & {
  code: string;
  occurrences: number;
  limitedOccurrences: number;
  referenceExamples: Reference[];
  omittedReferences: number;
};

/** Classification of work still needed, never a replacement security verdict. */
export function buildCoverageExplanation(input: unknown, llmInput?: unknown) {
  const report = assessmentReportSchema.parse(input);
  const counts = Object.fromEntries(
    causeKinds.map((kind) => [kind, 0]),
  ) as Record<CauseKind, number>;
  const coverageCounts = {
    checked: 0,
    partial: 0,
    unsupported: 0,
    not_applicable: 0,
  };
  const reasons = new Map<string, Reason>();
  const selected: {
    referenceId: string;
    code: string;
    causeKind: CauseKind;
    nextStep: string;
    reference: Reference;
  }[] = [];
  const llm =
    llmInput === undefined ? undefined : llmReviewSchema.parse(llmInput);
  if (
    llm &&
    (llm.inputSha256 !== report.inputSha256 ||
      JSON.stringify(llm.context) !== JSON.stringify(createLlmContext(report)))
  )
    throw new Error("LLM review is not bound to this assessment");
  const focus =
    llm?.status === "generated" ? llm.selection.focusReferenceIds : [];
  let diagnosticOccurrences = 0;
  let scopeNoteOccurrences = 0;
  let toolFailures = 0;
  let fileFailures = 0;
  if (report.status !== "error")
    for (const file of report.files) {
      toolFailures +=
        Number(file.tools.gitleaks.status === "error") +
        file.tools.native.modes.filter((mode) => mode.status === "error")
          .length;
      fileFailures += Number(file.base.status === "error");
      const rules: RuleResult[] = [
        ...(file.base.status === "error" ? [] : file.base.rules),
        ...file.extensionRules,
      ];
      for (const rule of rules) {
        for (const coverage of rule.coverage) coverageCounts[coverage.status]++;
        for (const diagnostic of rule.diagnostics) {
          const cause = classifyCoverageCause(diagnostic.code);
          counts[cause.kind]++;
          diagnosticOccurrences++;
          if (cause.scopeOnly) scopeNoteOccurrences++;
          const statuses = [
            ...new Set(
              rule.coverage
                .filter((entry) => entry.diagnosticIds.includes(diagnostic.id))
                .map((entry) => entry.status),
            ),
          ].sort();
          const reference: Reference = {
            analysisKey: file.analysisKey,
            fileSha256: file.inputSha256,
            ruleId: rule.ruleId,
            diagnosticId: diagnostic.id,
            nodeIndex: /^\/nodes\/(\d+)(?:\/|$)/.test(
              diagnostic.location.pointer,
            )
              ? Number(/^\/nodes\/(\d+)/.exec(diagnostic.location.pointer)![1])
              : null,
            coverageStatuses: statuses,
          };
          const reason = reasons.get(diagnostic.code) ?? {
            ...cause,
            code: diagnostic.code,
            occurrences: 0,
            limitedOccurrences: 0,
            referenceExamples: [],
            omittedReferences: 0,
          };
          reason.occurrences++;
          if (statuses.includes("partial") || statuses.includes("unsupported"))
            reason.limitedOccurrences++;
          if (
            reason.referenceExamples.length <
            coverageExplanationLimits.referencesPerCode
          )
            reason.referenceExamples.push(reference);
          else reason.omittedReferences++;
          reasons.set(diagnostic.code, reason);
          for (const ref of llm?.context.references ?? [])
            if (
              focus.includes(ref.id) &&
              ref.analysisKey === file.analysisKey &&
              ref.fileSha256 === file.inputSha256 &&
              ref.evidenceIds.includes(diagnostic.id)
            )
              selected.push({
                referenceId: ref.id,
                code: diagnostic.code,
                causeKind: cause.kind,
                nextStep: cause.nextStep,
                reference,
              });
        }
      }
    }
  const orderedReasons = [...reasons.values()].sort(
    (a, b) => b.occurrences - a.occurrences || a.code.localeCompare(b.code),
  );
  const omittedReasons = orderedReasons.slice(
    coverageExplanationLimits.reasonCodes,
  );
  return {
    coverageExplanationVersion: "1.0.0" as const,
    inputSha256: report.inputSha256,
    assessmentSha256: digest(report),
    engineVersion: report.engineVersion,
    assessmentStatus: report.status,
    decision: report.status === "error" ? "inconclusive" : report.decision,
    workflowExecution: "not_run" as const,
    meaning: "diagnostic_occurrences_not_vulnerabilities" as const,
    verdictChanged: false as const,
    error: report.status === "error" ? report.code : null,
    fileFailures,
    toolFailures,
    diagnosticOccurrences,
    scopeNoteOccurrences,
    counts,
    coverageCounts,
    reasons: orderedReasons.slice(0, coverageExplanationLimits.reasonCodes),
    omittedReasonCodes: omittedReasons.length,
    omittedReasonOccurrences: omittedReasons.reduce(
      (n, reason) => n + reason.occurrences,
      0,
    ),
    truncated: omittedReasons.length > 0,
    llmAssistance: {
      status: llm?.status ?? "not_requested",
      authority: "review_priority_only" as const,
      selectedDiagnosticActions: selected,
      analysisGapResolved: false as const,
    },
  };
}
