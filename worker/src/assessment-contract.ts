import { z } from "zod";
import {
  staticLocationSchema,
  staticReportSchema,
  ruleResultSchema,
  reportStatus,
} from "./static-contract.js";
import { evidenceSummarySchema } from "./assessment-evidence.js";
import { dependencyResultsSchema } from "./assessment-environment.js";
import { policyEvaluationSchema } from "./assessment-policy.js";
import { scannerResultSchema } from "./static-engine.js";
import { nativeInspectionResultSchema } from "./native-inspection.js";
import { remediationPlansSchema } from "./assessment-change.js";
import { errorCodes, limits } from "./contract.js";
import {
  functionSummarySchema,
  findingPresentationSchema,
  presentFindings,
} from "./assessment-summary.js";

export const assessmentLimits = {
  inputBytes: 2 * 1024 * 1024,
  resultBytes: 2 * 1024 * 1024,
  timeoutMs: 180_000,
  children: 8,
  depth: 3,
} as const;
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const code = z.string().regex(/^[a-z][a-z0-9_]{0,79}$/);
export const assessmentFailureCodes = [
  "invalid_input",
  "invalid_evidence",
  "evidence_input_mismatch",
  "evidence_limit",
  "invalid_result",
  "assessment_failed",
  "assessment_timeout",
  "assessment_output_limit",
  "sandbox_unavailable",
  "sandbox_failed",
  "sandbox_cleanup_failed",
  "invalid_configuration",
  "cancelled",
] as const;
export type AssessmentFailureCode = (typeof assessmentFailureCodes)[number];
export const assessmentBoundarySchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("caller_managed"),
    isolationVerified: z.literal(false),
  }),
  z.strictObject({
    kind: z.literal("docker"),
    isolationVerified: z.literal(true),
    imageSha256: hash,
    network: z.literal("none"),
    readOnlyRoot: z.literal(true),
    uid: z.literal(65532),
    memoryMiB: z.literal(1024),
    pids: z.literal(96),
    cpus: z.literal(1),
  }),
]);
export type AssessmentBoundary = z.infer<typeof assessmentBoundarySchema>;
export const legacyAssessmentExtensionRules = [
  "N8N_EXTENDED_OUTBOUND_DATA",
  "N8N_EXTENDED_OUTPUT_DATA",
  "N8N_ADVANCED_SQL",
  "N8N_ADVANCED_EXECUTION",
  "PRESIDIO_PII_CANDIDATES",
  "PYTHON_STATIC_CAPABILITIES",
  "PYTHON_STATIC_OUTPUT",
  "CONTEXT_PACKAGE_ADVISORIES",
  "CONTEXT_RUNTIME_EVIDENCE",
  "CONTEXT_AI_APPROVAL_BOUNDARY",
  "CONTEXT_SYNTHETIC_RECEIPTS",
  "N8N_SUBWORKFLOW_DEFINITIONS",
  "N8N_VALUE_FLOW_COVERAGE",
] as const;
export const assessmentExtensionRules = [
  ...legacyAssessmentExtensionRules,
  "N8N_DATABASE_OPERATIONS",
  "N8N_FILE_OPERATION_PATHS",
  "N8N_MAPPED_HTTP_DESTINATION",
  "N8N_AI_CONNECTION_CONTRACTS",
  "N8N_AI_PROMPT_DATA",
] as const;
export const subworkflowLinkSchema = z.strictObject({
  parentAnalysisKey: hash,
  caller: staticLocationSchema,
  source: z.enum(["supplied_definition", "inline_definition", "unavailable"]),
  status: z.enum([
    "definition_analyzed",
    "unresolved",
    "invalid",
    "limit",
    "cycle",
    "disabled",
  ]),
  childAnalysisKey: hash.nullable(),
  childInputSha256: hash.nullable(),
  codes: z.array(code).min(1).max(8),
});
export const fileAssessmentSchema = z
  .strictObject({
    analysisKey: hash,
    inputSha256: hash,
    depth: z.int().min(0).max(assessmentLimits.depth),
    parentAnalysisKey: hash.nullable(),
    caller: staticLocationSchema.nullable(),
    base: staticReportSchema,
    extensionRules: z.array(ruleResultSchema).max(18),
    evidence: evidenceSummarySchema,
    dependencies: dependencyResultsSchema,
    policy: policyEvaluationSchema,
    tools: z.strictObject({
      gitleaks: scannerResultSchema,
      native: nativeInspectionResultSchema,
    }),
    remediation: remediationPlansSchema,
    functionSummary: functionSummarySchema.optional(),
    findingPresentation: findingPresentationSchema.optional(),
  })
  .refine(
    (file) =>
      file.inputSha256 === file.base.inputSha256 &&
      (file.depth === 0
        ? file.parentAnalysisKey === null && file.caller === null
        : file.parentAnalysisKey !== null && file.caller !== null) &&
      [assessmentExtensionRules, legacyAssessmentExtensionRules].some(
        (expected) =>
          new Set(file.extensionRules.map((rule) => rule.ruleId)).size ===
            expected.length &&
          file.extensionRules.length === expected.length &&
          expected.every((id) =>
            file.extensionRules.some((rule) => rule.ruleId === id),
          ),
      ) &&
      file.tools.native.modes.length === 2 &&
      file.remediation.every((plan) => plan.inputSha256 === file.inputSha256),
  )
  .refine((file) => {
    const rules = [
      ...(file.base.status === "error" ? [] : file.base.rules),
      ...file.extensionRules,
    ];
    const incomplete =
      file.base.status === "error" ||
      reportStatus(rules) !== "analyzed" ||
      file.tools.gitleaks.status === "error" ||
      file.tools.native.modes.some((mode) => mode.status === "error");
    if (file.functionSummary) {
      const inventory = new Map(
        file.functionSummary.nodes.map((node) => [node.nodeKey, node.pointer]),
      );
      const locations = rules.flatMap((rule) => [
        ...rule.coverage.map((entry) => entry.location),
        ...rule.findings.flatMap((finding) => [
          finding.location,
          ...finding.evidence.map((entry) => entry.location),
        ]),
        ...rule.diagnostics.map((entry) => entry.location),
      ]);
      if (
        locations.some(
          (location) =>
            location.nodeKey !== null &&
            (inventory.get(location.nodeKey) === undefined ||
              !(
                location.pointer === inventory.get(location.nodeKey) ||
                location.pointer.startsWith(
                  `${inventory.get(location.nodeKey)}/`,
                )
              )),
        )
      )
        return false;
    }
    if (
      file.findingPresentation &&
      JSON.stringify(file.findingPresentation) !==
        JSON.stringify(presentFindings(rules.flatMap((rule) => rule.findings)))
    )
      return false;
    if (incomplete && file.policy.decision === "allow") return false;
    if (file.policy.status !== "evaluated") return true;
    const findingIds = new Set(
      rules.flatMap((rule) => rule.findings.map((finding) => finding.id)),
    );
    return (
      findingIds.size === file.policy.findingDecisions.length &&
      file.policy.findingDecisions.every((item) =>
        findingIds.has(item.findingId),
      )
    );
  });
const header = {
  assessmentVersion: z.literal("1.0.0"),
  engineVersion: z.enum(["0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0"]),
  inputSha256: hash,
  execution: z.literal("not_run"),
  boundary: assessmentBoundarySchema,
};
export const assessmentReportSchema = z
  .discriminatedUnion("status", [
    z.strictObject({
      ...header,
      status: z.literal("error"),
      code: z.enum(assessmentFailureCodes),
      inputDiagnosis: z
        .strictObject({
          code: z.enum(errorCodes),
          pointer: z
            .string()
            .regex(/^\/(?:nodes(?:\/(?:0|[1-9][0-9]*))?|connections)$/)
            .nullable(),
        })
        .optional(),
    }),
    z.strictObject({
      ...header,
      status: z.enum(["analyzed", "partial", "unsupported"]),
      files: z
        .array(fileAssessmentSchema)
        .min(1)
        .max(assessmentLimits.children + 1),
      subworkflows: z
        .array(subworkflowLinkSchema)
        .max(limits.nodes * (assessmentLimits.children + 1)),
      decision: z.enum(["allow", "review", "block", "inconclusive"]),
      publication: z.literal("requires_service_authorization"),
    }),
  ])
  .refine((report) => {
    if (
      Buffer.byteLength(JSON.stringify(report)) > assessmentLimits.resultBytes
    )
      return false;
    if (report.status === "error")
      return !report.inputDiagnosis || report.code === "invalid_input";
    const expectedRules = ["0.6.0", "0.7.0"].includes(report.engineVersion)
      ? assessmentExtensionRules
      : legacyAssessmentExtensionRules;
    if (
      report.files.some(
        (file) =>
          file.extensionRules.length !== expectedRules.length ||
          expectedRules.some(
            (id) => !file.extensionRules.some((rule) => rule.ruleId === id),
          ),
      )
    )
      return false;
    if (
      report.engineVersion !== "0.3.0" &&
      report.files.some(
        (file) => !file.functionSummary || !file.findingPresentation,
      )
    )
      return false;
    const root = report.files[0];
    const keys = new Set(report.files.map((file) => file.analysisKey));
    const incomplete =
      report.subworkflows.some(
        (link) => !["definition_analyzed", "disabled"].includes(link.status),
      ) || report.files.some((file) => file.base.status === "error");
    const decisions = report.files.map((file) => file.policy.decision);
    const expectedDecision = decisions.includes("block")
      ? "block"
      : incomplete || decisions.includes("inconclusive")
        ? "inconclusive"
        : decisions.includes("review")
          ? "review"
          : "allow";
    const expectedStatus = incomplete
      ? "partial"
      : reportStatus(
          report.files.flatMap((file) => [
            ...(file.base.status === "error" ? [] : file.base.rules),
            ...file.extensionRules,
          ]),
        );
    return (
      root?.inputSha256 === report.inputSha256 &&
      root.depth === 0 &&
      keys.size === report.files.length &&
      report.decision === expectedDecision &&
      report.status === expectedStatus &&
      report.files.slice(1).every((file) => {
        const parent = report.files.find(
          (candidate) => candidate.analysisKey === file.parentAnalysisKey,
        );
        const links = report.subworkflows.filter(
          (link) =>
            link.status === "definition_analyzed" &&
            link.childAnalysisKey === file.analysisKey,
        );
        return (
          parent !== undefined &&
          parent.depth + 1 === file.depth &&
          links.length === 1 &&
          links[0]!.parentAnalysisKey === parent.analysisKey &&
          links[0]!.childInputSha256 === file.inputSha256 &&
          JSON.stringify(links[0]!.caller) === JSON.stringify(file.caller)
        );
      }) &&
      report.subworkflows.every(
        (link) =>
          keys.has(link.parentAnalysisKey) &&
          (link.status === "definition_analyzed"
            ? report.files.some(
                (file) =>
                  file.analysisKey === link.childAnalysisKey &&
                  file.inputSha256 === link.childInputSha256 &&
                  file.parentAnalysisKey === link.parentAnalysisKey &&
                  file.caller?.nodeKey === link.caller.nodeKey,
              )
            : link.childAnalysisKey === null),
      )
    );
  });
export type FileAssessment = z.infer<typeof fileAssessmentSchema>;
export type SubworkflowLink = z.infer<typeof subworkflowLinkSchema>;
export type AssessmentReport = z.infer<typeof assessmentReportSchema>;
export function assessmentError(
  inputSha256: string,
  code: AssessmentFailureCode,
  boundary: AssessmentBoundary = {
    kind: "caller_managed",
    isolationVerified: false,
  },
): AssessmentReport {
  return {
    assessmentVersion: "1.0.0",
    engineVersion: "0.7.0",
    inputSha256,
    execution: "not_run",
    boundary,
    status: "error",
    code,
  };
}
