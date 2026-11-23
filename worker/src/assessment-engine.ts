import { z } from "zod";
import { analyzeStatic, scannerResultSchema } from "./static-engine.js";
import { buildValueFlow } from "./value-flow.js";
import type { SourceAnnotation, ValueFlow } from "./value-flow.js";
import { analyzeExtendedSinks } from "./extended-sinks.js";
import { analyzeAdvancedRisks } from "./advanced-risks.js";
import { analyzeDefinitionRisks } from "./definition-risks.js";
import { analyzeAiFlow } from "./ai-flow.js";
import {
  analyzeNativeInspection,
  nativeInspectionResultSchema,
} from "./native-inspection.js";
import {
  assessDependencies,
  assessEnvironment,
} from "./assessment-environment.js";
import {
  parseEvidenceBytes,
  evidenceSummary,
  AssessmentEvidenceError,
} from "./assessment-evidence.js";
import { evaluatePolicy } from "./assessment-policy.js";
import { createRemediationPlans } from "./assessment-change.js";
import {
  planSubworkflows,
  evidenceForInput,
} from "./assessment-subworkflows.js";
import {
  assessmentError,
  assessmentReportSchema,
} from "./assessment-contract.js";
import type {
  AssessmentReport,
  FileAssessment,
  SubworkflowLink,
} from "./assessment-contract.js";
import { locationFor, reportStatus, stableId } from "./static-contract.js";
import type { RuleResult } from "./static-contract.js";
import type { Context } from "./static-context.js";
import type { GitleaksResult } from "./gitleaks.js";
import type { NativeInspectionResult } from "./native-inspection.js";
import { sha256 } from "./worker-io.js";
import { WorkflowError } from "./n8n.js";
import { summarizeFunction, presentFindings } from "./assessment-summary.js";

export interface AssessmentEngineOptions {
  evidenceBytes?: Buffer;
  collectTools(
    context: Context,
  ): Promise<{ gitleaks: GitleaksResult; native: NativeInspectionResult }>;
  signal?: AbortSignal;
  now?: string;
}

function flowCoverage(context: Context, flow: ValueFlow): RuleResult {
  const ruleId = "N8N_VALUE_FLOW_COVERAGE";
  const diagnostics = [
    ...new Map(
      flow.diagnostics.map(({ nodeKey, code }) => {
        const node = context.nodeByKey.get(nodeKey);
        const location = node
          ? locationFor(node, "/parameters")
          : { nodeKey: null, pointer: "" };
        const id = stableId(ruleId, location, code);
        return [id, { id, code, location }] as const;
      }),
    ).values(),
  ];
  return {
    ruleId,
    category: "egress",
    profileVersion: "1.5.0",
    findings: [],
    diagnostics,
    coverage: diagnostics.length
      ? diagnostics.map((diagnostic) => ({
          location: diagnostic.location,
          status: "partial",
          findingIds: [],
          diagnosticIds: [diagnostic.id],
        }))
      : [
          {
            location: { nodeKey: null, pointer: "" },
            status: "not_applicable",
            findingIds: [],
            diagnosticIds: [],
          },
        ],
  };
}
function subworkflowCoverage(links: SubworkflowLink[]): RuleResult {
  const ruleId = "N8N_SUBWORKFLOW_DEFINITIONS";
  const diagnostics = links
    .filter((link) => link.status !== "disabled")
    .flatMap((link) =>
      link.codes.map((code) => ({
        id: stableId(ruleId, link.caller, code),
        code,
        location: link.caller,
      })),
    );
  return {
    ruleId,
    category: "dependencies",
    profileVersion: "1.0.0",
    findings: [],
    diagnostics,
    coverage: links.length
      ? links.map((link) => ({
          location: link.caller,
          status: link.status === "disabled" ? "not_applicable" : "partial",
          findingIds: [],
          diagnosticIds: diagnostics
            .filter((item) => item.location.nodeKey === link.caller.nodeKey)
            .map((item) => item.id),
        }))
      : [
          {
            location: { nodeKey: null, pointer: "" },
            status: "not_applicable",
            findingIds: [],
            diagnosticIds: [],
          },
        ],
  };
}

/** Library entry; production uses the OS-isolated controller, never this directly. */
export async function assessBytes(
  bytes: Buffer,
  options: AssessmentEngineOptions,
): Promise<AssessmentReport> {
  const inputSha256 = sha256(bytes);
  try {
    if (options.signal?.aborted)
      return assessmentError(inputSha256, "cancelled");
    const now = z.iso.datetime().parse(options.now ?? new Date().toISOString());
    const evidence = options.evidenceBytes
      ? parseEvidenceBytes(options.evidenceBytes, inputSha256)
      : undefined;
    const { inputs, links } = planSubworkflows(bytes, evidence);
    const files: FileAssessment[] = [];
    for (const input of inputs) {
      if (options.signal?.aborted)
        return assessmentError(inputSha256, "cancelled");
      const supplied = await options.collectTools(input.context);
      const tools = {
        gitleaks: scannerResultSchema.parse(supplied.gitleaks),
        native: nativeInspectionResultSchema.parse(supplied.native),
      };
      const localEvidence = evidenceForInput(input, evidence);
      const sourceAnnotations: SourceAnnotation[] =
        localEvidence?.classifications.flatMap((item) =>
          item.dataClass === "secret" ||
          item.dataClass === "personal" ||
          item.dataClass === "public"
            ? [
                {
                  nodeKey: item.nodeKey,
                  fieldPath: item.field,
                  sensitivity:
                    item.dataClass === "secret"
                      ? ("secret_candidate" as const)
                      : item.dataClass === "personal"
                        ? ("pii_candidate" as const)
                        : ("public_literal" as const),
                  provenance: "operator" as const,
                },
              ]
            : [],
        ) ?? [];
      const flow = buildValueFlow(input.context, { sourceAnnotations });
      // A terminal Code node can leak or execute data even when nobody reads
      // its return value. Analyze every active JS body before consumers spend
      // the shared budget; the bounded interpreter never executes the source.
      for (const node of input.context.nodes)
        if (
          !node.disabled &&
          node.type === "n8n-nodes-base.code" &&
          [1, 2].includes(node.typeVersion) &&
          (node.parameters.language ?? "javaScript") === "javaScript"
        )
          flow.output(node.key, "");
      const base = analyzeStatic(input.bytes, tools.gitleaks);
      const extensionRules = [
        ...analyzeExtendedSinks(input.context, flow, localEvidence),
        ...analyzeAdvancedRisks(input.context, flow),
        ...analyzeDefinitionRisks(input.context, flow),
        ...analyzeAiFlow(input.context, flow, localEvidence),
        ...analyzeNativeInspection(input.context, tools.native),
        ...assessEnvironment(input.context, localEvidence),
        subworkflowCoverage(
          links.filter((link) => link.parentAnalysisKey === input.analysisKey),
        ),
        flowCoverage(input.context, flow),
      ];
      const findings = [
        ...(base.status === "error" ? [] : base.rules),
        ...extensionRules,
      ].flatMap((rule) => rule.findings);
      files.push({
        analysisKey: input.analysisKey,
        inputSha256: input.inputSha256,
        depth: input.depth,
        parentAnalysisKey: input.parentAnalysisKey,
        caller: input.caller,
        functionSummary: summarizeFunction(input.context),
        findingPresentation: presentFindings(findings),
        base,
        extensionRules,
        tools,
        evidence: evidenceSummary(localEvidence),
        dependencies: assessDependencies(input.context, localEvidence),
        policy: evaluatePolicy(base, extensionRules, localEvidence, now),
        remediation: createRemediationPlans(
          input.context,
          findings,
          input.inputSha256,
        ),
      });
    }
    const decisions = files.map((file) => file.policy.decision);
    const incomplete =
      links.some(
        (link) => !["definition_analyzed", "disabled"].includes(link.status),
      ) || files.some((file) => file.base.status === "error");
    const decision = decisions.includes("block")
      ? "block"
      : incomplete || decisions.includes("inconclusive")
        ? "inconclusive"
        : decisions.includes("review")
          ? "review"
          : "allow";
    const status = incomplete
      ? "partial"
      : reportStatus(
          files.flatMap((file) => [
            ...(file.base.status === "error" ? [] : file.base.rules),
            ...file.extensionRules,
          ]),
        );
    const report = {
      assessmentVersion: "1.0.0",
      engineVersion: "0.9.0",
      inputSha256,
      execution: "not_run",
      boundary: { kind: "caller_managed", isolationVerified: false },
      status,
      files,
      subworkflows: links,
      decision,
      publication: "requires_service_authorization",
    };
    const validated = assessmentReportSchema.safeParse(report);
    return validated.success
      ? validated.data
      : assessmentError(inputSha256, "invalid_result");
  } catch (error) {
    if (error instanceof AssessmentEvidenceError)
      return assessmentError(
        inputSha256,
        error.code === "evidence_input_mismatch" ||
          error.code === "evidence_limit"
          ? error.code
          : "invalid_evidence",
      );
    const failure = assessmentError(
      inputSha256,
      error instanceof WorkflowError ? "invalid_input" : "assessment_failed",
    );
    if (error instanceof WorkflowError && failure.status === "error") {
      failure.inputDiagnosis = {
        code: error.code,
        pointer:
          error.pointer &&
          /^\/(?:nodes(?:\/(?:0|[1-9][0-9]*))?|connections)$/.test(
            error.pointer,
          )
            ? error.pointer
            : null,
      };
    }
    return failure;
  }
}
