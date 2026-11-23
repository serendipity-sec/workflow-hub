import { createHash } from "node:crypto";
import { z } from "zod";
import type {
  AssessmentEvidence,
  DataClass,
  SinkKind,
} from "./assessment-evidence.js";
import type { RuleResult, StaticReport } from "./static-contract.js";

export type Decision = "allow" | "review" | "block" | "inconclusive";
export type DestinationDecision = {
  status: "allowed" | "disallowed" | "unknown";
  codes: string[];
  policyRuleId: string | null;
};
const key = (value: string) => createHash("sha256").update(value).digest("hex");

function canonicalDestination(
  kind: SinkKind,
  value: string,
): string | undefined {
  if (kind === "http") {
    const parsed = URL.parse(value);
    if (
      !parsed ||
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password
    )
      return;
    return parsed.origin;
  }
  if (kind === "response") return value === "caller" ? value : undefined;
  if (kind === "log") return value === "execution_log" ? value : undefined;
  const trimmed = value.trim();
  if (!trimmed || /[\r\n\u0000]/.test(trimmed) || trimmed.startsWith("="))
    return;
  if (kind === "email" && !/^[^\s<>()@,;]+@[^\s<>()@,;]+$/.test(trimmed))
    return;
  return trimmed;
}

/** Policy comes from the operator sidecar, never from uploaded node content. */
export function assessDestination(
  evidence: AssessmentEvidence | undefined,
  nodeKey: string,
  sink: SinkKind,
  destination: string | null,
  dataClasses: readonly DataClass[],
): DestinationDecision {
  const policy = evidence?.policy?.egress.find(
    (entry) => entry.nodeKey === nodeKey && entry.sink === sink,
  );
  if (!policy)
    return {
      status: "unknown",
      codes: [evidence?.policy ? "policy_rule_missing" : "policy_not_provided"],
      policyRuleId: null,
    };
  const policyRuleId = key(`egress:${policy.id}`);
  // This node/sink policy forbids the known class regardless of which
  // destination the runtime eventually selects. An unknown address must not
  // erase an independently observed class violation.
  const classViolation = dataClasses.some(
    (value) =>
      value !== "unknown" && !policy.allowedDataClasses.includes(value),
  );
  if (destination === null)
    return {
      status: classViolation ? "disallowed" : "unknown",
      codes: [
        classViolation ? "data_class_not_allowed" : "destination_unresolved",
      ],
      policyRuleId,
    };
  const actual = canonicalDestination(sink, destination);
  const expected = policy.destinations.map((value) =>
    canonicalDestination(sink, value),
  );
  if (actual === undefined || expected.some((value) => value === undefined))
    return {
      status: classViolation ? "disallowed" : "unknown",
      codes: [
        classViolation
          ? "data_class_not_allowed"
          : "destination_format_unknown",
      ],
      policyRuleId,
    };
  const listed = expected.includes(actual);
  if (policy.mode === "allowlist" && !listed)
    return {
      status: "disallowed",
      codes: [
        "destination_not_allowlisted",
        ...(classViolation ? ["data_class_not_allowed"] : []),
      ],
      policyRuleId,
    };
  if (policy.mode === "denylist" && listed)
    return {
      status: "disallowed",
      codes: [
        "destination_denylisted",
        ...(classViolation ? ["data_class_not_allowed"] : []),
      ],
      policyRuleId,
    };
  if (classViolation)
    return {
      status: "disallowed",
      codes: ["data_class_not_allowed"],
      policyRuleId,
    };
  if (dataClasses.length === 0 || dataClasses.includes("unknown"))
    return { status: "unknown", codes: ["data_class_unknown"], policyRuleId };
  return {
    status: "allowed",
    codes: ["destination_and_data_allowed_by_supplied_policy"],
    policyRuleId,
  };
}

export type PolicyEvaluation = {
  status: "evaluated" | "not_provided" | "analysis_failed";
  decision: Decision;
  policyKey: string | null;
  evaluatedAt: string;
  codes: string[];
  findingDecisions: {
    findingId: string;
    decision: Decision;
    codes: string[];
    exceptionKey: string | null;
  }[];
  publication: {
    status: "eligible_for_service_review" | "hold" | "rejected";
    codes: string[];
  };
  authority: "local_policy_evaluation_only";
};

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const codes = z.array(z.string().regex(/^[a-z][a-z0-9_]{0,79}$/)).max(16);
const decisionSchema = z.enum(["allow", "review", "block", "inconclusive"]);
export const policyEvaluationSchema: z.ZodType<PolicyEvaluation> = z
  .strictObject({
    status: z.enum(["evaluated", "not_provided", "analysis_failed"]),
    decision: decisionSchema,
    policyKey: hash.nullable(),
    evaluatedAt: z.iso.datetime(),
    codes,
    findingDecisions: z
      .array(
        z.strictObject({
          findingId: hash,
          decision: decisionSchema,
          codes,
          exceptionKey: hash.nullable(),
        }),
      )
      .max(1024),
    publication: z.strictObject({
      status: z.enum(["eligible_for_service_review", "hold", "rejected"]),
      codes,
    }),
    authority: z.literal("local_policy_evaluation_only"),
  })
  .refine(
    (value) => {
      if (value.status !== "evaluated")
        return (
          value.decision === "inconclusive" &&
          value.publication.status === "hold" &&
          value.findingDecisions.length === 0 &&
          (value.status === "not_provided"
            ? value.policyKey === null
            : value.policyKey !== null)
        );
      if (
        value.policyKey === null ||
        new Set(value.findingDecisions.map(({ findingId }) => findingId))
          .size !== value.findingDecisions.length
      )
        return false;
      if (
        value.decision === "allow" &&
        value.findingDecisions.some(({ decision }) => decision !== "allow")
      )
        return false;
      if (
        value.decision !== "block" &&
        value.findingDecisions.some(({ decision }) => decision === "block")
      )
        return false;
      if (
        value.decision === "review" &&
        value.findingDecisions.some(
          ({ decision }) => decision === "inconclusive",
        )
      )
        return false;
      return (
        value.publication.status !== "eligible_for_service_review" ||
        (value.decision === "allow" &&
          value.publication.codes.length === 1 &&
          value.publication.codes[0] ===
            "authenticated_service_publication_check_still_required")
      );
    },
    { message: "Inconsistent policy evaluation" },
  );

function strongest(decisions: readonly Decision[]): Decision {
  for (const value of ["block", "inconclusive", "review", "allow"] as const)
    if (decisions.includes(value)) return value;
  return "allow";
}

export function evaluatePolicy(
  base: StaticReport,
  extensionRules: RuleResult[],
  evidence: AssessmentEvidence | undefined,
  nowISO: string,
): PolicyEvaluation {
  const now = Date.parse(nowISO);
  const empty: PolicyEvaluation = {
    status: "not_provided",
    decision: "inconclusive",
    policyKey: null,
    evaluatedAt: nowISO,
    codes: ["policy_not_provided"],
    findingDecisions: [],
    publication: {
      status: "hold",
      codes: ["completed_policy_evaluation_required"],
    },
    authority: "local_policy_evaluation_only",
  };
  if (!z.iso.datetime().safeParse(nowISO).success || !Number.isFinite(now))
    throw new Error("invalid_evaluation_time");
  const policy = evidence?.policy;
  if (!policy) return empty;
  const policyKey = key(JSON.stringify([policy.id, policy.version]));
  if (base.status === "error")
    return {
      ...empty,
      policyKey,
      status: "analysis_failed",
      codes: ["analysis_failed"],
      publication: { status: "hold", codes: ["successful_analysis_required"] },
    };
  const rules = [...base.rules, ...extensionRules];
  const findings = rules.flatMap((rule) => rule.findings);
  const severity = { info: 0, low: 1, medium: 2, high: 3 };
  const effectiveExceptions = new Map<
    string,
    "false_positive" | "risk_acceptance"
  >();
  const findingDecisions: PolicyEvaluation["findingDecisions"] = findings.map(
    (finding) => {
      const codes = finding.evidence.map(({ code }) => code);
      const matched = policy.rules.filter(
        (entry) =>
          entry.category === finding.category &&
          severity[finding.severity] >= severity[entry.minimumSeverity],
      );
      const decisionCodes = [
        matched.length ? "category_policy_applied" : "default_policy_applied",
      ];
      let decision: Decision = strongest(
        matched.length
          ? matched.map(({ decision }) => decision)
          : [policy.defaultDecision],
      );
      if (
        codes.some((code) =>
          [
            "destination_not_allowlisted",
            "destination_denylisted",
            "data_class_not_allowed",
          ].includes(code),
        )
      ) {
        decision = "block";
        decisionCodes.push("explicit_egress_policy_violation");
      }
      if (
        policy.requireAuthenticatedWebhook &&
        codes.some(
          (code) =>
            code === "webhook_authentication_none" ||
            code === "webhook_authentication_default_none",
        )
      ) {
        decision = "block";
        decisionCodes.push("authentication_policy_requirement");
      }
      if (
        policy.requireAiApproval &&
        codes.includes("ai_tool_approval_not_declared")
      ) {
        decision = "block";
        decisionCodes.push("ai_approval_policy_requirement");
      }
      let exceptionKey: string | null = null;
      const exception =
        policy.exceptions.find(
          (entry) =>
            entry.findingId === finding.id &&
            entry.inputSha256 === base.inputSha256,
        ) ?? policy.exceptions.find((entry) => entry.findingId === finding.id);
      if (exception) {
        if (exception.inputSha256 !== base.inputSha256)
          decisionCodes.push("exception_input_mismatch");
        else if (
          Date.parse(exception.approvedAt) > now ||
          Date.parse(exception.expiresAt) <= now
        )
          decisionCodes.push("exception_not_active");
        else {
          decision = exception.decision;
          exceptionKey = key(`exception:${exception.id}`);
          decisionCodes.push(
            exception.kind === "false_positive"
              ? "supplied_false_positive_exception_applied"
              : "supplied_risk_acceptance_applied",
          );
          effectiveExceptions.set(finding.id, exception.kind);
        }
      }
      return {
        findingId: finding.id,
        decision,
        codes: decisionCodes,
        exceptionKey,
      };
    },
  );
  const incomplete = rules.some((rule) =>
    rule.coverage.some(
      ({ status }) => status === "partial" || status === "unsupported",
    ),
  );
  const decision = strongest([
    findings.length ? "allow" : policy.defaultDecision,
    ...findingDecisions.map(({ decision }) => decision),
    ...(incomplete ? [policy.unknownDecision] : []),
  ]);
  const publicationCodes: string[] = [];
  const review = evidence?.publicationReview;
  if (decision !== "allow")
    publicationCodes.push("policy_does_not_allow_publication");
  if (incomplete)
    publicationCodes.push("analysis_scope_requires_service_review");
  if (
    findings.some(
      (finding) =>
        finding.category === "secrets" &&
        effectiveExceptions.get(finding.id) !== "false_positive",
    )
  )
    publicationCodes.push("unresolved_secret_candidate");
  {
    if (!policy.requirePublicationReview)
      publicationCodes.push("file_exposure_review_cannot_be_disabled");
    if (!review) publicationCodes.push("file_exposure_review_missing");
    else {
      if (review.inputSha256 !== base.inputSha256)
        publicationCodes.push("file_exposure_review_hash_mismatch");
      if (
        review.policyId !== policy.id ||
        review.policyVersion !== policy.version
      )
        publicationCodes.push("file_exposure_review_policy_mismatch");
      if (
        Date.parse(review.recordedAt) > now ||
        Date.parse(review.expiresAt) <= now
      )
        publicationCodes.push("file_exposure_review_not_current");
      if (review.status !== "approved")
        publicationCodes.push("file_exposure_review_not_approved");
      if (
        !["secrets", "pii", "internal_addresses", "account_references"].every(
          (scope) =>
            review.scopes.includes(scope as (typeof review.scopes)[number]),
        )
      )
        publicationCodes.push("file_exposure_review_scope_incomplete");
    }
  }
  if (evidence?.provenance?.license?.redistribution === "restricted")
    publicationCodes.push("redistribution_restricted");
  else if (
    evidence?.provenance &&
    evidence.provenance.license?.redistribution !== "allowed"
  )
    publicationCodes.push("redistribution_permission_unknown");
  return {
    status: "evaluated",
    decision,
    policyKey,
    evaluatedAt: nowISO,
    codes: [
      "findings_preserved",
      "supplied_policy_authority_not_service_authorization",
      ...(incomplete ? ["incomplete_coverage_policy_applied"] : []),
    ],
    findingDecisions,
    publication: {
      status:
        review?.status === "rejected" ||
        evidence?.provenance?.license?.redistribution === "restricted"
          ? "rejected"
          : publicationCodes.length
            ? "hold"
            : "eligible_for_service_review",
      codes: publicationCodes.length
        ? publicationCodes
        : ["authenticated_service_publication_check_still_required"],
    },
    authority: "local_policy_evaluation_only",
  };
}
