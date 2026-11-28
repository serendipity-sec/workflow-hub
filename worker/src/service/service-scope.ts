import { classifyCoverageCause } from "./coverage-policy.js";

export type ServiceDiagnosticDisposition =
  "analysisGaps" | "environmentChecks" | "scopeNotes";

/** Fixed product scope, not an uploaded allowlist or a security verdict. */
export function serviceDiagnosticDisposition(
  code: string,
): ServiceDiagnosticDisposition {
  const cause = classifyCoverageCause(code);
  if (cause.kind === "environment_evidence") return "environmentChecks";
  if (
    cause.scopeOnly ||
    code === "nlp_language_outside_profile" ||
    code === "model_attack_resistance_and_value_flow_unverified"
  )
    return "scopeNotes";
  // Missing definitions, unknown transformations, parse/resource limits and
  // unregistered diagnostics can conceal security-relevant effects.
  return "analysisGaps";
}

export const initialServiceScope = {
  profile: "initial_static_v1",
  environmentInput: "not_requested",
  environmentNotices: "usage_precautions",
  piiScope: "existing_detectors_context_completeness_excluded",
  workflowExecution: "not_run",
} as const;
