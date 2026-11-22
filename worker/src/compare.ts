import { resultSchema, resultVersions } from "./contract.js";
import type { Result } from "./contract.js";

export type Recheck = {
  id: string;
  status: "binding_verified" | "persisting" | "inconclusive";
};

type Basis =
  | "matched"
  | "different_analysis_versions"
  | "unsupported_analysis_versions"
  | "invalid_result"
  | "same_workflow_version"
  | "same_input";
type CoverageChange =
  "unchanged" | "changed" | "reduced" | "expanded" | "unknown";
type ComparisonStatus = Result["status"] | "unknown";

const analysisVersions = [
  "contractVersion",
  "engineVersion",
  "rulesVersion",
  "adapterVersion",
] as const;

type StoredResult<Shape extends Result = Result> = {
  [Field in keyof Shape]: Field extends keyof typeof resultVersions
    ? string
    : Shape[Field];
};

export type AnalysisComparison = {
  basis: Basis;
  coverage: {
    baseline: ComparisonStatus;
    candidate: ComparisonStatus;
    change: CoverageChange;
  };
  rechecks: Recheck[];
  newFindings: { id: string; status: "introduced" | "inconclusive" }[];
};

function readStoredResult(result: StoredResult): Result | undefined {
  for (const field of analysisVersions) {
    const stamp = result?.[field];
    if (typeof stamp !== "string" || !stamp.trim()) return undefined;
  }
  // The current shape can preserve historical evidence. The original version
  // stamps remain authoritative for whether that evidence is comparable.
  return resultSchema.safeParse({ ...result, ...resultVersions }).data;
}

function compareBasis(
  baseline: StoredResult,
  candidate: StoredResult,
  validResults: boolean,
): Basis {
  if (!validResults) return "invalid_result";
  if (analysisVersions.some((field) => baseline[field] !== candidate[field]))
    return "different_analysis_versions";
  if (
    analysisVersions.some((field) => baseline[field] !== resultVersions[field])
  )
    return "unsupported_analysis_versions";
  if (baseline.workflowVersionId === candidate.workflowVersionId)
    return "same_workflow_version";
  if (baseline.inputSha256 === candidate.inputSha256) return "same_input";
  return "matched";
}

function compareCoverage(
  basis: Basis,
  baseline: ComparisonStatus,
  candidate: ComparisonStatus,
  sameScope: boolean,
): CoverageChange {
  if (basis !== "matched" || baseline === "error" || candidate === "error")
    return "unknown";
  if (baseline === "analyzed" && candidate === "analyzed")
    return sameScope ? "unchanged" : "changed";
  if (baseline === "analyzed") return "reduced";
  if (candidate === "analyzed") return "expanded";
  return "unknown";
}

/** The caller must establish that both immutable versions belong to the same workflow. */
export function compareAnalysis(
  baseline: StoredResult,
  candidate: StoredResult,
): AnalysisComparison {
  const before = readStoredResult(baseline);
  const after = readStoredResult(candidate);
  const basis = compareBasis(
    baseline,
    candidate,
    before !== undefined && after !== undefined,
  );
  const beforeStatus = before?.status ?? "unknown";
  const afterStatus = after?.status ?? "unknown";
  // The result contract permits exactly one fully analyzed sink in this profile.
  const earlier =
    before?.status === "analyzed" ? before.coverage[0] : undefined;
  const later = after?.status === "analyzed" ? after.coverage[0] : undefined;
  const sameLookup =
    earlier !== undefined &&
    later !== undefined &&
    earlier.sink.nodeKey === later.sink.nodeKey &&
    earlier.shapeKey === later.shapeKey;
  const sameScope = sameLookup && earlier.inputKey === later.inputKey;
  const baselineFindings =
    before && before.status !== "error" ? before.findings : [];
  const candidateFindings =
    after && after.status !== "error" ? after.findings : [];
  const presentBefore = new Set(baselineFindings.map(({ id }) => id));
  const presentAfter = new Set(candidateFindings.map(({ id }) => id));

  const rechecks = baselineFindings.map<Recheck>(({ id }) => {
    const inconclusive = { id, status: "inconclusive" } as const;
    if (
      basis !== "matched" ||
      !sameScope ||
      earlier.disposition !== "interpolated"
    )
      return inconclusive;
    if (later.disposition === "bound")
      return { id, status: "binding_verified" };
    if (presentAfter.has(id)) return { id, status: "persisting" };
    return inconclusive;
  });
  const newStatus =
    basis === "matched" && sameLookup && baselineFindings.length === 0
      ? "introduced"
      : "inconclusive";

  return {
    basis,
    coverage: {
      baseline: beforeStatus,
      candidate: afterStatus,
      change: compareCoverage(basis, beforeStatus, afterStatus, sameScope),
    },
    rechecks,
    newFindings: candidateFindings
      .filter(
        ({ id }) => basis !== "matched" || !sameScope || !presentBefore.has(id),
      )
      .map(({ id }) => ({ id, status: newStatus })),
  };
}

/** Per-finding rechecks for callers that only need the disposition of previous warnings. */
export function compareResults(
  baseline: StoredResult,
  candidate: StoredResult,
): Recheck[] {
  return compareAnalysis(baseline, candidate).rechecks;
}
