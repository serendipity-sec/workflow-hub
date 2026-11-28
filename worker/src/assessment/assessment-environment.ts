import { createHash } from "node:crypto";
import * as semver from "semver";
import { z } from "zod";
import type { AssessmentEvidence, OsvDocument } from "./assessment-evidence.js";
import type { Context } from "../workflow/static-context.js";
import { locationFor, stableId } from "../contracts/static-contract.js";
import type {
  Finding,
  RuleResult,
  StaticLocation,
} from "../contracts/static-contract.js";

const root: StaticLocation = { nodeKey: null, pointer: "" };
const key = (value: string) => createHash("sha256").update(value).digest("hex");
export type AdvisoryMatch = {
  advisoryKey: string;
  status: "affected" | "not_affected" | "unknown";
  codes: string[];
};
export type DependencyAssessment = {
  packageKey: string;
  sourceKey: string;
  observationKind: "declaration" | "supplied_observation";
  independentlyVerified: false;
  status: "affected" | "not_affected" | "unknown";
  nodeKeys: string[];
  codes: string[];
  advisories: AdvisoryMatch[];
};
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const codes = z.array(z.string().regex(/^[a-z][a-z0-9_]{0,79}$/)).max(16);
export const advisoryMatchSchema: z.ZodType<AdvisoryMatch> = z.strictObject({
  advisoryKey: hash,
  status: z.enum(["affected", "not_affected", "unknown"]),
  codes,
});
export const dependencyAssessmentSchema: z.ZodType<DependencyAssessment> = z
  .strictObject({
    packageKey: hash,
    sourceKey: hash,
    observationKind: z.enum(["declaration", "supplied_observation"]),
    independentlyVerified: z.literal(false),
    status: z.enum(["affected", "not_affected", "unknown"]),
    nodeKeys: z.array(hash).max(64),
    codes,
    advisories: z.array(advisoryMatchSchema).max(128),
  })
  .refine(
    (value) => {
      const expected = value.advisories.some(
        ({ status }) => status === "affected",
      )
        ? "affected"
        : !value.advisories.length ||
            value.advisories.some(({ status }) => status === "unknown")
          ? "unknown"
          : "not_affected";
      return (
        value.status === expected &&
        new Set(value.nodeKeys).size === value.nodeKeys.length &&
        new Set(value.advisories.map(({ advisoryKey }) => advisoryKey)).size ===
          value.advisories.length
      );
    },
    { message: "Inconsistent dependency assessment" },
  );
export const dependencyResultsSchema = z
  .array(dependencyAssessmentSchema)
  .max(65);

function rangeMatch(
  version: string,
  range: OsvDocument["affected"][number]["ranges"][number],
): boolean | undefined {
  if (range.type === "GIT" || !semver.valid(version)) return;
  const intervals: { start: string; end?: string; inclusive?: boolean }[] = [];
  let open: string | undefined;
  let previous: string | undefined;
  for (const event of range.events) {
    if ("introduced" in event) {
      if (
        open !== undefined ||
        (event.introduced !== "0" && !semver.valid(event.introduced))
      )
        return;
      if (
        previous &&
        (event.introduced === "0" || semver.lt(event.introduced, previous))
      )
        return;
      open = event.introduced;
    } else {
      const end =
        "fixed" in event
          ? event.fixed
          : "last_affected" in event
            ? event.last_affected
            : event.limit;
      if (
        open === undefined ||
        !semver.valid(end) ||
        (open !== "0" && semver.lt(end, open))
      )
        return;
      intervals.push({ start: open, end, inclusive: "last_affected" in event });
      previous = end;
      open = undefined;
    }
  }
  if (open !== undefined) intervals.push({ start: open });
  if (intervals.length === 0) return;
  return intervals.some(
    ({ start, end, inclusive }) =>
      (start === "0" || semver.gte(version, start)) &&
      (end === undefined ||
        (inclusive ? semver.lte(version, end) : semver.lt(version, end))),
  );
}

/** OSV matching is limited to the supplied npm snapshot; it performs no lookup. */
export function matchAdvisory(
  name: string,
  version: string,
  document: OsvDocument,
): AdvisoryMatch {
  const advisoryKey = key(`advisory:${document.id}`);
  if (
    document.schema_version &&
    (!semver.valid(document.schema_version) ||
      semver.major(document.schema_version) !== 1)
  )
    return {
      advisoryKey,
      status: "unknown",
      codes: ["advisory_schema_version_unsupported"],
    };
  if (document.withdrawn)
    return {
      advisoryKey,
      status: "unknown",
      codes: ["supplied_advisory_withdrawn"],
    };
  const affected = document.affected.filter(
    (entry) => entry.package.ecosystem === "npm" && entry.package.name === name,
  );
  if (!affected.length)
    return {
      advisoryKey,
      status: "unknown",
      codes: ["advisory_package_mismatch"],
    };
  let unknown = false;
  let found = false;
  for (const entry of affected) {
    if (entry.versions.includes(version)) found = true;
    if (!entry.versions.length && !entry.ranges.length) unknown = true;
    for (const range of entry.ranges) {
      const matched = rangeMatch(version, range);
      if (matched === true) found = true;
      else if (matched === undefined) unknown = true;
    }
  }
  if (found)
    return {
      advisoryKey,
      status: "affected",
      codes: ["version_matches_supplied_advisory"],
    };
  if (unknown || !semver.valid(version))
    return {
      advisoryKey,
      status: "unknown",
      codes: ["advisory_range_not_supported"],
    };
  return {
    advisoryKey,
    status: "not_affected",
    codes: ["not_affected_in_supplied_snapshot_only"],
  };
}

export function assessDependencies(
  context: Context,
  evidence: AssessmentEvidence | undefined,
): DependencyAssessment[] {
  if (!evidence) return [];
  const packages = [...evidence.packages];
  if (
    evidence.runtime &&
    !packages.some(
      ({ name, version }) =>
        name === "n8n" && version === evidence.runtime!.n8nVersion,
    )
  )
    packages.push({
      name: "n8n",
      version: evidence.runtime.n8nVersion,
      nodeKeys: [],
      sourceId: evidence.runtime.sourceId,
    });
  return packages.map((pkg) => {
    const source = evidence.sources.find(({ id }) => id === pkg.sourceId)!;
    const docs = evidence.advisories.filter(({ document }) =>
      document.affected.some(
        ({ package: item }) =>
          item.ecosystem === "npm" && item.name === pkg.name,
      ),
    );
    const advisories = docs.map(({ document }) =>
      matchAdvisory(pkg.name, pkg.version, document),
    );
    const status = advisories.some(({ status }) => status === "affected")
      ? "affected"
      : !advisories.length ||
          advisories.some(({ status }) => status === "unknown")
        ? "unknown"
        : "not_affected";
    const present = pkg.nodeKeys.filter((nodeKey) =>
      context.nodeByKey.has(nodeKey),
    );
    return {
      packageKey: key(`package:${pkg.name}`),
      sourceKey: key(`source:${pkg.sourceId}`),
      observationKind: source.kind,
      independentlyVerified: false,
      status,
      nodeKeys: present,
      codes: [
        "installed_version_is_supplied_evidence",
        ...(present.length !== pkg.nodeKeys.length
          ? ["package_node_binding_unresolved"]
          : []),
        ...(!advisories.length
          ? ["advisory_snapshot_missing_for_package"]
          : []),
      ],
      advisories,
    };
  });
}

function rule(ruleId: string): RuleResult {
  return {
    ruleId,
    category: "dependencies",
    profileVersion: "1.0.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}
function diagnostic(
  result: RuleResult,
  location: StaticLocation,
  code: string,
): void {
  const id = stableId(result.ruleId, location, code);
  if (result.diagnostics.length >= 250) return;
  if (!result.diagnostics.some((entry) => entry.id === id))
    result.diagnostics.push({ id, location, code });
}
function finding(
  result: RuleResult,
  location: StaticLocation,
  code: string,
  severity: Finding["severity"] = "info",
  extra: Finding["evidence"] = [],
): void {
  const id = stableId(result.ruleId, location, code);
  const existing = result.findings.find((entry) => entry.id === id);
  if (existing) {
    for (const item of extra)
      if (
        !existing.evidence.some(
          (value) =>
            value.code === item.code &&
            value.location.nodeKey === item.location.nodeKey &&
            value.location.pointer === item.location.pointer,
        ) &&
        existing.evidence.length < 68
      )
        existing.evidence.push(item);
    return;
  }
  if (result.findings.length >= 250) {
    diagnostic(result, root, "context_rule_result_limit");
    return;
  }
  if (!result.findings.some((entry) => entry.id === id))
    result.findings.push({
      id,
      ruleId: result.ruleId,
      category: result.category,
      severity,
      claim: severity === "high" ? "candidate" : "configuration",
      location,
      evidence: [{ code, location }, ...extra],
      assumptions: [
        "supplied_evidence_not_independently_verified",
        "no_uploaded_content_executed",
      ],
      remediation: {
        code: "verify_environment_and_dependency_evidence",
        checks: [
          "confirm_actual_installed_versions",
          "review_bound_source_artifact",
          "reassess_changed_environment",
        ],
      },
    });
}
function finish(result: RuleResult): RuleResult {
  result.coverage.push({
    location: root,
    status: result.diagnostics.length
      ? result.findings.length
        ? "partial"
        : "unsupported"
      : result.findings.length
        ? "checked"
        : "not_applicable",
    findingIds: result.findings.map(({ id }) => id),
    diagnosticIds: result.diagnostics.map(({ id }) => id),
  });
  return result;
}

export function assessEnvironment(
  context: Context,
  evidence: AssessmentEvidence | undefined,
): RuleResult[] {
  const dependencies = rule("CONTEXT_PACKAGE_ADVISORIES");
  for (const assessment of assessDependencies(context, evidence)) {
    const locations = assessment.nodeKeys.length
      ? assessment.nodeKeys.map((nodeKey) =>
          locationFor(context.nodeByKey.get(nodeKey)!),
        )
      : [root];
    for (const location of locations) {
      if (assessment.status === "affected")
        finding(
          dependencies,
          location,
          "supplied_package_version_matches_advisory",
          "high",
        );
      else if (assessment.status === "not_affected")
        finding(
          dependencies,
          location,
          "package_not_affected_in_supplied_snapshot",
          "info",
        );
      else
        diagnostic(dependencies, location, "package_advisory_status_unknown");
      if (assessment.codes.includes("package_node_binding_unresolved"))
        diagnostic(dependencies, root, "package_node_binding_unresolved");
    }
  }
  for (const node of context.nodes.filter(
    ({ type }) =>
      !type.startsWith("n8n-nodes-base.") &&
      !type.startsWith("@n8n/n8n-nodes-langchain."),
  )) {
    if (!evidence?.packages.some(({ nodeKeys }) => nodeKeys.includes(node.key)))
      diagnostic(
        dependencies,
        locationFor(node),
        "external_node_package_evidence_missing",
      );
  }
  const runtime = rule("CONTEXT_RUNTIME_EVIDENCE");
  if (!evidence?.runtime) diagnostic(runtime, root, "runtime_evidence_missing");
  else {
    if (!semver.valid(evidence.runtime.n8nVersion))
      diagnostic(runtime, root, "runtime_version_invalid");
    else finding(runtime, root, "runtime_version_supplied");
    if (
      evidence.packages.some(
        ({ name, version }) =>
          name === "n8n" && version !== evidence.runtime!.n8nVersion,
      )
    )
      diagnostic(runtime, root, "runtime_package_version_conflict");
    for (const control of evidence.runtime.networkControls)
      finding(
        runtime,
        root,
        `${control.kind}_declared_${control.enabled ? "enabled" : "disabled"}`,
        control.enabled ? "info" : "medium",
      );
    for (const credential of evidence.runtime.credentialScopes) {
      const node = context.nodeByKey.get(credential.nodeKey);
      if (!node) {
        diagnostic(runtime, root, "credential_node_binding_unresolved");
        continue;
      }
      finding(runtime, locationFor(node), "credential_scopes_supplied");
      if (
        credential.scopes.some(
          (scope) =>
            scope === "*" ||
            /(?:^|[:._-])(?:admin|write|delete)(?:$|[:._-])/.test(scope),
        )
      )
        finding(
          runtime,
          locationFor(node),
          "broad_credential_scope_declared",
          "medium",
        );
    }
    for (const authentication of evidence.runtime.upstreamAuthentication) {
      const node = context.nodeByKey.get(authentication.nodeKey);
      if (!node) {
        diagnostic(
          runtime,
          root,
          "upstream_authentication_node_binding_unresolved",
        );
        continue;
      }
      finding(
        runtime,
        locationFor(node),
        authentication.enforced && authentication.kind !== "none"
          ? "upstream_authentication_declared_enforced"
          : "upstream_authentication_declared_absent",
        authentication.enforced && authentication.kind !== "none"
          ? "info"
          : "medium",
      );
      diagnostic(
        runtime,
        locationFor(node),
        "upstream_authentication_not_independently_verified",
      );
    }
  }
  const ai = rule("CONTEXT_AI_APPROVAL_BOUNDARY");
  for (const edge of context.unsupportedEdges.filter(
    ({ channel }) => channel === "ai_languageModel",
  )) {
    finding(
      ai,
      locationFor(context.nodeByKey.get(edge.to)!),
      "ai_model_boundary_declared",
      "info",
      [
        {
          code: "attached_model_declaration",
          location: locationFor(context.nodeByKey.get(edge.from)!),
        },
      ],
    );
    diagnostic(
      ai,
      locationFor(context.nodeByKey.get(edge.to)!),
      "model_attack_resistance_and_value_flow_unverified",
    );
  }
  const toolEdges = context.unsupportedEdges.filter(
    ({ channel }) => channel === "ai_tool",
  );
  for (const edge of toolEdges) {
    const tool = context.nodeByKey.get(edge.from)!;
    const agent = context.nodeByKey.get(edge.to)!;
    const location = locationFor(agent);
    finding(ai, location, "ai_tool_boundary_declared", "medium", [
      { code: "attached_tool_declaration", location: locationFor(tool) },
    ]);
    const approval = evidence?.aiApprovals.find(
      ({ nodeKey, toolNodeKeys }) =>
        nodeKey === agent.key && toolNodeKeys.includes(tool.key),
    );
    if (approval?.required) {
      finding(ai, location, "ai_tool_approval_declared_required");
      diagnostic(ai, location, "runtime_approval_enforcement_unverified");
    } else {
      finding(ai, location, "ai_tool_approval_not_declared", "medium");
      diagnostic(
        ai,
        location,
        approval
          ? "approval_requirement_declared_absent"
          : "ai_approval_evidence_missing",
      );
    }
    if (
      [
        "n8n-nodes-base.executeCommand",
        "n8n-nodes-base.ssh",
        "n8n-nodes-base.code",
        "n8n-nodes-base.readWriteFile",
        "n8n-nodes-base.httpRequest",
        "@n8n/n8n-nodes-langchain.toolCode",
        "@n8n/n8n-nodes-langchain.toolHttpRequest",
        "@n8n/n8n-nodes-langchain.toolWorkflow",
      ].includes(tool.type)
    )
      finding(
        ai,
        location,
        "ai_tool_privileged_capability_declared",
        "medium",
        [{ code: "privileged_tool_declaration", location: locationFor(tool) }],
      );
    const pending = [agent.key];
    const reached = new Set<string>();
    let input = false;
    for (
      let index = 0;
      index < pending.length && reached.size <= context.nodes.length;
      index++
    ) {
      const nodeKey = pending[index]!;
      if (reached.has(nodeKey)) continue;
      reached.add(nodeKey);
      for (const incoming of context.edges.filter(({ to }) => to === nodeKey)) {
        const source = context.nodeByKey.get(incoming.from)!;
        if (
          [
            "n8n-nodes-base.webhook",
            "n8n-nodes-base.emailReadImap",
            "n8n-nodes-base.readBinaryFile",
          ].includes(source.type)
        )
          input = true;
        pending.push(source.key);
      }
    }
    if (input)
      finding(ai, location, "external_input_control_path_to_ai", "medium");
    diagnostic(
      ai,
      location,
      "model_attack_resistance_and_value_flow_unverified",
    );
  }
  const receipts = rule("CONTEXT_SYNTHETIC_RECEIPTS");
  for (const receipt of evidence?.syntheticReceipts ?? []) {
    if (receipt.inputSha256 !== evidence!.inputSha256) {
      diagnostic(receipts, root, "synthetic_receipt_input_mismatch");
      continue;
    }
    const passed = receipt.cases.every(
      ({ attackBlocked, normalBehaviorPreserved }) =>
        attackBlocked && normalBehaviorPreserved,
    );
    finding(
      receipts,
      root,
      passed
        ? "supplied_synthetic_receipt_reports_both_checks_passed"
        : "supplied_synthetic_receipt_reports_failed_checks",
      passed ? "info" : "medium",
    );
    diagnostic(
      receipts,
      root,
      "synthetic_receipt_not_independently_reexecuted",
    );
  }
  return [finish(dependencies), finish(runtime), finish(ai), finish(receipts)];
}
