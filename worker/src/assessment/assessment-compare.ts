import { createHash } from "node:crypto";
import { z } from "zod";
import {
  assessmentExtensionRules,
  assessmentLimits,
  assessmentReportSchema,
} from "../contracts/assessment-contract.js";
import type {
  AssessmentReport,
  FileAssessment,
  SubworkflowLink,
} from "../contracts/assessment-contract.js";
import { categories, reportStatus } from "../contracts/static-contract.js";
import type {
  Finding,
  RuleResult,
  StaticLocation,
} from "../contracts/static-contract.js";

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const supportedRules = [
  "CONTENT_SECRET_CANDIDATE",
  "CONTENT_PII_CANDIDATE",
  "N8N_REQUEST_AUTH_SETTINGS",
  "N8N_HTTP_EGRESS",
  "N8N_HTTP_SSRF",
  "N8N_SQL_TEXT_FLOW",
  "N8N_EXECUTABLE_CONTENT",
  "N8N_TRANSPORT_SETTINGS",
  "N8N_RESPONSE_EXPOSURE",
  "N8N_DEPENDENCY_CAPABILITIES",
  ...assessmentExtensionRules,
] as const;
const ruleIdSchema = z.enum(supportedRules);
export const assessmentComparisonLimits = {
  rows: 4096,
  files: 2 * (assessmentLimits.children + 1),
  resultBytes: 2 * 1024 * 1024,
} as const;
const reasonCodes = [
  "invalid_before_report",
  "invalid_after_report",
  "before_assessment_failed",
  "after_assessment_failed",
  "unsupported_rule_set",
  "ambiguous_file_correspondence",
  "comparison_output_limit",
  "assessment_engine_changed",
  "assessment_contract_changed",
  "isolation_boundary_changed",
  "base_analysis_failed",
  "base_profile_changed",
  "node_inventory_unavailable",
  "evidence_context_changed",
  "policy_context_changed",
  "policy_evaluation_time_changed",
  "dependency_context_changed",
  "scanner_profile_changed",
  "native_profile_changed",
  "tool_failed",
  "child_definition_changed",
  "child_definition_missing",
  "child_definition_added",
  "child_disabled",
  "child_invalid",
  "child_analysis_limit",
  "child_cycle",
  "child_caller_unmatched",
  "rule_missing",
  "rule_profile_changed",
  "node_removed",
  "node_added",
  "node_disabled",
  "node_identity_unmatched",
  "node_identity_kind_changed",
  "node_kind_changed",
  "name_derived_identity",
  "evidence_node_removed",
  "evidence_node_added",
  "evidence_node_disabled",
  "coverage_changed",
  "scope_not_checked",
  "analysis_path_changed",
  "observation_present_both",
  "observation_details_changed",
  "observation_not_seen_in_checked_scope",
  "observation_new_in_checked_scope",
] as const;
type Reason = (typeof reasonCodes)[number];
const reasons = z.array(z.enum(reasonCodes)).max(reasonCodes.length);
// A comparison points back to the original finding for field-level details.
// It never copies arbitrary field paths, evidence strings or snippets from a
// report supplied to the CLI, even when they pass that report's shape schema.
const observationSchema = z.strictObject({
  id: hash,
  ruleId: ruleIdSchema,
  category: z.enum(categories),
  severity: z.enum(["info", "low", "medium", "high"]),
  claim: z.enum(["configuration", "candidate", "supported_path"]),
  nodeKey: hash.nullable(),
});
const fileRefSchema = z.strictObject({
  analysisKey: hash,
  inputSha256: hash,
  depth: z.int().min(0).max(assessmentLimits.depth),
  coverageStatus: z.enum(["analyzed", "partial", "unsupported", "error"]),
  policyDecision: z.enum(["allow", "review", "block", "inconclusive"]),
});
const filePairSchema = z.strictObject({
  key: hash,
  before: fileRefSchema.nullable(),
  after: fileRefSchema.nullable(),
  correspondence: z.enum([
    "root",
    "same_child_hash",
    "changed_child_hash",
    "before_only",
    "after_only",
  ]),
  codes: reasons,
});
const comparisonEntrySchema = z.strictObject({
  filePairKey: hash,
  before: observationSchema.nullable(),
  after: observationSchema.nullable(),
  status: z.enum([
    "persisting",
    "not_observed",
    "newly_observed",
    "inconclusive",
  ]),
  detailsChanged: z.boolean(),
  codes: reasons.min(1),
});
const count = z.int().min(0).max(assessmentComparisonLimits.rows);
export const assessmentComparisonSchema = z
  .strictObject({
    comparisonVersion: z.literal("1.0.0"),
    status: z.enum(["compared", "inconclusive"]),
    basis: z.enum([
      "same_input",
      "same_assessment_contract",
      "incompatible_or_failed",
    ]),
    beforeSha256: hash.nullable(),
    afterSha256: hash.nullable(),
    scope: z.literal("all_reported_static_findings"),
    execution: z.literal("not_run"),
    behaviorPreserved: z.literal("not_verified"),
    exploitBlocked: z.literal("not_verified"),
    securityEquivalent: z.literal("not_claimed"),
    files: z.array(filePairSchema).max(assessmentComparisonLimits.files),
    rechecks: z
      .array(comparisonEntrySchema)
      .max(assessmentComparisonLimits.rows),
    newFindings: z
      .array(comparisonEntrySchema)
      .max(assessmentComparisonLimits.rows),
    counts: z.strictObject({
      beforeFindings: count,
      afterFindings: count,
      persisting: count,
      notObserved: count,
      newlyObserved: count,
      inconclusive: count,
    }),
    codes: reasons,
  })
  .refine(
    (result) => {
      const entries = [...result.rechecks, ...result.newFindings];
      const pairs = new Map(result.files.map((pair) => [pair.key, pair]));
      const beforeIds = new Set<string>();
      const afterIds = new Set<string>();
      if (
        entries.length > assessmentComparisonLimits.rows ||
        pairs.size !== result.files.length ||
        Buffer.byteLength(JSON.stringify(result)) >
          assessmentComparisonLimits.resultBytes ||
        new Set(result.codes).size !== result.codes.length ||
        result.rechecks.some(
          (item) => item.before === null || item.status === "newly_observed",
        ) ||
        result.newFindings.some(
          (item) =>
            item.before !== null ||
            item.after === null ||
            !["newly_observed", "inconclusive"].includes(item.status),
        )
      )
        return false;
      for (const pair of result.files) {
        if (
          (!pair.before && !pair.after) ||
          new Set(pair.codes).size !== pair.codes.length
        )
          return false;
        if (
          pair.before?.depth === 0 &&
          pair.before.inputSha256 !== result.beforeSha256
        )
          return false;
        if (
          pair.after?.depth === 0 &&
          pair.after.inputSha256 !== result.afterSha256
        )
          return false;
        if (
          pair.correspondence === "before_only" &&
          (pair.before === null || pair.after !== null)
        )
          return false;
        if (
          pair.correspondence === "after_only" &&
          (pair.after === null || pair.before !== null)
        )
          return false;
        if (
          ["root", "same_child_hash", "changed_child_hash"].includes(
            pair.correspondence,
          )
        ) {
          if (!pair.before || !pair.after) return false;
          if (
            pair.correspondence === "root" &&
            (pair.before.depth !== 0 || pair.after.depth !== 0)
          )
            return false;
          if (
            pair.correspondence !== "root" &&
            (pair.before.depth === 0 || pair.before.depth !== pair.after.depth)
          )
            return false;
          if (
            pair.correspondence === "same_child_hash" &&
            pair.before.inputSha256 !== pair.after.inputSha256
          )
            return false;
          if (
            pair.correspondence === "changed_child_hash" &&
            pair.before.inputSha256 === pair.after.inputSha256
          )
            return false;
        }
      }
      for (const entry of entries) {
        const pair = pairs.get(entry.filePairKey);
        if (
          !pair ||
          (!entry.before && !entry.after) ||
          new Set(entry.codes).size !== entry.codes.length
        )
          return false;
        for (const side of ["before", "after"] as const) {
          const observation = entry[side];
          if (!observation) continue;
          const ids = side === "before" ? beforeIds : afterIds;
          const key = JSON.stringify([
            entry.filePairKey,
            observation.ruleId,
            observation.id,
          ]);
          if (!pair[side] || ids.has(key)) return false;
          ids.add(key);
        }
        if (entry.detailsChanged && (!entry.before || !entry.after))
          return false;
        if (
          entry.detailsChanged !==
          entry.codes.includes("observation_details_changed")
        )
          return false;
        if (
          entry.status === "persisting" &&
          (!entry.before ||
            !entry.after ||
            entry.before.id !== entry.after.id ||
            entry.before.ruleId !== entry.after.ruleId ||
            entry.before.category !== entry.after.category ||
            entry.before.nodeKey !== entry.after.nodeKey ||
            !entry.codes.includes("observation_present_both"))
        )
          return false;
        if (
          entry.status === "not_observed" &&
          (!entry.before ||
            entry.after ||
            !entry.codes.includes("observation_not_seen_in_checked_scope"))
        )
          return false;
        if (
          entry.status === "newly_observed" &&
          (entry.before ||
            !entry.after ||
            !entry.codes.includes("observation_new_in_checked_scope"))
        )
          return false;
        const allowed: Partial<Record<Entry["status"], Reason[]>> = {
          persisting: [
            "observation_present_both",
            "observation_details_changed",
            "name_derived_identity",
          ],
          not_observed: [
            "observation_not_seen_in_checked_scope",
            "name_derived_identity",
          ],
          newly_observed: [
            "observation_new_in_checked_scope",
            "name_derived_identity",
          ],
        };
        if (
          allowed[entry.status] &&
          entry.codes.some((code) => !allowed[entry.status]!.includes(code))
        )
          return false;
        if (
          entry.status === "inconclusive" &&
          entry.codes.some(
            (code) =>
              code === "observation_not_seen_in_checked_scope" ||
              code === "observation_new_in_checked_scope",
          )
        )
          return false;
        if (entry.status !== "inconclusive" && pair.codes.length) return false;
      }
      const counted = counts(entries);
      if (JSON.stringify(result.counts) !== JSON.stringify(counted))
        return false;
      if (result.basis === "incompatible_or_failed")
        return (
          result.status === "inconclusive" &&
          entries.every((entry) => entry.status === "inconclusive") &&
          result.codes.length > 0
        );
      return (
        result.beforeSha256 !== null &&
        result.afterSha256 !== null &&
        result.files.length > 0 &&
        result.basis ===
          (result.beforeSha256 === result.afterSha256
            ? "same_input"
            : "same_assessment_contract") &&
        result.status ===
          (entries.some((entry) => entry.status === "inconclusive") ||
          result.files.some((pair) => pair.codes.length > 0)
            ? "inconclusive"
            : "compared")
      );
    },
    { message: "Inconsistent assessment comparison" },
  );
export type AssessmentComparison = z.infer<typeof assessmentComparisonSchema>;
type Entry = z.infer<typeof comparisonEntrySchema>;
type FilePair = z.infer<typeof filePairSchema>;
type Success = Exclude<AssessmentReport, { status: "error" }>;

function counts(entries: Entry[]): AssessmentComparison["counts"] {
  return {
    beforeFindings: entries.filter((entry) => entry.before).length,
    afterFindings: entries.filter((entry) => entry.after).length,
    persisting: entries.filter((entry) => entry.status === "persisting").length,
    notObserved: entries.filter((entry) => entry.status === "not_observed")
      .length,
    newlyObserved: entries.filter((entry) => entry.status === "newly_observed")
      .length,
    inconclusive: entries.filter((entry) => entry.status === "inconclusive")
      .length,
  };
}
const unique = (values: Reason[]): Reason[] => [...new Set(values)];
function canonical(value: unknown): string {
  if (Array.isArray(value)) return JSON.stringify(value.map(canonical));
  if (value && typeof value === "object")
    return JSON.stringify(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, canonical(child)]),
    );
  return JSON.stringify(value) ?? "undefined";
}
function same(left: unknown, right: unknown): boolean {
  return canonical(left) === canonical(right);
}
function field(location: StaticLocation): string {
  return location.nodeKey === null
    ? location.pointer
    : location.pointer.replace(/^\/nodes\/\d+(?=\/|$)/, "");
}
function scope(location: StaticLocation): string {
  return JSON.stringify([location.nodeKey, field(location)]);
}
function rules(file: FileAssessment): RuleResult[] {
  return [
    ...(file.base.status === "error" ? [] : file.base.rules),
    ...file.extensionRules,
  ];
}
function fingerprint(finding: Finding): string {
  // stableId already binds the rule, stable node key, relative field and a fixed
  // discriminator. Verify the structural scope too; an arbitrary reused ID is
  // not enough. Raw values and node array positions do not participate.
  return JSON.stringify([
    finding.id,
    finding.ruleId,
    finding.category,
    scope(finding.location),
  ]);
}
function observation(finding: Finding): z.infer<typeof observationSchema> {
  return {
    id: finding.id,
    ruleId: ruleIdSchema.parse(finding.ruleId),
    category: finding.category,
    severity: finding.severity,
    claim: finding.claim,
    nodeKey: finding.location.nodeKey,
  };
}
function details(finding: Finding): unknown {
  return [
    finding.severity,
    finding.claim,
    finding.evidence.map((item) => [item.code, scope(item.location)]).sort(),
    [...finding.assumptions].sort(),
  ];
}
function fileRef(
  file: FileAssessment | undefined,
): z.infer<typeof fileRefSchema> | null {
  return file
    ? {
        analysisKey: file.analysisKey,
        inputSha256: file.inputSha256,
        depth: file.depth,
        coverageStatus:
          file.base.status === "error" ? "error" : reportStatus(rules(file)),
        policyDecision: file.policy.decision,
      }
    : null;
}

type Index = {
  files: Map<string, FileAssessment>;
  links: Map<string, SubworkflowLink>;
  routes: Map<string, string[]>;
};
function index(report: Success): Index | undefined {
  const files = new Map<string, FileAssessment>();
  const links = new Map<string, SubworkflowLink>();
  const routes = new Map<string, string[]>();
  for (const file of [...report.files].sort((a, b) => a.depth - b.depth)) {
    const parent =
      file.parentAnalysisKey === null
        ? undefined
        : routes.get(file.parentAnalysisKey);
    if (file.depth > 0 && (!parent || !file.caller?.nodeKey)) return;
    const route = file.depth === 0 ? [] : [...parent!, file.caller!.nodeKey!];
    const key = JSON.stringify(route);
    if (files.has(key)) return;
    files.set(key, file);
    routes.set(file.analysisKey, route);
  }
  for (const link of report.subworkflows) {
    const parent = routes.get(link.parentAnalysisKey);
    if (!parent || !link.caller.nodeKey) return;
    const route = JSON.stringify([...parent, link.caller.nodeKey]);
    if (links.has(route)) return;
    links.set(route, link);
  }
  return { files, links, routes };
}
function profile(file: FileAssessment): unknown {
  return [
    file.base.contractVersion,
    file.base.engineVersion,
    file.base.rulesVersion,
    file.base.adapterVersion,
  ];
}
function nativeProfile(file: FileAssessment): unknown {
  return [
    file.tools.native.version,
    [...file.tools.native.modes]
      .sort((a, b) => a.mode.localeCompare(b.mode))
      .map((mode) => [mode.mode, mode.versions]),
  ];
}
function fileReasons(before: FileAssessment, after: FileAssessment): Reason[] {
  const result: Reason[] = [];
  if (before.base.status === "error" || after.base.status === "error")
    result.push("base_analysis_failed");
  if (!same(profile(before), profile(after)))
    result.push("base_profile_changed");
  if (!before.functionSummary || !after.functionSummary)
    result.push("node_inventory_unavailable");
  if (!same(before.evidence, after.evidence))
    result.push("evidence_context_changed");
  if (
    !same(
      [before.policy.status, before.policy.policyKey],
      [after.policy.status, after.policy.policyKey],
    )
  )
    result.push("policy_context_changed");
  if (
    (before.policy.status === "evaluated" ||
      after.policy.status === "evaluated") &&
    before.policy.evaluatedAt !== after.policy.evaluatedAt
  )
    result.push("policy_evaluation_time_changed");
  if (!same(before.dependencies, after.dependencies))
    result.push("dependency_context_changed");
  if (before.tools.gitleaks.version !== after.tools.gitleaks.version)
    result.push("scanner_profile_changed");
  if (!same(nativeProfile(before), nativeProfile(after)))
    result.push("native_profile_changed");
  if (
    [before, after].some(
      (file) =>
        file.tools.gitleaks.status === "error" ||
        file.tools.native.modes.some((mode) => mode.status === "error"),
    )
  )
    result.push("tool_failed");
  return result;
}
function missingChild(
  link: SubworkflowLink | undefined,
  addition: boolean,
): Reason[] {
  if (!link)
    return [
      addition ? "child_definition_added" : "child_definition_missing",
      "child_caller_unmatched",
    ];
  const reason: Partial<Record<SubworkflowLink["status"], Reason>> = {
    disabled: "child_disabled",
    invalid: "child_invalid",
    limit: "child_analysis_limit",
    cycle: "child_cycle",
  };
  return [
    addition ? "child_definition_added" : "child_definition_missing",
    ...(reason[link.status] ? [reason[link.status]!] : []),
  ];
}
function makePairs(
  before: Index,
  after: Index,
  global: Reason[],
): { pair: FilePair; before?: FileAssessment; after?: FileAssessment }[] {
  return [...new Set([...before.files.keys(), ...after.files.keys()])]
    .sort()
    .map((route) => {
      const left = before.files.get(route),
        right = after.files.get(route);
      const correspondence: FilePair["correspondence"] = !left
        ? "after_only"
        : !right
          ? "before_only"
          : route === "[]"
            ? "root"
            : left.inputSha256 === right.inputSha256
              ? "same_child_hash"
              : "changed_child_hash";
      let codes = [...global];
      if (left && right) codes.push(...fileReasons(left, right));
      if (correspondence === "changed_child_hash")
        codes.push("child_definition_changed");
      if (!left) codes.push(...missingChild(before.links.get(route), true));
      if (!right) codes.push(...missingChild(after.links.get(route), false));
      // If a child of a changed child happens to have identical bytes, its caller
      // context has still changed. Do not match it through a different ancestor.
      const parts: string[] = JSON.parse(route) as string[];
      for (let length = 1; length < parts.length; length++) {
        const ancestor = JSON.stringify(parts.slice(0, length));
        if (
          before.files.get(ancestor)?.inputSha256 !==
          after.files.get(ancestor)?.inputSha256
        )
          codes.push("child_definition_changed");
      }
      codes = unique(codes);
      return {
        before: left,
        after: right,
        pair: {
          key: createHash("sha256")
            .update(`assessment-file-route:${route}`)
            .digest("hex"),
          before: fileRef(left),
          after: fileRef(right),
          correspondence,
          codes,
        },
      };
    });
}

function covers(outer: StaticLocation, inner: StaticLocation): boolean {
  if (outer.nodeKey === null && outer.pointer === "") return true;
  if (
    outer.nodeKey === null &&
    outer.pointer === "/nodes" &&
    inner.nodeKey !== null
  )
    return true;
  if (outer.nodeKey !== inner.nodeKey) return false;
  const parent = field(outer),
    child = field(inner);
  return child === parent || child.startsWith(parent + "/");
}
function checked(rule: RuleResult, location: StaticLocation): boolean {
  const touching = rule.coverage.filter(
    (item) =>
      covers(item.location, location) || covers(location, item.location),
  );
  return (
    touching.some(
      (item) => item.status === "checked" && covers(item.location, location),
    ) &&
    !touching.some(
      (item) => item.status === "partial" || item.status === "unsupported",
    )
  );
}
function coverageKey(rule: RuleResult): string {
  return canonical(
    rule.coverage
      .map((item) => [
        scope(item.location),
        item.status,
        item.diagnosticIds
          .map((id) =>
            rule.diagnostics.find((diagnostic) => diagnostic.id === id),
          )
          .filter((item) => item !== undefined)
          .map((item) => [item.code, scope(item.location)])
          .sort(),
      ])
      .sort(),
  );
}
function nodeReasons(
  finding: Finding,
  before: FileAssessment,
  after: FileAssessment,
  addition: boolean,
): Reason[] {
  const result: Reason[] = [];
  const locations = [
    finding.location,
    ...finding.evidence.map((item) => item.location),
  ];
  const seen = new Set<string>();
  for (const location of locations) {
    if (location.nodeKey === null || seen.has(location.nodeKey)) continue;
    seen.add(location.nodeKey);
    const primary = location.nodeKey === finding.location.nodeKey;
    const left = before.functionSummary?.nodes.find(
      (node) => node.nodeKey === location.nodeKey,
    );
    const right = after.functionSummary?.nodes.find(
      (node) => node.nodeKey === location.nodeKey,
    );
    if (!left || !right) {
      result.push(
        primary
          ? addition
            ? "node_added"
            : "node_removed"
          : addition
            ? "evidence_node_added"
            : "evidence_node_removed",
      );
      if (
        left?.identity === "name_derived" ||
        right?.identity === "name_derived"
      )
        result.push("node_identity_unmatched");
      continue;
    }
    if (left.disabled || right.disabled)
      result.push(primary ? "node_disabled" : "evidence_node_disabled");
    if (left.identity !== right.identity)
      result.push("node_identity_kind_changed");
    if (left.kind !== right.kind) result.push("node_kind_changed");
  }
  return unique(result);
}
function derivedIdentity(finding: Finding, file: FileAssessment): Reason[] {
  return file.functionSummary?.nodes.some(
    (node) =>
      node.nodeKey === finding.location.nodeKey &&
      node.identity === "name_derived",
  )
    ? ["name_derived_identity"]
    : [];
}
function pathChanged(
  finding: Finding,
  before: FileAssessment,
  after: FileAssessment,
): boolean {
  const hasPath =
    finding.claim === "supported_path" ||
    finding.evidence.some(
      (item) =>
        item.location.nodeKey !== null &&
        item.location.nodeKey !== finding.location.nodeKey,
    );
  return (
    hasPath &&
    !same(
      before.functionSummary?.edges.map(canonical).sort(),
      after.functionSummary?.edges.map(canonical).sort(),
    )
  );
}
function policyDetails(file: FileAssessment, finding: Finding): unknown {
  const item = file.policy.findingDecisions.find(
    (decision) => decision.findingId === finding.id,
  );
  return item
    ? [item.decision, [...item.codes].sort(), item.exceptionKey]
    : null;
}
function compareEntry(
  pair: FilePair,
  before: FileAssessment | undefined,
  after: FileAssessment | undefined,
  oldFinding: Finding | undefined,
  newFinding: Finding | undefined,
): Entry {
  const finding = oldFinding ?? newFinding!;
  const entry: Entry = {
    filePairKey: pair.key,
    before: oldFinding ? observation(oldFinding) : null,
    after: newFinding ? observation(newFinding) : null,
    status: "inconclusive",
    detailsChanged: false,
    codes: [...pair.codes],
  };
  if (!before || !after) return entry;
  const oldRule = rules(before).find((rule) => rule.ruleId === finding.ruleId);
  const newRule = rules(after).find((rule) => rule.ruleId === finding.ruleId);
  if (!oldRule || !newRule) entry.codes.push("rule_missing");
  else if (
    oldRule.profileVersion !== newRule.profileVersion ||
    oldRule.category !== newRule.category
  )
    entry.codes.push("rule_profile_changed");
  entry.codes.push(
    ...nodeReasons(finding, before, after, oldFinding === undefined),
  );
  if (oldFinding && newFinding) {
    entry.detailsChanged =
      !same(details(oldFinding), details(newFinding)) ||
      !same(
        policyDetails(before, oldFinding),
        policyDetails(after, newFinding),
      );
    if (!entry.codes.length) entry.status = "persisting";
    entry.codes.push("observation_present_both");
    if (entry.detailsChanged) entry.codes.push("observation_details_changed");
  } else if (oldRule && newRule) {
    if (coverageKey(oldRule) !== coverageKey(newRule))
      entry.codes.push("coverage_changed");
    if (
      !checked(oldRule, finding.location) ||
      !checked(newRule, finding.location)
    )
      entry.codes.push("scope_not_checked");
    if (pathChanged(finding, before, after))
      entry.codes.push("analysis_path_changed");
    if (!entry.codes.length) {
      entry.status = oldFinding ? "not_observed" : "newly_observed";
      entry.codes.push(
        oldFinding
          ? "observation_not_seen_in_checked_scope"
          : "observation_new_in_checked_scope",
      );
    }
  }
  entry.codes.push(...derivedIdentity(finding, oldFinding ? before : after));
  entry.codes = unique(entry.codes);
  return entry;
}

function failure(
  before: string | null,
  after: string | null,
  codes: Reason[],
  available?: { side: "before" | "after"; report: Success },
): AssessmentComparison {
  const result: AssessmentComparison = {
    comparisonVersion: "1.0.0",
    status: "inconclusive",
    basis: "incompatible_or_failed",
    beforeSha256: before,
    afterSha256: after,
    scope: "all_reported_static_findings",
    execution: "not_run",
    behaviorPreserved: "not_verified",
    exploitBlocked: "not_verified",
    securityEquivalent: "not_claimed",
    files: [],
    rechecks: [],
    newFindings: [],
    counts: counts([]),
    codes: unique(codes),
  };
  // A failed recheck must not make all the valid baseline observations vanish
  // from the UI. Retain the validated side as inconclusive when possible.
  const indexed = available ? index(available.report) : undefined;
  if (!available || !indexed || !knownRules(available.report)) return result;
  for (const [route, file] of indexed.files) {
    const pair: FilePair = {
      key: createHash("sha256")
        .update(`assessment-file-route:${route}`)
        .digest("hex"),
      before: available.side === "before" ? fileRef(file) : null,
      after: available.side === "after" ? fileRef(file) : null,
      correspondence:
        available.side === "before" ? "before_only" : "after_only",
      codes: result.codes,
    };
    result.files.push(pair);
    const entries =
      available.side === "before" ? result.rechecks : result.newFindings;
    for (const finding of rules(file).flatMap((rule) => rule.findings)) {
      entries.push({
        filePairKey: pair.key,
        before: available.side === "before" ? observation(finding) : null,
        after: available.side === "after" ? observation(finding) : null,
        status: "inconclusive",
        detailsChanged: false,
        codes: result.codes,
      });
    }
  }
  result.counts = counts([...result.rechecks, ...result.newFindings]);
  if (
    result.rechecks.length + result.newFindings.length >
      assessmentComparisonLimits.rows ||
    Buffer.byteLength(JSON.stringify(result)) >
      assessmentComparisonLimits.resultBytes
  )
    return failure(before, after, [...codes, "comparison_output_limit"]);
  return assessmentComparisonSchema.parse(result);
}

function knownRules(report: Success): boolean {
  return report.files.every((file) => {
    const all = rules(file);
    return (
      new Set(all.map((rule) => rule.ruleId)).size === all.length &&
      all.every((rule) => ruleIdSchema.safeParse(rule.ruleId).success)
    );
  });
}

/** Compare validated observations, never execution outcomes or exploit blocking. */
export function compareAssessment(
  beforeValue: unknown,
  afterValue: unknown,
): AssessmentComparison {
  const before = assessmentReportSchema.safeParse(beforeValue);
  const after = assessmentReportSchema.safeParse(afterValue);
  const beforeHash = before.success ? before.data.inputSha256 : null;
  const afterHash = after.success ? after.data.inputSha256 : null;
  if (!before.success || !after.success)
    return failure(
      beforeHash,
      afterHash,
      [
        ...(!before.success ? ["invalid_before_report" as const] : []),
        ...(!after.success ? ["invalid_after_report" as const] : []),
      ],
      before.success && before.data.status !== "error"
        ? { side: "before", report: before.data }
        : after.success && after.data.status !== "error"
          ? { side: "after", report: after.data }
          : undefined,
    );
  if (before.data.status === "error" || after.data.status === "error")
    return failure(
      beforeHash,
      afterHash,
      [
        ...(before.data.status === "error"
          ? ["before_assessment_failed" as const]
          : []),
        ...(after.data.status === "error"
          ? ["after_assessment_failed" as const]
          : []),
      ],
      before.data.status !== "error"
        ? { side: "before", report: before.data }
        : after.data.status !== "error"
          ? { side: "after", report: after.data }
          : undefined,
    );
  const baseline = before.data,
    candidate = after.data;
  if (!knownRules(baseline) || !knownRules(candidate))
    return failure(beforeHash, afterHash, ["unsupported_rule_set"]);
  const left = index(baseline),
    right = index(candidate);
  if (!left || !right)
    return failure(beforeHash, afterHash, ["ambiguous_file_correspondence"]);
  const global: Reason[] = [];
  if (baseline.engineVersion !== candidate.engineVersion)
    global.push("assessment_engine_changed");
  if (baseline.assessmentVersion !== candidate.assessmentVersion)
    global.push("assessment_contract_changed");
  if (!same(baseline.boundary, candidate.boundary))
    global.push("isolation_boundary_changed");
  const paired = makePairs(left, right, global);
  const rechecks: Entry[] = [],
    newFindings: Entry[] = [];
  for (const { pair, before: oldFile, after: newFile } of paired) {
    const oldFindings = oldFile
      ? rules(oldFile).flatMap((rule) => rule.findings)
      : [];
    const newByKey = new Map(
      (newFile ? rules(newFile).flatMap((rule) => rule.findings) : []).map(
        (finding) => [fingerprint(finding), finding],
      ),
    );
    for (const finding of oldFindings) {
      const next = newByKey.get(fingerprint(finding));
      rechecks.push(compareEntry(pair, oldFile, newFile, finding, next));
      if (next) newByKey.delete(fingerprint(finding));
    }
    for (const finding of newByKey.values())
      newFindings.push(
        compareEntry(pair, oldFile, newFile, undefined, finding),
      );
  }
  const entries = [...rechecks, ...newFindings];
  if (entries.length > assessmentComparisonLimits.rows)
    return failure(beforeHash, afterHash, ["comparison_output_limit"]);
  const files = paired.map((item) => item.pair);
  const result: AssessmentComparison = {
    comparisonVersion: "1.0.0",
    status:
      entries.some((entry) => entry.status === "inconclusive") ||
      files.some((pair) => pair.codes.length)
        ? "inconclusive"
        : "compared",
    basis: global.length
      ? "incompatible_or_failed"
      : beforeHash === afterHash
        ? "same_input"
        : "same_assessment_contract",
    beforeSha256: beforeHash,
    afterSha256: afterHash,
    scope: "all_reported_static_findings",
    execution: "not_run",
    behaviorPreserved: "not_verified",
    exploitBlocked: "not_verified",
    securityEquivalent: "not_claimed",
    files,
    rechecks,
    newFindings,
    counts: counts(entries),
    codes: global,
  };
  if (
    Buffer.byteLength(JSON.stringify(result)) >
    assessmentComparisonLimits.resultBytes
  )
    return failure(beforeHash, afterHash, ["comparison_output_limit"]);
  return assessmentComparisonSchema.parse(result);
}
