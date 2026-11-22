import { createHash } from "node:crypto";
import { z } from "zod";
import { errorCodes, limits, versions } from "./contract.js";
import type { NormalizedNode } from "./n8n.js";

export const categories = [
  "secrets",
  "pii",
  "request_auth",
  "egress",
  "ssrf",
  "sql",
  "code_execution",
  "transport",
  "output",
  "dependencies",
] as const;

export const staticVersions = {
  contract: "2.0.0",
  engine: "0.2.0",
  rules: "0.2.0",
  adapter: versions.adapter,
} as const;

export const staticResultVersions = {
  contractVersion: staticVersions.contract,
  engineVersion: staticVersions.engine,
  rulesVersion: staticVersions.rules,
  adapterVersion: staticVersions.adapter,
} as const;

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const ruleId = z.string().regex(/^[A-Z][A-Z0-9_]{2,79}$/);
const code = z.string().regex(/^[a-z][a-z0-9_]{0,79}$/);
const profileVersion = z.string().regex(/^\d{1,3}\.\d{1,3}\.\d{1,3}$/);
const category = z.enum(categories);

// Report locations use known structural keys only. Raw JSON pointers and names
// remain in the internal Context; safeLocation coarsens an arbitrary key path.
export const staticLocationSchema = z
  .strictObject({
    nodeKey: hash.nullable(),
    pointer: z
      .string()
      .regex(/^(?:\/(?:[A-Za-z0-9_-]|~[01])*)*$/)
      .max(512),
  })
  .refine(
    ({ nodeKey, pointer }) => {
      const nodeIndex = /^\/nodes\/(0|[1-9][0-9]*)(?:\/|$)/.exec(pointer)?.[1];
      return nodeIndex === undefined
        ? nodeKey === null
        : nodeKey !== null && Number(nodeIndex) < limits.nodes;
    },
    { message: "Inconsistent static location" },
  );

const evidenceSchema = z.strictObject({
  code,
  location: staticLocationSchema,
});

export const staticFindingSchema = z.strictObject({
  id: hash,
  ruleId,
  category,
  severity: z.enum(["info", "low", "medium", "high"]),
  claim: z.enum(["configuration", "candidate", "supported_path"]),
  location: staticLocationSchema,
  evidence: z
    .array(evidenceSchema)
    .min(1)
    .max(limits.nodes + 4),
  assumptions: z.array(code).max(16),
  remediation: z.strictObject({
    code,
    checks: z.array(code).min(1).max(12),
  }),
});

export const staticDiagnosticSchema = z.strictObject({
  id: hash,
  code,
  location: staticLocationSchema,
});

export const staticCoverageSchema = z.strictObject({
  location: staticLocationSchema,
  status: z.enum(["checked", "partial", "unsupported", "not_applicable"]),
  findingIds: z.array(hash).max(256),
  diagnosticIds: z.array(hash).max(256),
});

export const ruleResultSchema = z
  .strictObject({
    ruleId,
    category,
    profileVersion,
    coverage: z.array(staticCoverageSchema).min(1).max(256),
    findings: z.array(staticFindingSchema).max(256),
    diagnostics: z.array(staticDiagnosticSchema).max(256),
  })
  .refine(
    (result) => {
      const findingIds = new Set(result.findings.map(({ id }) => id));
      const diagnosticIds = new Set(result.diagnostics.map(({ id }) => id));
      if (
        findingIds.size !== result.findings.length ||
        diagnosticIds.size !== result.diagnostics.length ||
        [...findingIds].some((id) => diagnosticIds.has(id)) ||
        result.findings.some(
          (finding) =>
            finding.ruleId !== result.ruleId ||
            finding.category !== result.category,
        )
      ) {
        return false;
      }
      const coveredFindings = new Set<string>();
      const coveredDiagnostics = new Set<string>();
      for (const coverage of result.coverage) {
        if (
          new Set(coverage.findingIds).size !== coverage.findingIds.length ||
          new Set(coverage.diagnosticIds).size !==
            coverage.diagnosticIds.length ||
          coverage.findingIds.some((id) => !findingIds.has(id)) ||
          coverage.diagnosticIds.some((id) => !diagnosticIds.has(id)) ||
          (coverage.status === "checked" &&
            coverage.diagnosticIds.length > 0) ||
          ((coverage.status === "partial" ||
            coverage.status === "unsupported") &&
            coverage.diagnosticIds.length === 0) ||
          (coverage.status === "not_applicable" &&
            (coverage.findingIds.length > 0 ||
              coverage.diagnosticIds.length > 0))
        ) {
          return false;
        }
        coverage.findingIds.forEach((id) => coveredFindings.add(id));
        coverage.diagnosticIds.forEach((id) => coveredDiagnostics.add(id));
      }
      return (
        coveredFindings.size === findingIds.size &&
        coveredDiagnostics.size === diagnosticIds.size
      );
    },
    { message: "Inconsistent rule coverage" },
  );

export type Category = (typeof categories)[number];
export type StaticLocation = z.infer<typeof staticLocationSchema>;
export type Evidence = z.infer<typeof evidenceSchema>;
export type Finding = z.infer<typeof staticFindingSchema>;
export type Diagnostic = z.infer<typeof staticDiagnosticSchema>;
export type Coverage = z.infer<typeof staticCoverageSchema>;
export type RuleResult = z.infer<typeof ruleResultSchema>;

export function reportStatus(
  rules: readonly RuleResult[],
): "analyzed" | "partial" | "unsupported" {
  const coverage = rules.flatMap((rule) => rule.coverage);
  const limited = coverage.some(
    ({ status }) => status === "partial" || status === "unsupported",
  );
  const inspected = coverage.some(
    ({ status }) => status === "checked" || status === "partial",
  );
  if (limited && !inspected) return "unsupported";
  return limited ? "partial" : "analyzed";
}

const reportHeader = {
  contractVersion: z.literal(staticVersions.contract),
  engineVersion: z.literal(staticVersions.engine),
  rulesVersion: z.literal(staticVersions.rules),
  adapterVersion: z.literal(staticVersions.adapter),
  inputSha256: hash,
  execution: z.literal("not_run"),
};

export const staticReportSchema = z
  .discriminatedUnion("status", [
    z.strictObject({
      ...reportHeader,
      status: z.enum(["analyzed", "partial", "unsupported"]),
      rules: z.array(ruleResultSchema).min(categories.length).max(64),
    }),
    z.strictObject({
      ...reportHeader,
      status: z.literal("error"),
      code: z.enum(errorCodes),
    }),
  ])
  .refine(
    (report) => {
      if (Buffer.byteLength(JSON.stringify(report)) > limits.resultBytes)
        return false;
      if (report.status === "error") return true;
      return (
        new Set(report.rules.map(({ ruleId }) => ruleId)).size ===
          report.rules.length &&
        new Set(report.rules.map(({ category }) => category)).size ===
          categories.length &&
        report.status === reportStatus(report.rules)
      );
    },
    { message: "Incomplete or inconsistent static report" },
  );

export type StaticReport = z.infer<typeof staticReportSchema>;
export type StaticReportSuccess = Exclude<StaticReport, { status: "error" }>;

export function locationFor(
  node: Pick<NormalizedNode, "key" | "pointer">,
  suffix = "",
): StaticLocation {
  return { nodeKey: node.key, pointer: node.pointer + suffix };
}

/** Never pass an uploaded value as the discriminator. It is a fixed rule code. */
export function stableId(
  rule: string,
  location: StaticLocation,
  discriminator = "",
): string {
  const field =
    location.nodeKey === null
      ? location.pointer
      : location.pointer.replace(/^\/nodes\/\d+(?=\/|$)/, "");
  return createHash("sha256")
    .update(JSON.stringify([rule, location.nodeKey, field, discriminator]))
    .digest("hex");
}
