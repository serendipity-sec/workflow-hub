import { createHash } from "node:crypto";
import { z } from "zod";
import { categories } from "../contracts/static-contract.js";

export const evidenceLimits = {
  bytes: 1024 * 1024,
  depth: 48,
  subworkflows: 8,
  subworkflowBytes: 256 * 1024,
} as const;
const opaque = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/);
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const text = z.string().min(1).max(2048);
const version = z.string().min(1).max(128);
const timestamp = z.iso.datetime();
const sourceId = opaque;
const packageName = z
  .string()
  .max(214)
  .regex(/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/);
const dataClassSchema = z.enum([
  "public",
  "internal",
  "personal",
  "secret",
  "unknown",
]);
const sinkSchema = z.enum([
  "http",
  "email",
  "slack",
  "telegram",
  "notion",
  "google_docs",
  "google_sheets",
  "airtable",
  "whatsapp",
  "gemini",
  "openai",
  "response",
  "log",
  "ai_tool",
  "ai_model",
  "ai_vector_store",
]);
const publicUrl = z
  .url()
  .max(2048)
  .refine((value) => {
    const url = URL.parse(value);
    return url?.protocol === "https:" && !url.username && !url.password;
  });

export const evidenceSourceSchema = z
  .strictObject({
    id: opaque,
    kind: z.enum(["declaration", "supplied_observation"]),
    method: z.enum([
      "user_declaration",
      "instance_export",
      "package_inventory",
      "official_advisory_snapshot",
      "manual_review",
      "synthetic_test_receipt",
    ]),
    recordedAt: timestamp,
    artifactSha256: hash.optional(),
  })
  .refine(
    (source) =>
      source.kind !== "supplied_observation" ||
      source.artifactSha256 !== undefined,
    { message: "Observation artifact digest required" },
  );

export const destinationPolicySchema = z.strictObject({
  id: opaque,
  nodeKey: hash,
  sink: sinkSchema,
  mode: z.enum(["allowlist", "denylist"]),
  destinations: z.array(text).max(128),
  allowedDataClasses: z.array(dataClassSchema).min(1).max(5),
  purpose: z.string().min(1).max(512),
});
export const assessmentPolicySchema = z.strictObject({
  id: opaque,
  version,
  sourceId,
  purpose: z.string().min(1).max(512),
  defaultDecision: z.enum(["allow", "review", "block"]),
  unknownDecision: z.enum(["review", "block", "inconclusive"]),
  rules: z
    .array(
      z.strictObject({
        category: z.enum(categories),
        minimumSeverity: z.enum(["info", "low", "medium", "high"]),
        decision: z.enum(["review", "block"]),
      }),
    )
    .max(40)
    .default([]),
  egress: z.array(destinationPolicySchema).max(64).default([]),
  exceptions: z
    .array(
      z
        .strictObject({
          id: opaque,
          findingId: hash,
          inputSha256: hash,
          decision: z.enum(["allow", "review"]),
          kind: z.enum(["false_positive", "risk_acceptance"]),
          subjectId: opaque,
          reasonCode: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
          sourceId,
          approvedAt: timestamp,
          expiresAt: timestamp,
        })
        .refine(
          (entry) => Date.parse(entry.approvedAt) < Date.parse(entry.expiresAt),
          { message: "Invalid exception interval" },
        ),
    )
    .max(32)
    .default([]),
  requireAuthenticatedWebhook: z.boolean().default(true),
  requireAiApproval: z.boolean().default(true),
  requirePublicationReview: z.boolean().default(true),
});

const osvEvent = z.union([
  z.strictObject({ introduced: version }),
  z.strictObject({ fixed: version }),
  z.strictObject({ last_affected: version }),
  z.strictObject({ limit: version }),
]);
// OSV allows additional descriptive fields. They are discarded rather than
// interpreted or copied to reports; supported matching fields stay bounded.
export const osvDocumentSchema = z.object({
  schema_version: version.optional(),
  id: z.string().regex(/^[A-Za-z0-9:_.-]{1,160}$/),
  modified: timestamp,
  withdrawn: timestamp.optional(),
  affected: z
    .array(
      z.object({
        package: z.object({
          ecosystem: z.string().max(64),
          name: z.string().max(214),
        }),
        versions: z.array(version).max(256).default([]),
        ranges: z
          .array(
            z.object({
              type: z.enum(["SEMVER", "ECOSYSTEM", "GIT"]),
              events: z.array(osvEvent).min(1).max(128),
            }),
          )
          .max(32)
          .default([]),
      }),
    )
    .min(1)
    .max(32),
});

export const assessmentEvidenceSchema = z.strictObject({
  schemaVersion: z.literal("1.0.0"),
  inputSha256: hash,
  sources: z.array(evidenceSourceSchema).max(64).default([]),
  provenance: z
    .strictObject({
      sourceId,
      platform: z.string().min(1).max(128),
      sourceUrl: publicUrl,
      templateId: z.string().min(1).max(256).optional(),
      commit: z
        .string()
        .regex(/^[0-9a-f]{40,64}$/)
        .optional(),
      collectedAt: timestamp,
      license: z
        .strictObject({
          identifier: z.string().min(1).max(128),
          redistribution: z.enum(["allowed", "restricted", "unknown"]),
          evidenceUrl: publicUrl,
        })
        .optional(),
    })
    .optional(),
  policy: assessmentPolicySchema.optional(),
  runtime: z
    .strictObject({
      sourceId,
      environmentId: opaque,
      n8nVersion: version,
      credentialScopes: z
        .array(
          z.strictObject({
            nodeKey: hash,
            scopes: z.array(z.string().min(1).max(128)).max(64),
            sourceId,
          }),
        )
        .max(64)
        .default([]),
      networkControls: z
        .array(
          z.strictObject({
            kind: z.enum([
              "private_egress_block",
              "redirect_validation",
              "dns_validation",
            ]),
            enabled: z.boolean(),
            sourceId,
          }),
        )
        .max(3)
        .default([]),
      upstreamAuthentication: z
        .array(
          z.strictObject({
            nodeKey: hash,
            kind: z.enum(["none", "basic", "header", "jwt", "mtls"]),
            enforced: z.boolean(),
            sourceId,
          }),
        )
        .max(64)
        .default([]),
    })
    .optional(),
  packages: z
    .array(
      z.strictObject({
        name: packageName,
        version,
        nodeKeys: z.array(hash).max(64).default([]),
        integrity: hash.optional(),
        sourceId,
      }),
    )
    .max(64)
    .default([]),
  advisories: z
    .array(z.strictObject({ sourceId, document: osvDocumentSchema }))
    .max(128)
    .default([]),
  subworkflows: z
    .array(
      z.strictObject({
        parentInputSha256: hash,
        callerNodeKey: hash,
        reference: text,
        inputSha256: hash,
        content: z.string().min(1).max(evidenceLimits.subworkflowBytes),
        workflowVersionId: opaque,
        sourceId,
      }),
    )
    .max(evidenceLimits.subworkflows)
    .default([]),
  classifications: z
    .array(
      z.strictObject({
        nodeKey: hash,
        field: z.string().max(256),
        dataClass: dataClassSchema,
        sourceId,
      }),
    )
    .max(256)
    .default([]),
  aiApprovals: z
    .array(
      z.strictObject({
        nodeKey: hash,
        required: z.boolean(),
        toolNodeKeys: z.array(hash).max(64),
        sourceId,
      }),
    )
    .max(64)
    .default([]),
  syntheticReceipts: z
    .array(
      z.strictObject({
        inputSha256: hash,
        environmentId: opaque,
        sourceId,
        recordedAt: timestamp,
        cases: z
          .array(
            z.strictObject({
              caseId: opaque,
              attackBlocked: z.boolean(),
              normalBehaviorPreserved: z.boolean(),
            }),
          )
          .min(1)
          .max(32),
      }),
    )
    .max(16)
    .default([]),
  publicationReview: z
    .strictObject({
      inputSha256: hash,
      sourceId,
      reviewId: opaque,
      reviewerId: opaque,
      status: z.enum(["approved", "rejected", "pending"]),
      recordedAt: timestamp,
      expiresAt: timestamp,
      scopes: z
        .array(
          z.enum([
            "secrets",
            "pii",
            "internal_addresses",
            "account_references",
          ]),
        )
        .max(4),
      policyId: opaque,
      policyVersion: version,
    })
    .optional(),
});

export type DataClass = z.infer<typeof dataClassSchema>;
export type SinkKind = z.infer<typeof sinkSchema>;
export type EvidenceSource = z.infer<typeof evidenceSourceSchema>;
export type AssessmentPolicy = z.infer<typeof assessmentPolicySchema>;
export type DestinationPolicy = z.infer<typeof destinationPolicySchema>;
export type AssessmentEvidence = z.infer<typeof assessmentEvidenceSchema>;
export type OsvDocument = z.infer<typeof osvDocumentSchema>;

export class AssessmentEvidenceError extends Error {
  constructor(
    readonly code:
      | "invalid_evidence"
      | "evidence_input_mismatch"
      | "duplicate_evidence"
      | "unknown_evidence_source"
      | "subworkflow_hash_mismatch"
      | "evidence_limit",
  ) {
    super(code);
  }
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
function unique(values: string[]): void {
  if (new Set(values).size !== values.length)
    throw new AssessmentEvidenceError("duplicate_evidence");
}

/** Dotted convenience paths and JSON Pointers share one classification scope. */
export function canonicalEvidenceField(field: string): string {
  if (field.startsWith("/") && /~(?:[^01]|$)/.test(field))
    throw new AssessmentEvidenceError("invalid_evidence");
  const parts = field.startsWith("/")
    ? field
        .slice(1)
        .split("/")
        .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    : field === ""
      ? []
      : field.split(".");
  if (
    parts.length > 32 ||
    parts.some(
      (part) =>
        part.length > 256 ||
        ["__proto__", "prototype", "constructor"].includes(part),
    )
  )
    throw new AssessmentEvidenceError("invalid_evidence");
  return parts.length
    ? "/" +
        parts
          .map((part) => part.replace(/~/g, "~0").replace(/\//g, "~1"))
          .join("/")
    : "";
}

export function parseEvidence(
  value: unknown,
  inputSha256: string,
): AssessmentEvidence {
  let size: number;
  try {
    size = Buffer.byteLength(JSON.stringify(value));
  } catch {
    throw new AssessmentEvidenceError("invalid_evidence");
  }
  if (size > evidenceLimits.bytes)
    throw new AssessmentEvidenceError("evidence_limit");
  const parsed = assessmentEvidenceSchema.safeParse(value);
  if (!parsed.success) throw new AssessmentEvidenceError("invalid_evidence");
  const evidence = parsed.data;
  if (evidence.inputSha256 !== inputSha256)
    throw new AssessmentEvidenceError("evidence_input_mismatch");
  unique(evidence.sources.map(({ id }) => id));
  unique(evidence.packages.map(({ name }) => name));
  for (const pkg of evidence.packages) unique(pkg.nodeKeys);
  unique(evidence.advisories.map(({ document }) => document.id));
  for (const annotation of evidence.classifications)
    annotation.field = canonicalEvidenceField(annotation.field);
  unique(
    evidence.classifications.map(({ nodeKey, field }) =>
      JSON.stringify([nodeKey, field]),
    ),
  );
  unique(evidence.aiApprovals.map(({ nodeKey }) => nodeKey));
  for (const approval of evidence.aiApprovals) unique(approval.toolNodeKeys);
  unique(
    evidence.subworkflows.map(
      ({ parentInputSha256, callerNodeKey }) =>
        `${parentInputSha256}:${callerNodeKey}`,
    ),
  );
  unique(evidence.policy?.egress.map(({ id }) => id) ?? []);
  unique(
    evidence.policy?.egress.map(({ nodeKey, sink }) => `${nodeKey}:${sink}`) ??
      [],
  );
  unique(evidence.policy?.exceptions.map(({ id }) => id) ?? []);
  unique(
    evidence.policy?.exceptions.map(
      ({ findingId, inputSha256 }) => `${inputSha256}:${findingId}`,
    ) ?? [],
  );
  unique(evidence.runtime?.networkControls.map(({ kind }) => kind) ?? []);
  unique(
    evidence.runtime?.credentialScopes.map(({ nodeKey }) => nodeKey) ?? [],
  );
  unique(
    evidence.runtime?.upstreamAuthentication.map(({ nodeKey }) => nodeKey) ??
      [],
  );
  unique(
    evidence.syntheticReceipts.map(
      ({ inputSha256, environmentId, sourceId }) =>
        `${inputSha256}:${environmentId}:${sourceId}`,
    ),
  );
  for (const receipt of evidence.syntheticReceipts)
    unique(receipt.cases.map(({ caseId }) => caseId));
  const sources = new Set(evidence.sources.map(({ id }) => id));
  const references = [
    evidence.provenance?.sourceId,
    evidence.policy?.sourceId,
    evidence.runtime?.sourceId,
    evidence.publicationReview?.sourceId,
    ...evidence.packages.map(({ sourceId }) => sourceId),
    ...evidence.advisories.map(({ sourceId }) => sourceId),
    ...evidence.subworkflows.map(({ sourceId }) => sourceId),
    ...evidence.classifications.map(({ sourceId }) => sourceId),
    ...evidence.aiApprovals.map(({ sourceId }) => sourceId),
    ...evidence.syntheticReceipts.map(({ sourceId }) => sourceId),
    ...(evidence.policy?.exceptions.map(({ sourceId }) => sourceId) ?? []),
    ...(evidence.runtime?.credentialScopes.map(({ sourceId }) => sourceId) ??
      []),
    ...(evidence.runtime?.networkControls.map(({ sourceId }) => sourceId) ??
      []),
    ...(evidence.runtime?.upstreamAuthentication.map(
      ({ sourceId }) => sourceId,
    ) ?? []),
  ];
  if (references.some((id) => id !== undefined && !sources.has(id)))
    throw new AssessmentEvidenceError("unknown_evidence_source");
  const workflowHashes = new Set([
    inputSha256,
    ...evidence.subworkflows.map(({ inputSha256 }) => inputSha256),
  ]);
  for (const child of evidence.subworkflows) {
    if (!workflowHashes.has(child.parentInputSha256))
      throw new AssessmentEvidenceError("evidence_input_mismatch");
    if (Buffer.byteLength(child.content) > evidenceLimits.subworkflowBytes)
      throw new AssessmentEvidenceError("evidence_limit");
    if (digest(child.content) !== child.inputSha256)
      throw new AssessmentEvidenceError("subworkflow_hash_mismatch");
  }
  return evidence;
}

/** Duplicate keys and ambiguous/deep JSON are rejected before policy use. */
export function parseEvidenceBytes(
  bytes: Buffer,
  inputSha256: string,
): AssessmentEvidence {
  if (bytes.length > evidenceLimits.bytes)
    throw new AssessmentEvidenceError("evidence_limit");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new AssessmentEvidenceError("invalid_evidence");
  }
  const stack: { object: boolean; expectKey: boolean; keys: Set<string> }[] =
    [];
  try {
    for (let index = 0; index < text.length; index++) {
      const char = text[index];
      if (char === '"') {
        const start = index;
        while (++index < text.length) {
          if (text[index] === "\\") index++;
          else if (text[index] === '"') break;
        }
        const current = stack.at(-1);
        if (current?.object && current.expectKey) {
          const key = JSON.parse(text.slice(start, index + 1)) as string;
          if (current.keys.has(key))
            throw new AssessmentEvidenceError("duplicate_evidence");
          current.keys.add(key);
          current.expectKey = false;
        }
      } else if (char === "{" || char === "[") {
        stack.push({
          object: char === "{",
          expectKey: char === "{",
          keys: new Set(),
        });
        if (stack.length > evidenceLimits.depth)
          throw new AssessmentEvidenceError("evidence_limit");
      } else if (char === "}" || char === "]") stack.pop();
      else if (char === "," && stack.at(-1)?.object)
        stack.at(-1)!.expectKey = true;
    }
    return parseEvidence(JSON.parse(text), inputSha256);
  } catch (error) {
    if (error instanceof AssessmentEvidenceError) throw error;
    throw new AssessmentEvidenceError("invalid_evidence");
  }
}

export const evidenceSummarySchema = z
  .strictObject({
    status: z.enum(["not_provided", "provided"]),
    independentlyVerified: z.literal(false),
    normalizedSha256: hash.nullable(),
    sources: z
      .array(
        z.strictObject({
          sourceKey: hash,
          kind: z.enum(["declaration", "supplied_observation"]),
          method: z.enum([
            "user_declaration",
            "instance_export",
            "package_inventory",
            "official_advisory_snapshot",
            "manual_review",
            "synthetic_test_receipt",
          ]),
          recordedAt: timestamp,
          artifactSha256: hash.nullable(),
        }),
      )
      .max(64),
    syntheticReceipts: z
      .array(
        z.strictObject({
          inputSha256: hash,
          environmentKey: hash,
          sourceKey: hash,
          kind: z.enum(["declaration", "supplied_observation"]),
          recordedAt: timestamp,
          scope: z.enum(["assessed_file", "other_file"]),
          cases: z
            .array(
              z.strictObject({
                caseKey: hash,
                attackBlocked: z.boolean(),
                normalBehaviorPreserved: z.boolean(),
              }),
            )
            .min(1)
            .max(32),
        }),
      )
      .max(16),
  })
  .refine(
    (value) => {
      if (value.status === "not_provided")
        return (
          value.normalizedSha256 === null &&
          value.sources.length === 0 &&
          value.syntheticReceipts.length === 0
        );
      if (
        value.normalizedSha256 === null ||
        new Set(value.sources.map(({ sourceKey }) => sourceKey)).size !==
          value.sources.length
      )
        return false;
      return value.syntheticReceipts.every(
        (receipt) =>
          value.sources.some(
            (source) =>
              source.sourceKey === receipt.sourceKey &&
              source.kind === receipt.kind,
          ) &&
          new Set(receipt.cases.map(({ caseKey }) => caseKey)).size ===
            receipt.cases.length,
      );
    },
    { message: "Inconsistent evidence summary" },
  );
export type EvidenceSummary = z.infer<typeof evidenceSummarySchema>;

export function evidenceSummary(
  evidence: AssessmentEvidence | undefined,
): EvidenceSummary {
  if (!evidence)
    return {
      status: "not_provided",
      independentlyVerified: false,
      sources: [],
      normalizedSha256: null,
      syntheticReceipts: [],
    };
  return {
    status: "provided" as const,
    independentlyVerified: false as const,
    normalizedSha256: digest(JSON.stringify(evidence)),
    sources: evidence.sources.map(
      ({ id, kind, method, recordedAt, artifactSha256 }) => ({
        sourceKey: digest(`source:${id}`),
        kind,
        method,
        recordedAt,
        artifactSha256: artifactSha256 ?? null,
      }),
    ),
    syntheticReceipts: evidence.syntheticReceipts.map((receipt) => ({
      inputSha256: receipt.inputSha256,
      environmentKey: digest(`environment:${receipt.environmentId}`),
      sourceKey: digest(`source:${receipt.sourceId}`),
      kind: evidence.sources.find(({ id }) => id === receipt.sourceId)!.kind,
      recordedAt: receipt.recordedAt,
      scope:
        receipt.inputSha256 === evidence.inputSha256
          ? "assessed_file"
          : "other_file",
      cases: receipt.cases.map(
        ({ caseId, attackBlocked, normalBehaviorPreserved }) => ({
          caseKey: digest(`case:${caseId}`),
          attackBlocked,
          normalBehaviorPreserved,
        }),
      ),
    })),
  };
}

export { assessDestination } from "./assessment-policy.js";
