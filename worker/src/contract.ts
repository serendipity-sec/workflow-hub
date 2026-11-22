import { z } from "zod";

export const versions = {
  contract: "1.0.0",
  engine: "0.1.1",
  rules: "0.1.0",
  adapter: "n8n@2.48.7/workflow-json@1",
} as const;

export const limits = {
  fileBytes: 256 * 1024,
  depth: 32,
  nodes: 64,
  edges: 128,
  resultBytes: 128 * 1024,
  apiTimeoutMs: 5_000,
  analysisTimeoutMs: 3_000,
  subprocessHeapMiB: 96,
  productionMemoryMiB: 256,
  productionCpuCount: 1,
  productionPids: 32,
} as const;

const opaqueId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/);
const hash = z.string().regex(/^[0-9a-f]{64}$/);
const pointer = z
  .string()
  .regex(/^\/(?:[A-Za-z0-9_/-]|~[01])*$/)
  .max(512);
const downloadUrl = z
  .url()
  .max(4096)
  .refine((value) => {
    const url = URL.parse(value);
    if (!url || url.username || url.password || url.hash) return false;
    return (
      url.protocol === "https:" ||
      /^http:\/\/(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:[/?]|$)/.test(value)
    );
  });
export const identityFields = {
  taskId: opaqueId,
  attemptId: opaqueId,
  workflowVersionId: opaqueId,
  inputSha256: hash,
};
export const identitySchema = z.strictObject(identityFields);
export const fileSourceSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("local"),
    path: z.string().min(1).max(4096),
  }),
  z.strictObject({ kind: z.literal("download"), url: downloadUrl }),
]);
export const taskSchema = z.strictObject({
  ...identityFields,
  contractVersion: z.literal(versions.contract),
  leaseExpiresAt: z.iso.datetime(),
  file: fileSourceSchema,
});

export const resultVersionFields = {
  contractVersion: z.literal(versions.contract),
  engineVersion: z.literal(versions.engine),
  rulesVersion: z.literal(versions.rules),
  adapterVersion: z.literal(versions.adapter),
};
export const resultVersions = {
  contractVersion: versions.contract,
  engineVersion: versions.engine,
  rulesVersion: versions.rules,
  adapterVersion: versions.adapter,
};

export const diagnosticCodes = [
  "unsupported_node",
  "unsupported_version",
  "subworkflow_missing",
  "unsupported_config",
  "unsupported_expression",
  "unsupported_connection",
  "unsupported_topology",
  "no_supported_sink",
  "analysis_unavailable",
] as const;
export const errorCodes = [
  "file_not_found",
  "file_access",
  "file_too_large",
  "hash_mismatch",
  "invalid_utf8",
  "invalid_json",
  "duplicate_key",
  "depth_limit",
  "graph_limit",
  "invalid_workflow",
  "identity_collision",
  "broken_connection",
  "analyzer_timeout",
  "analyzer_output_limit",
  "analyzer_exit",
  "invalid_result",
  "cancelled",
  "isolation_unverified",
] as const;

export const locationSchema = z.strictObject({ nodeKey: hash, pointer });
const nodePath = /^\/nodes\/\d+$/;
const queryPath = /^(\/nodes\/\d+)\/parameters\/query$/;
const diagnosticSchema = z.strictObject({
  code: z.enum(diagnosticCodes),
  location: pointer,
  affected: z.array(hash).max(limits.nodes),
});
const scopedDiagnosticSchema = diagnosticSchema.extend({
  affected: z
    .array(
      z
        .int()
        .min(0)
        .max(limits.nodes - 1),
    )
    .max(limits.nodes),
});
const coverageSchema = z.strictObject({
  sink: locationSchema.extend({ pointer: pointer.regex(queryPath) }),
  disposition: z.enum([
    "interpolated",
    "bound",
    "constant",
    "guarded",
    "unknown",
  ]),
  inputKey: hash.nullable(),
  shapeKey: hash.nullable(),
});
const findingSchema = z
  .strictObject({
    id: hash,
    ruleId: z.literal("N8N_POSTGRES_DYNAMIC_QUERY"),
    source: locationSchema,
    sink: locationSchema,
    path: z.array(locationSchema).min(2).max(limits.nodes),
    reference: z.enum(["current_input", "direct_source"]),
    guard: z.enum(["absent", "unrelated_value", "reject_branch"]),
    assumptions: z.tuple([
      z.literal("single_json_webhook_item"),
      z.literal("pinned_node_semantics"),
    ]),
    remediation: z.strictObject({
      strategy: z.literal("use_value_parameter"),
      binding: locationSchema,
      checks: z.tuple([
        z.literal("fixed_sql_value_position"),
        z.literal("expected_rows_and_side_effects"),
        z.literal("rescan_same_rules"),
      ]),
    }),
  })
  .refine(
    ({ source, sink, path, remediation }) => {
      const queryNode = queryPath.exec(sink.pointer)?.[1];
      const first = path[0];
      const last = path.at(-1);
      return (
        queryNode !== undefined &&
        nodePath.test(source.pointer) &&
        first?.nodeKey === source.nodeKey &&
        first.pointer === source.pointer &&
        last?.nodeKey === sink.nodeKey &&
        last.pointer === sink.pointer &&
        new Set(path.map(({ nodeKey }) => nodeKey)).size === path.length &&
        path.slice(0, -1).every(({ pointer }) => nodePath.test(pointer)) &&
        remediation.binding.nodeKey === sink.nodeKey &&
        remediation.binding.pointer ===
          `${queryNode}/parameters/options/queryReplacement`
      );
    },
    { message: "Inconsistent finding locations" },
  );

const resultHeader = { ...identityFields, ...resultVersionFields };
export const resultSchema = z
  .discriminatedUnion("status", [
    z.strictObject({
      ...resultHeader,
      status: z.literal("analyzed"),
      coverage: z.array(coverageSchema).length(1),
      findings: z.array(findingSchema).max(1),
      diagnostics: z.tuple([]),
    }),
    z.strictObject({
      ...resultHeader,
      status: z.literal("unsupported"),
      coverage: z.array(coverageSchema).max(limits.nodes),
      findings: z.array(findingSchema).max(limits.nodes),
      affectedNodeKeys: z.array(hash).max(limits.nodes),
      diagnostics: z
        .array(scopedDiagnosticSchema)
        .min(1)
        .max(limits.edges + limits.nodes),
    }),
    z.strictObject({
      ...resultHeader,
      status: z.literal("error"),
      code: z.enum(errorCodes),
      location: pointer.optional(),
    }),
  ])
  .refine(
    (result) => {
      if (result.status === "error") return true;
      if (result.status === "unsupported") {
        const { affectedNodeKeys, diagnostics } = result;
        if (
          new Set(affectedNodeKeys).size !== affectedNodeKeys.length ||
          diagnostics.some(
            ({ affected }) =>
              new Set(affected).size !== affected.length ||
              affected.some((index) => index >= affectedNodeKeys.length),
          )
        )
          return false;
      }
      const sinks = new Set(result.coverage.map(({ sink }) => sink.nodeKey));
      const findings = new Set(result.findings.map(({ sink }) => sink.nodeKey));
      if (
        sinks.size !== result.coverage.length ||
        findings.size !== result.findings.length
      )
        return false;
      const interpolated = result.coverage.filter(
        ({ disposition }) => disposition === "interpolated",
      );
      if (interpolated.length !== findings.size) return false;
      return result.coverage.every(
        ({ sink, disposition, inputKey, shapeKey }) => {
          if (disposition === "unknown")
            return (
              result.status === "unsupported" &&
              inputKey === null &&
              shapeKey === null
            );
          if (
            shapeKey === null ||
            (inputKey === null) !== (disposition === "constant")
          )
            return false;
          return (
            disposition !== "interpolated" ||
            result.findings.some(
              (finding) =>
                finding.sink.nodeKey === sink.nodeKey &&
                finding.sink.pointer === sink.pointer,
            )
          );
        },
      );
    },
    { message: "Inconsistent analysis coverage" },
  );

export type Identity = z.infer<typeof identitySchema>;
export type Task = z.infer<typeof taskSchema>;
export type Result = z.infer<typeof resultSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type DiagnosticCode = (typeof diagnosticCodes)[number];
export type ErrorCode = (typeof errorCodes)[number];
export type Diagnostic = z.infer<typeof diagnosticSchema>;
export type Coverage = z.infer<typeof coverageSchema>;

export function identityOf(task: Identity): Identity {
  return {
    taskId: task.taskId,
    attemptId: task.attemptId,
    workflowVersionId: task.workflowVersionId,
    inputSha256: task.inputSha256,
  };
}
