import { createHash } from "node:crypto";
import { parseExpressionAt } from "acorn";
import { z } from "zod";
import { limits } from "../contracts/contract.js";
import { inspectSqlOperation } from "../rules/advanced-risks.js";
import type {
  SqlOperationDescription,
  SqlDialect,
} from "../rules/advanced-risks.js";
import { parseEvidence } from "./assessment-evidence.js";
import type { AssessmentEvidence } from "./assessment-evidence.js";
import { createContext, isObject } from "../workflow/static-context.js";
import type { Context, JsonObject } from "../workflow/static-context.js";
import {
  locationFor,
  stableId,
  staticLocationSchema,
} from "../contracts/static-contract.js";
import type { Finding, StaticLocation } from "../contracts/static-contract.js";
import type { NormalizedNode } from "../workflow/n8n.js";

const hash = z.string().regex(/^[0-9a-f]{64}$/);
const code = z.string().regex(/^[a-z][a-z0-9_]{0,79}$/);
const digest = (value: Buffer | string) =>
  createHash("sha256").update(value).digest("hex");
const root: StaticLocation = { nodeKey: null, pointer: "" };
const changeKinds = [
  "node_added",
  "node_removed",
  "node_enabled",
  "node_disabled",
  "node_type_changed",
  "node_version_changed",
  "authentication_changed",
  "destination_changed",
  "recipient_changed",
  "database_operation_changed",
  "capability_changed",
  "node_configuration_changed",
  "guard_changed",
  "connections_changed",
  "workflow_settings_changed",
  "environment_changed",
  "policy_changed",
  "packages_changed",
  "advisories_changed",
  "subworkflows_changed",
  "classifications_changed",
  "evidence_changed",
  "document_metadata_changed",
] as const;
export const definitionComparisonSchema = z
  .strictObject({
    contractVersion: z.literal("1.0.0"),
    beforeSha256: hash,
    afterSha256: hash,
    status: z.enum(["compared", "inconclusive"]),
    byteIdentity: z.enum(["same", "different"]),
    scope: z.literal("supported_declarations"),
    execution: z.literal("not_run"),
    behaviorPreserved: z.literal("not_verified"),
    securityEquivalent: z.literal("not_claimed"),
    changes: z
      .array(
        z.strictObject({
          id: hash,
          kind: z.enum(changeKinds),
          beforeLocation: staticLocationSchema.nullable(),
          afterLocation: staticLocationSchema.nullable(),
          codes: z.array(code).min(1).max(8),
          recheck: z.literal("required"),
        }),
      )
      .max(256),
    diagnostics: z.array(code).max(32),
  })
  .refine(
    (value) =>
      value.byteIdentity ===
        (value.beforeSha256 === value.afterSha256 ? "same" : "different") &&
      new Set(value.changes.map(({ id }) => id)).size ===
        value.changes.length &&
      new Set(value.diagnostics).size === value.diagnostics.length,
    { message: "Inconsistent definition comparison" },
  );
export type DefinitionComparison = z.infer<typeof definitionComparisonSchema>;
type ChangeKind = (typeof changeKinds)[number];

// Used only internally. Never return a per-value hash or serialized raw fragment.
function canonical(value: unknown): string {
  function sorted(item: unknown): unknown {
    if (Array.isArray(item)) return item.map(sorted);
    if (isObject(item))
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((key) => [key, sorted(item[key])]),
      );
    return item;
  }
  return JSON.stringify(sorted(value)) ?? "undefined";
}
const changed = (left: unknown, right: unknown) =>
  canonical(left) !== canonical(right);
const selected = (object: JsonObject, keys: readonly string[]) =>
  keys.map((key) => object[key]);
const supportedHttp = (node: NormalizedNode) =>
  node.type === "n8n-nodes-base.httpRequest" &&
  [3, 4, 4.1, 4.2, 4.3, 4.4, 4.5].includes(node.typeVersion);
const supportedWebhook = (node: NormalizedNode) =>
  node.type === "n8n-nodes-base.webhook" &&
  [2, 2.1, 2.2].includes(node.typeVersion);
const supportedPostgres = (node: NormalizedNode) =>
  node.type === "n8n-nodes-base.postgres" &&
  [2.5, 2.6, 2.8].includes(node.typeVersion);
function authentication(node: NormalizedNode): unknown[] {
  return [
    supportedWebhook(node) || supportedHttp(node)
      ? (node.parameters.authentication ?? "none")
      : node.parameters.authentication,
    node.parameters.genericAuthType,
    node.parameters.nodeCredentialType,
    node.raw.credentials,
  ];
}
function recipient(node: NormalizedNode): unknown[] | undefined {
  const fields: Record<string, string[]> = {
    "n8n-nodes-base.emailSend": ["toEmail"],
    "n8n-nodes-base.gmail": ["sendTo"],
    "n8n-nodes-base.slack": [
      "channelId",
      "channel",
      "user",
      "userId",
      "select",
    ],
    "n8n-nodes-base.telegram": ["chatId"],
  };
  if (!fields[node.type]) return;
  const options = isObject(node.parameters.options)
    ? node.parameters.options
    : {};
  const optional =
    node.type === "n8n-nodes-base.emailSend"
      ? selected(options, ["ccEmail", "bccEmail"])
      : node.type === "n8n-nodes-base.gmail"
        ? selected(options, ["ccList", "bccList"])
        : [];
  return [...selected(node.parameters, fields[node.type]!), ...optional];
}
function sqlOperation(
  node: NormalizedNode,
): SqlOperationDescription | undefined {
  const dialect: SqlDialect | undefined =
    node.type === "n8n-nodes-base.postgres" &&
    [2.5, 2.6, 2.8].includes(node.typeVersion)
      ? "Postgresql"
      : node.type === "n8n-nodes-base.mySql" &&
          [2, 2.1, 2.2, 2.3, 2.4, 2.5].includes(node.typeVersion)
        ? "MySQL"
        : node.type === "n8n-nodes-base.microsoftSql" &&
            [1, 1.1, 1.2].includes(node.typeVersion)
          ? "TransactSQL"
          : undefined;
  if (
    !dialect ||
    node.parameters.operation !== "executeQuery" ||
    typeof node.parameters.query !== "string" ||
    (dialect !== "TransactSQL" &&
      (node.parameters.resource ?? "database") !== "database")
  )
    return;
  const query = node.parameters.query.startsWith("=")
    ? node.parameters.query.slice(1)
    : node.parameters.query;
  if (query.includes("{{")) return;
  return inspectSqlOperation(query, dialect);
}
function operation(node: NormalizedNode): unknown[] | undefined {
  if (!/(?:^|\.)(?:postgres|mySql|microsoftSql|mongoDb)$/.test(node.type))
    return;
  const declaration = supportedPostgres(node)
    ? [
        node.parameters.resource ?? "database",
        node.parameters.operation ?? "insert",
      ]
    : [node.parameters.resource, node.parameters.operation];
  const sql = sqlOperation(node);
  return [
    ...declaration,
    sql?.status === "parsed" ? sql.operations : null,
    sql?.status === "parsed" ? sql.statementCount : null,
  ];
}
function capabilities(node: NormalizedNode): string[] {
  const result: string[] = [];
  if (
    ["n8n-nodes-base.executeCommand", "n8n-nodes-base.ssh"].includes(node.type)
  )
    result.push("command");
  if (
    ["n8n-nodes-base.code", "@n8n/n8n-nodes-langchain.toolCode"].includes(
      node.type,
    )
  )
    result.push("code");
  if (
    [
      "n8n-nodes-base.readWriteFile",
      "n8n-nodes-base.readBinaryFile",
      "n8n-nodes-base.writeBinaryFile",
    ].includes(node.type)
  )
    result.push("file");
  if (
    [
      "n8n-nodes-base.executeWorkflow",
      "@n8n/n8n-nodes-langchain.toolWorkflow",
    ].includes(node.type)
  )
    result.push("subworkflow");
  if (node.type.startsWith("@n8n/n8n-nodes-langchain.")) result.push("ai");
  if (
    !node.type.startsWith("n8n-nodes-base.") &&
    !node.type.startsWith("@n8n/n8n-nodes-langchain.")
  )
    result.push("external_package");
  return result;
}
function nodeConfiguration(node: NormalizedNode): unknown {
  return [
    node.parameters,
    node.raw.credentials,
    node.raw.continueOnFail,
    node.raw.onError,
    node.raw.alwaysOutputData,
    node.raw.executeOnce,
    node.raw.retryOnFail,
    node.raw.maxTries,
    node.raw.waitBetweenTries,
  ];
}
function connections(context: Context): string[] {
  return [
    ...context.edges.map((edge) => [
      edge.from,
      edge.to,
      "main",
      edge.output,
      edge.input,
    ]),
    ...context.unsupportedEdges.map((edge) => [
      edge.from,
      edge.to,
      edge.channel,
      edge.output,
      edge.input,
    ]),
  ]
    .map((edge) => JSON.stringify(edge))
    .sort();
}

/** Definition comparison is declarative and never treats a change as a verified fix. */
export function compareDefinitions(
  beforeBytes: Buffer,
  afterBytes: Buffer,
  beforeEvidence?: AssessmentEvidence,
  afterEvidence?: AssessmentEvidence,
): DefinitionComparison {
  const beforeSha256 = digest(beforeBytes);
  const afterSha256 = digest(afterBytes);
  const before = createContext(beforeBytes);
  const after = createContext(afterBytes);
  if (beforeEvidence)
    beforeEvidence = parseEvidence(beforeEvidence, beforeSha256);
  if (afterEvidence) afterEvidence = parseEvidence(afterEvidence, afterSha256);
  const changes: DefinitionComparison["changes"] = [];
  const diagnostics = new Set<string>();
  if (
    before.nodes.some(
      (node) =>
        node.identity === "name_derived" && !after.nodeByKey.has(node.key),
    ) ||
    after.nodes.some(
      (node) =>
        node.identity === "name_derived" && !before.nodeByKey.has(node.key),
    )
  ) {
    diagnostics.add("name_derived_identity_renames_unresolved");
  }
  function add(
    kind: ChangeKind,
    previous?: NormalizedNode,
    next?: NormalizedNode,
    codes: string[] = [kind],
  ): void {
    if (changes.length >= 256) {
      diagnostics.add("definition_change_limit");
      return;
    }
    const location = next
      ? locationFor(next)
      : previous
        ? locationFor(previous)
        : root;
    const id = stableId("DEFINITION_CHANGE", location, kind);
    const existing = changes.find((item) => item.id === id);
    if (existing) {
      for (const value of codes)
        if (!existing.codes.includes(value) && existing.codes.length < 8)
          existing.codes.push(value);
    } else
      changes.push({
        id,
        kind,
        beforeLocation: previous ? locationFor(previous) : null,
        afterLocation: next ? locationFor(next) : null,
        codes,
        recheck: "required",
      });
  }
  for (const previous of before.nodes) {
    const next = after.nodeByKey.get(previous.key);
    if (!next) {
      add("node_removed", previous, undefined, [
        "node_removed_not_verified_remediation",
        "normal_behavior_must_be_rechecked",
      ]);
      if (capabilities(previous).length)
        add("capability_changed", previous, undefined, [
          "declared_capability_removed",
        ]);
      continue;
    }
    if (previous.disabled !== next.disabled)
      add(next.disabled ? "node_disabled" : "node_enabled", previous, next, [
        next.disabled
          ? "disabled_not_verified_remediation"
          : "node_execution_enabled",
        "normal_behavior_must_be_rechecked",
      ]);
    if (previous.type !== next.type) add("node_type_changed", previous, next);
    if (previous.typeVersion !== next.typeVersion)
      add("node_version_changed", previous, next, [
        "adapter_profile_must_be_rechecked",
      ]);
    if (changed(authentication(previous), authentication(next)))
      add("authentication_changed", previous, next, [
        "authentication_declaration_changed",
        "runtime_authentication_not_verified",
      ]);
    if (
      (previous.type === "n8n-nodes-base.httpRequest" ||
        next.type === "n8n-nodes-base.httpRequest") &&
      changed(previous.parameters.url, next.parameters.url)
    ) {
      const oldUrl =
        typeof previous.parameters.url === "string" &&
        !previous.parameters.url.includes("{{")
          ? URL.parse(previous.parameters.url)
          : null;
      const newUrl =
        typeof next.parameters.url === "string" &&
        !next.parameters.url.includes("{{")
          ? URL.parse(next.parameters.url)
          : null;
      const staticUrls =
        oldUrl &&
        newUrl &&
        ["http:", "https:"].includes(oldUrl.protocol) &&
        ["http:", "https:"].includes(newUrl.protocol);
      add("destination_changed", previous, next, [
        staticUrls
          ? oldUrl.origin === newUrl.origin
            ? "request_target_path_or_query_changed"
            : "destination_origin_changed"
          : "dynamic_destination_declaration_changed",
        "actual_network_destination_not_verified",
      ]);
      if (!staticUrls) diagnostics.add("destination_semantics_unresolved");
      if (
        staticUrls &&
        (oldUrl.username !== newUrl.username ||
          oldUrl.password !== newUrl.password)
      )
        add("authentication_changed", previous, next, [
          "url_authentication_material_changed",
        ]);
    }
    if (changed(recipient(previous), recipient(next)))
      add("recipient_changed", previous, next, [
        "recipient_declaration_changed",
        "recipient_identity_not_verified",
      ]);
    if (changed(operation(previous), operation(next)))
      add("database_operation_changed", previous, next, [
        "database_operation_declaration_changed",
        "database_authorization_not_verified",
      ]);
    if (
      (previous.parameters.operation === "executeQuery" ||
        next.parameters.operation === "executeQuery") &&
      changed(previous.parameters.query, next.parameters.query)
    ) {
      const beforeSql = sqlOperation(previous);
      const afterSql = sqlOperation(next);
      if (
        beforeSql?.status !== "parsed" ||
        afterSql?.status !== "parsed" ||
        beforeSql.operations.includes("unknown") ||
        afterSql.operations.includes("unknown")
      )
        diagnostics.add("database_operation_semantics_unresolved");
    }
    if (changed(capabilities(previous), capabilities(next)))
      add("capability_changed", previous, next, [
        "declared_capability_changed",
      ]);
    if (changed(nodeConfiguration(previous), nodeConfiguration(next))) {
      add("node_configuration_changed", previous, next, [
        "node_configuration_changed",
        "full_program_semantics_not_compared",
      ]);
      if (
        [
          "n8n-nodes-base.if",
          "n8n-nodes-base.switch",
          "n8n-nodes-base.filter",
        ].includes(previous.type) ||
        [
          "n8n-nodes-base.if",
          "n8n-nodes-base.switch",
          "n8n-nodes-base.filter",
        ].includes(next.type)
      )
        add("guard_changed", previous, next, [
          "guard_configuration_changed",
          "same_value_all_path_analysis_required",
        ]);
    }
  }
  for (const next of after.nodes)
    if (!before.nodeByKey.has(next.key)) {
      add("node_added", undefined, next);
      if (capabilities(next).length)
        add("capability_changed", undefined, next, [
          "declared_capability_added",
        ]);
    }
  if (
    changes.some(({ kind }) => kind === "node_added") &&
    changes.some(({ kind }) => kind === "node_removed")
  )
    diagnostics.add("node_identity_matching_incomplete");
  if (changed(connections(before), connections(after)))
    add("connections_changed", undefined, undefined, [
      "connection_channel_or_branch_changed",
      "reachability_and_value_flow_must_be_rechecked",
    ]);
  if (
    changed(before.document.settings, after.document.settings) ||
    changed(before.document.active, after.document.active)
  )
    add("workflow_settings_changed");
  const documentMetadata = (context: Context) =>
    Object.fromEntries(
      Object.entries(context.document).filter(
        ([key]) =>
          !["nodes", "connections", "settings", "active"].includes(key),
      ),
    );
  const nodeMetadata = (context: Context) =>
    context.nodes
      .map((node) => [
        node.key,
        node.raw.name,
        node.raw.notes,
        node.raw.position,
      ])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  if (
    changed(documentMetadata(before), documentMetadata(after)) ||
    changed(nodeMetadata(before), nodeMetadata(after))
  )
    add("document_metadata_changed", undefined, undefined, [
      "document_metadata_changed",
      "content_exposure_recheck_required",
    ]);
  const evidenceFields: [keyof AssessmentEvidence, ChangeKind][] = [
    ["runtime", "environment_changed"],
    ["policy", "policy_changed"],
    ["packages", "packages_changed"],
    ["advisories", "advisories_changed"],
    ["subworkflows", "subworkflows_changed"],
    ["classifications", "classifications_changed"],
    ["aiApprovals", "environment_changed"],
  ];
  for (const [field, kind] of evidenceFields)
    if (changed(beforeEvidence?.[field], afterEvidence?.[field]))
      add(kind, undefined, undefined, [
        kind,
        "supplied_evidence_requires_reevaluation",
      ]);
  const evidenceMetadata = (evidence?: AssessmentEvidence) =>
    evidence
      ? [
          evidence.sources,
          evidence.provenance,
          evidence.publicationReview,
          evidence.syntheticReceipts,
        ]
      : undefined;
  if (
    changed(evidenceMetadata(beforeEvidence), evidenceMetadata(afterEvidence))
  )
    add("evidence_changed", undefined, undefined, [
      "evidence_provenance_or_review_changed",
    ]);
  if (before.topology === "partial" || after.topology === "partial")
    diagnostics.add("non_main_channels_compared_as_declarations_only");
  diagnostics.add("workflow_execution_and_normal_behavior_not_verified");
  return definitionComparisonSchema.parse({
    contractVersion: "1.0.0",
    beforeSha256,
    afterSha256,
    status:
      diagnostics.has("definition_change_limit") ||
      diagnostics.has("node_identity_matching_incomplete")
        ? "inconclusive"
        : "compared",
    byteIdentity: beforeSha256 === afterSha256 ? "same" : "different",
    scope: "supported_declarations",
    execution: "not_run",
    behaviorPreserved: "not_verified",
    securityEquivalent: "not_claimed",
    changes,
    diagnostics: [...diagnostics],
  });
}

const remediationKinds = [
  "enable_tls_verification",
  "bind_postgres_lookup_value",
  "bind_postgres_lookup_values",
  "rotate_exposed_secret",
  "minimize_personal_data",
  "configure_request_authentication",
  "restrict_egress_destination",
  "constrain_request_origin",
  "review_sql_binding",
  "remove_dynamic_command",
  "review_transport_configuration",
  "minimize_output_data",
  "review_dependency_and_permissions",
] as const;
export const remediationPlanSchema = z
  .strictObject({
    contractVersion: z.literal("1.0.0"),
    id: hash,
    inputSha256: hash,
    location: staticLocationSchema,
    kind: z.enum(remediationKinds),
    automatic: z.boolean(),
    findingIds: z.array(hash).min(1).max(256),
    preconditions: z.array(code).min(1).max(12),
    checks: z.array(code).min(1).max(12),
    execution: z.literal("not_run"),
    normalBehavior: z.literal("requires_validation"),
  })
  .refine(
    (plan) =>
      plan.automatic ===
        [
          "enable_tls_verification",
          "bind_postgres_lookup_value",
          "bind_postgres_lookup_values",
        ].includes(plan.kind) &&
      (!plan.automatic || plan.location.nodeKey !== null) &&
      new Set(plan.findingIds).size === plan.findingIds.length &&
      plan.id === planId(plan.kind, plan.location, plan.inputSha256),
    { message: "Inconsistent remediation plan" },
  );
export const remediationPlansSchema = z.array(remediationPlanSchema).max(256);
export type RemediationPlan = z.infer<typeof remediationPlanSchema>;
type RemediationKind = (typeof remediationKinds)[number];

function tlsEligible(node: NormalizedNode): boolean {
  return (
    supportedHttp(node) &&
    isObject(node.parameters.options) &&
    node.parameters.options.allowUnauthorizedCerts === true
  );
}
function boundQuery(node: NormalizedNode): string | undefined {
  if (
    node.type !== "n8n-nodes-base.postgres" ||
    node.typeVersion !== 2.8 ||
    node.disabled ||
    node.parameters.operation !== "executeQuery" ||
    (node.parameters.resource !== undefined &&
      node.parameters.resource !== "database") ||
    typeof node.parameters.query !== "string"
  )
    return;
  if (
    Object.keys(node.parameters).some(
      (key) => !["resource", "operation", "query", "options"].includes(key),
    )
  )
    return;
  if (
    node.parameters.options !== undefined &&
    (!isObject(node.parameters.options) ||
      Object.keys(node.parameters.options).length > 0)
  )
    return;
  const match =
    /^=?([ \t\r\n]*SELECT[ \t\r\n]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]+FROM[ \t\r\n]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]+WHERE[ \t\r\n]+[A-Za-z_][A-Za-z0-9_]*[ \t\r\n]*=[ \t\r\n]*)\{\{\s*\$json\.body\.id\s*\}\}([ \t\r\n]*)$/i.exec(
      node.parameters.query,
    );
  return match && /\{\{\s*\$json\.body\.id\s*\}\}/.test(node.parameters.query)
    ? `${match[1]}$1${match[2]}`
    : undefined;
}

/** A fixed lookup grammar, with the SQL parser confirming the generated value slots. */
function boundLookup(
  node: NormalizedNode,
): { query: string; replacement: string } | undefined {
  if (
    node.type !== "n8n-nodes-base.postgres" ||
    node.typeVersion !== 2.8 ||
    node.disabled ||
    node.parameters.operation !== "executeQuery" ||
    (node.parameters.resource !== undefined &&
      node.parameters.resource !== "database") ||
    typeof node.parameters.query !== "string" ||
    node.parameters.query.length > 8192 ||
    Object.keys(node.parameters).some(
      (key) => !["resource", "operation", "query", "options"].includes(key),
    ) ||
    (node.parameters.options !== undefined &&
      (!isObject(node.parameters.options) ||
        Object.keys(node.parameters.options).length > 0))
  )
    return;
  const identifier = "[A-Za-z_][A-Za-z0-9_]{0,62}";
  const column = `${identifier}(?:\\.${identifier})?`;
  const projection = `(?:\\*|${column}(?:\\s*,\\s*${column}){0,15})`;
  const query = node.parameters.query.replace(/^=/, "");
  const prefix = new RegExp(
    `^(\\s*SELECT\\s+${projection}\\s+FROM\\s+${column}\\s+WHERE\\s+)`,
    "i",
  ).exec(query);
  if (!prefix) return;
  const member =
    "(?:\\.[A-Za-z_$][A-Za-z0-9_$]*|\\[(?:0|[1-9][0-9]{0,5})\\]|\\[\"[A-Za-z_$][A-Za-z0-9_$]*\"\\]|\\['[A-Za-z_$][A-Za-z0-9_$]*'\\])";
  const expression = `\\$json${member}{1,8}`;
  // Quotes are removed only when they enclose exactly one interpolation.
  // Quoted prefixes/suffixes, casts, comments and identifier interpolation fail closed.
  const operand = new RegExp(
    `^(\\s*${column}\\s*=\\s*)(?:\\{\\{\\s*(${expression})\\s*\\}\\}|'\\{\\{\\s*(${expression})\\s*\\}\\}')`,
    "i",
  );
  let rest = query.slice(prefix[0].length);
  let output = prefix[0];
  const values: string[] = [];
  for (;;) {
    const match = operand.exec(rest);
    if (!match || values.length >= 8) return;
    const value = match[2] ?? match[3];
    if (!value || value.length > 1024 || !value.startsWith("$json")) return;
    try {
      const parsed = parseExpressionAt(value, 0, { ecmaVersion: "latest" });
      // The grammar admits only member access. Acorn independently checks syntax;
      // neither uploaded expressions nor generated binding expressions are executed.
      if (parsed.type !== "MemberExpression" || parsed.end !== value.length)
        return;
      let reference: unknown = parsed;
      while (isObject(reference) && reference.type === "MemberExpression") {
        const property = reference.property;
        if (!isObject(property)) return;
        const key = reference.computed ? property.value : property.name;
        if (
          typeof key === "string" &&
          ["__proto__", "constructor", "prototype"].includes(key)
        )
          return;
        reference = reference.object;
      }
      if (
        !isObject(reference) ||
        reference.type !== "Identifier" ||
        reference.name !== "$json"
      )
        return;
    } catch {
      return;
    }
    values.push(value);
    output += `${match[1]}$${values.length}`;
    rest = rest.slice(match[0].length);
    const conjunction = /^(\s+AND\s+)/i.exec(rest);
    if (conjunction) {
      output += conjunction[0];
      rest = rest.slice(conjunction[0].length);
      continue;
    }
    if (!/^\s*;?\s*$/.test(rest)) return;
    output += rest;
    break;
  }
  const description = inspectSqlOperation(output, "Postgresql");
  if (
    description.status !== "parsed" ||
    description.statementCount !== 1 ||
    description.operations.length !== 1 ||
    description.operations[0] !== "select" ||
    description.valueParameterCount !== values.length
  )
    return;
  return { query: output, replacement: `={{ [${values.join(", ")}] }}` };
}
const manualKind: Record<Finding["category"], RemediationKind> = {
  secrets: "rotate_exposed_secret",
  pii: "minimize_personal_data",
  request_auth: "configure_request_authentication",
  egress: "restrict_egress_destination",
  ssrf: "constrain_request_origin",
  sql: "review_sql_binding",
  code_execution: "remove_dynamic_command",
  transport: "review_transport_configuration",
  output: "minimize_output_data",
  dependencies: "review_dependency_and_permissions",
};
function planDetails(
  kind: RemediationKind,
): Pick<RemediationPlan, "automatic" | "preconditions" | "checks"> {
  const common = [
    "reassess_exact_new_bytes",
    "validate_normal_behavior_in_synthetic_environment",
  ];
  if (kind === "enable_tls_verification")
    return {
      automatic: true,
      preconditions: [
        "exact_input_hash_matches",
        "supported_http_request_version",
        "certificate_validation_explicitly_disabled",
      ],
      checks: [
        "confirm_target_certificate_chain",
        "confirm_request_still_succeeds",
        ...common,
      ],
    };
  if (kind === "bind_postgres_lookup_value")
    return {
      automatic: true,
      preconditions: [
        "exact_input_hash_matches",
        "postgres_2_8_execute_query",
        "single_unquoted_current_body_id_lookup",
        "no_existing_binding_or_query_options",
      ],
      checks: [
        "confirm_database_column_type",
        "confirm_binding_preserves_expected_result",
        "confirm_input_cannot_change_query_structure",
        ...common,
      ],
    };
  if (kind === "bind_postgres_lookup_values")
    return {
      automatic: true,
      preconditions: [
        "exact_input_hash_matches",
        "postgres_2_8_execute_query",
        "fixed_select_lookup_with_current_json_member_values",
        "at_most_eight_equality_operands_joined_by_and",
        "no_existing_binding_or_query_options",
        "generated_sql_ast_and_parameter_count_checked",
      ],
      checks: [
        "confirm_database_column_type",
        "confirm_binding_preserves_expected_result",
        "confirm_input_cannot_change_query_structure",
        "confirm_missing_null_and_string_value_semantics",
        ...common,
      ],
    };
  const checks: Record<
    Exclude<
      RemediationKind,
      | "enable_tls_verification"
      | "bind_postgres_lookup_value"
      | "bind_postgres_lookup_values"
    >,
    string[]
  > = {
    rotate_exposed_secret: [
      "revoke_or_rotate_actual_credential",
      "replace_literal_with_credential_reference",
      "review_exposure_history",
    ],
    minimize_personal_data: [
      "identify_needed_personal_fields",
      "remove_unneeded_pinned_or_literal_data",
    ],
    configure_request_authentication: [
      "configure_requester_verification",
      "test_unauthorized_and_authorized_requests",
    ],
    restrict_egress_destination: [
      "confirm_recipient_and_business_purpose",
      "restrict_destination_and_data_classes",
    ],
    constrain_request_origin: [
      "use_fixed_allowed_origin",
      "verify_redirect_dns_and_private_egress_controls",
    ],
    review_sql_binding: [
      "bind_each_untrusted_value",
      "keep_identifiers_and_query_structure_fixed",
      "verify_database_authorization_separately",
    ],
    remove_dynamic_command: [
      "prefer_non_shell_operation",
      "avoid_untrusted_command_concatenation",
      "restrict_runtime_permissions",
    ],
    review_transport_configuration: [
      "require_authenticated_encrypted_transport",
      "remove_url_authentication_material",
    ],
    minimize_output_data: [
      "select_only_needed_output_fields",
      "confirm_audience_and_log_retention",
    ],
    review_dependency_and_permissions: [
      "obtain_exact_package_and_child_versions",
      "review_installed_capabilities_and_approval_controls",
    ],
  };
  return {
    automatic: false,
    preconditions: ["exact_input_hash_matches", "manual_review_required"],
    checks: [...checks[kind], ...common],
  };
}
function planId(
  kind: RemediationKind,
  location: StaticLocation,
  inputSha256: string,
): string {
  return digest(
    JSON.stringify([
      "remediation-plan-1.0.0",
      inputSha256,
      stableId("REMEDIATION_PLAN", location, kind),
    ]),
  );
}

export function createRemediationPlans(
  context: Context,
  findings: Finding[],
  inputSha256: string,
): RemediationPlan[] {
  hash.parse(inputSha256);
  const plans: RemediationPlan[] = [];
  for (const finding of findings) {
    // Informational capabilities and configured protections are observations,
    // not requests to change a legitimate workflow.
    if (finding.severity === "info") continue;
    const node =
      finding.location.nodeKey === null
        ? undefined
        : context.nodeByKey.get(finding.location.nodeKey);
    const codes = finding.evidence.map(({ code }) => code);
    let kind = manualKind[finding.category];
    if (
      finding.category === "transport" &&
      codes.includes("tls_certificate_validation_disabled") &&
      node &&
      tlsEligible(node)
    )
      kind = "enable_tls_verification";
    if (finding.category === "sql" && node && boundQuery(node) !== undefined)
      kind = "bind_postgres_lookup_value";
    else if (
      finding.category === "sql" &&
      node &&
      boundLookup(node) !== undefined
    )
      kind = "bind_postgres_lookup_values";
    const location = node ? locationFor(node) : root;
    const id = planId(kind, location, inputSha256);
    const existing = plans.find((plan) => plan.id === id);
    if (existing) {
      if (!existing.findingIds.includes(finding.id)) {
        if (existing.findingIds.length >= 256)
          throw new RemediationError("remediation_output_limit");
        existing.findingIds.push(finding.id);
      }
      continue;
    }
    if (plans.length >= 256)
      throw new RemediationError("remediation_output_limit");
    plans.push({
      contractVersion: "1.0.0",
      id,
      inputSha256,
      location,
      kind,
      findingIds: [finding.id],
      ...planDetails(kind),
      execution: "not_run",
      normalBehavior: "requires_validation",
    });
  }
  return remediationPlansSchema.parse(plans);
}

export class RemediationError extends Error {
  constructor(
    readonly code:
      | "invalid_remediation_plan"
      | "remediation_input_mismatch"
      | "manual_remediation_required"
      | "remediation_not_eligible"
      | "remediation_output_limit",
  ) {
    super(code);
  }
}

/** Only recognized change profiles can be applied. No arbitrary patch is accepted. */
export function applyRemediation(
  bytes: Buffer,
  value: RemediationPlan,
): Buffer {
  const parsed = remediationPlanSchema.safeParse(value);
  if (!parsed.success) throw new RemediationError("invalid_remediation_plan");
  const plan = parsed.data;
  if (digest(bytes) !== plan.inputSha256)
    throw new RemediationError("remediation_input_mismatch");
  if (
    plan.id !== planId(plan.kind, plan.location, plan.inputSha256) ||
    changed(planDetails(plan.kind), {
      automatic: plan.automatic,
      preconditions: plan.preconditions,
      checks: plan.checks,
    })
  )
    throw new RemediationError("invalid_remediation_plan");
  if (!plan.automatic)
    throw new RemediationError("manual_remediation_required");
  const context = createContext(bytes);
  const node =
    plan.location.nodeKey === null
      ? undefined
      : context.nodeByKey.get(plan.location.nodeKey);
  if (!node || changed(locationFor(node), plan.location))
    throw new RemediationError("remediation_not_eligible");
  if (plan.kind === "enable_tls_verification" && tlsEligible(node))
    (node.parameters.options as JsonObject).allowUnauthorizedCerts = false;
  else if (plan.kind === "bind_postgres_lookup_value") {
    const query = boundQuery(node);
    if (query === undefined)
      throw new RemediationError("remediation_not_eligible");
    node.parameters.query = query;
    node.parameters.options = { queryReplacement: "={{ [$json.body.id] }}" };
  } else if (plan.kind === "bind_postgres_lookup_values") {
    const bound = boundLookup(node);
    if (bound === undefined)
      throw new RemediationError("remediation_not_eligible");
    node.parameters.query = bound.query;
    node.parameters.options = { queryReplacement: bound.replacement };
  } else throw new RemediationError("remediation_not_eligible");
  // Context.document and parseWorkflow's normalized raw nodes are independently
  // decoded. Copy the recognized node edit into the preserved document explicitly.
  const index = Number(/^\/nodes\/(\d+)$/.exec(node.pointer)?.[1]);
  const target = Array.isArray(context.document.nodes)
    ? context.document.nodes[index]
    : undefined;
  if (!isObject(target)) throw new RemediationError("remediation_not_eligible");
  target.parameters = node.parameters;
  const result = Buffer.from(JSON.stringify(context.document, null, 2) + "\n");
  if (result.length > limits.fileBytes)
    throw new RemediationError("remediation_output_limit");
  createContext(result);
  return result;
}
