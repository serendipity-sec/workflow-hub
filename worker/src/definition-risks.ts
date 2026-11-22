import type { NormalizedNode } from "./n8n.js";
import type { Context } from "./static-context.js";
import { isObject } from "./static-context.js";
import { locationFor, stableId } from "./static-contract.js";
import type { Category, Finding, RuleResult } from "./static-contract.js";
import type { AbstractValue, ValueFlow } from "./value-flow.js";

const base = "n8n-nodes-base.";
const external = (value: AbstractValue) =>
  value.trust === "external" ||
  value.origins.some((origin) =>
    ["webhook", "subworkflow"].includes(origin.kind),
  );
const makeRule = (ruleId: string, category: Category): RuleResult => ({
  ruleId,
  category,
  profileVersion: "1.0.0",
  findings: [],
  diagnostics: [],
  coverage: [],
});
class Scope {
  private findings: string[] = [];
  private diagnostics: string[] = [];
  constructor(
    private rule: RuleResult,
    private context: Context,
    private node: NormalizedNode,
  ) {}
  diagnostic(code: string) {
    let location = locationFor(this.node, "/parameters");
    if (this.rule.diagnostics.length >= 127) {
      code = "definition_diagnostic_limit";
      location = { nodeKey: null, pointer: "/nodes" };
    }
    const id = stableId(this.rule.ruleId, location, code);
    if (!this.rule.diagnostics.some((d) => d.id === id))
      this.rule.diagnostics.push({ id, code, location });
    if (!this.diagnostics.includes(id)) this.diagnostics.push(id);
  }
  finding(
    code: string,
    field: string,
    value?: AbstractValue,
    severity: Finding["severity"] = "info",
  ) {
    if (this.rule.findings.length >= 128) {
      this.diagnostic("definition_finding_limit");
      return;
    }
    const location = locationFor(this.node, "/parameters" + field);
    const id = stableId(this.rule.ruleId, location, code);
    if (this.rule.findings.some((f) => f.id === id)) return;
    const evidence: Finding["evidence"] = [{ code, location }];
    if ((value?.origins.length ?? 0) > 32)
      this.diagnostic("definition_origin_limit");
    for (const origin of value?.origins.slice(0, 32) ?? []) {
      const source = this.context.nodeByKey.get(origin.nodeKey);
      if (source)
        evidence.push({
          code: "possible_value_source",
          location: locationFor(source),
        });
    }
    this.rule.findings.push({
      id,
      ruleId: this.rule.ruleId,
      category: this.rule.category,
      severity,
      claim: severity === "info" ? "configuration" : "candidate",
      location,
      evidence,
      assumptions: [
        "static_definition_only",
        "runtime_permissions_unverified",
        "execution_reachability_unverified",
      ],
      remediation: {
        code: "review_operation_and_value_scope",
        checks: [
          "verify_required_operation",
          "constrain_same_value",
          "preserve_required_behavior",
          "rescan_same_profile",
        ],
      },
    });
    this.findings.push(id);
  }
  finish() {
    this.rule.coverage.push({
      location: locationFor(this.node, "/parameters"),
      status: this.node.disabled
        ? "not_applicable"
        : this.diagnostics.length
          ? "partial"
          : "checked",
      findingIds: this.findings,
      diagnosticIds: this.diagnostics,
    });
  }
  value(flow: ValueFlow, field: string, raw: unknown, role: string) {
    if (typeof raw !== "string" || raw === "") {
      this.diagnostic(role + "_unavailable");
      return;
    }
    const value = flow.resolve(this.node.key, raw);
    if (external(value))
      this.finding(role + "_external_input_candidate", field, value, "high");
    else if (
      raw.startsWith("=") &&
      (value.status !== "resolved" ||
        value.origins.some((o) => o.kind !== "literal"))
    )
      this.finding(role + "_dynamic_value_candidate", field, value, "medium");
    if (value.status !== "resolved")
      this.diagnostic(role + "_provenance_unresolved");
  }
}
function finish(rule: RuleResult) {
  if (!rule.coverage.length)
    rule.coverage.push({
      location: { nodeKey: null, pointer: "/nodes" },
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  return rule;
}
const pgVersions = [2.4, 2.5, 2.6, 2.8];
const structuredOperations = [
  "insert",
  "update",
  "upsert",
  "select",
  "deleteTable",
];
export function isStructuredPostgres(node: NormalizedNode): boolean {
  return (
    [base + "postgres", base + "postgresTool"].includes(node.type) &&
    pgVersions.includes(node.typeVersion) &&
    (node.parameters.resource ?? "database") === "database" &&
    structuredOperations.includes(String(node.parameters.operation ?? "insert"))
  );
}
function database(context: Context, flow: ValueFlow): RuleResult {
  const rule = makeRule("N8N_DATABASE_OPERATIONS", "sql");
  for (const node of context.nodes.filter(isStructuredPostgres)) {
    const scope = new Scope(rule, context, node);
    if (node.disabled) {
      scope.finish();
      continue;
    }
    const p = node.parameters,
      operation = String(p.operation ?? "insert");
    scope.finding(
      "database_" +
        (operation === "deleteTable" ? "delete_table" : operation) +
        "_capability",
      "",
    );
    scope.diagnostic("database_runtime_schema_and_permissions_unverified");
    for (const field of ["schema", "table"] as const) {
      const locator = p[field],
        raw = isObject(locator) ? locator.value : locator;
      scope.value(
        flow,
        "/" + field + (isObject(locator) ? "/value" : ""),
        raw,
        "database_identifier_selection",
      );
    }
    if (["insert", "update", "upsert"].includes(operation)) {
      const columns = p.columns;
      if (!isObject(columns)) scope.diagnostic("database_mapping_unresolved");
      else if (columns.mappingMode === "autoMapInputData") {
        const value = flow.resolve(node.key, "={{ $json }}");
        scope.finding("database_input_item_value_channel", "/columns", value);
        if (value.status !== "resolved")
          scope.diagnostic("database_input_provenance_unresolved");
      } else if (
        columns.mappingMode === "defineBelow" &&
        isObject(columns.value)
      ) {
        scope.finding("database_mapped_value_channel", "/columns");
        const entries = Object.values(columns.value);
        if (entries.length > 128) scope.diagnostic("database_mapping_limit");
        for (const value of entries.slice(0, 128)) {
          const abstract = flow.resolve(node.key, value);
          // Never export uploaded column names, values or abstract constants.
          if (abstract.status !== "resolved")
            scope.diagnostic("database_input_provenance_unresolved");
        }
      } else scope.diagnostic("database_mapping_unresolved");
      if (operation !== "insert")
        scope.diagnostic("database_match_columns_and_effect_unverified");
    } else if (operation === "deleteTable") {
      scope.finding(
        "database_destructive_operation_capability",
        "/deleteCommand",
        undefined,
        "medium",
      );
      scope.diagnostic("database_deletion_scope_unverified");
    } else scope.diagnostic("database_filter_and_result_scope_unverified");
    // Official adapters quote identifiers and format values separately. The
    // runtime schema can change conversion/constraints, so this is not a SQL
    // injection or successful-write verdict.
    scope.finish();
  }
  return finish(rule);
}
function fileOperations(context: Context, flow: ValueFlow): RuleResult {
  const rule = makeRule("N8N_FILE_OPERATION_PATHS", "code_execution");
  const types = [
    "readWriteFile",
    "readBinaryFile",
    "writeBinaryFile",
    "ssh",
  ].map((t) => base + t);
  for (const node of context.nodes.filter((n) => types.includes(n.type))) {
    const scope = new Scope(rule, context, node),
      p = node.parameters;
    if (node.disabled) {
      scope.finish();
      continue;
    }
    if (
      !(node.type === base + "readWriteFile" ? [1, 1.1] : [1]).includes(
        node.typeVersion,
      )
    ) {
      scope.diagnostic("file_operation_version_unsupported");
      scope.finish();
      continue;
    }
    if (node.type === base + "ssh") {
      if ((p.resource ?? "command") === "command") {
        if ((p.operation ?? "execute") === "execute") {
          scope.value(flow, "/cwd", p.cwd ?? "/", "remote_working_directory");
          scope.diagnostic("remote_host_permissions_and_directory_unverified");
        } else scope.diagnostic("file_operation_unsupported");
        scope.finish();
        continue;
      }
      if (
        p.resource !== "file" ||
        !["upload", "download"].includes(String(p.operation ?? "upload"))
      ) {
        scope.diagnostic("file_operation_unsupported");
        scope.finish();
        continue;
      }
      scope.finding(
        (p.operation ?? "upload") === "upload"
          ? "remote_file_upload_capability"
          : "remote_file_download_capability",
        "",
      );
      scope.value(flow, "/path", p.path, "remote_file_path");
      scope.diagnostic("remote_host_permissions_and_directory_unverified");
    } else {
      const op =
        node.type === base + "readBinaryFile"
          ? "read"
          : node.type === base + "writeBinaryFile"
            ? "write"
            : (p.operation ?? "read");
      if (!["read", "write"].includes(String(op))) {
        scope.diagnostic("file_operation_unsupported");
        scope.finish();
        continue;
      }
      const field =
        node.type === base + "readBinaryFile"
          ? "filePath"
          : op === "read"
            ? "fileSelector"
            : "fileName";
      scope.finding(
        op === "read"
          ? "local_file_read_capability"
          : "local_file_write_capability",
        "",
      );
      scope.value(flow, "/" + field, p[field], "local_file_path");
      scope.diagnostic("filesystem_permissions_and_path_scope_unverified");
    }
    scope.diagnostic("binary_payload_unavailable");
    scope.finish();
  }
  return finish(rule);
}
function mappedHttp(context: Context, flow: ValueFlow): RuleResult {
  const rule = makeRule("N8N_MAPPED_HTTP_DESTINATION", "ssrf");
  for (const node of context.nodes.filter((n) =>
    [base + "httpRequest", base + "httpRequestTool"].includes(n.type),
  )) {
    const scope = new Scope(rule, context, node),
      raw = node.parameters.url;
    if (node.disabled) {
      scope.finish();
      continue;
    }
    if (![3, 4, 4.1, 4.2, 4.3, 4.4, 4.5].includes(node.typeVersion)) {
      scope.diagnostic("http_destination_profile_unsupported");
      scope.finish();
      continue;
    }
    scope.finding("outbound_http_request_declared", "/url");
    if (typeof raw !== "string") {
      scope.diagnostic("http_destination_unavailable");
      scope.finish();
      continue;
    }
    const value = flow.resolve(node.key, raw);
    const constant = (value as AbstractValue & { constant?: unknown }).constant;
    const exact =
      value.status === "resolved" && typeof constant === "string"
        ? constant
        : undefined;
    const expression =
      exact === undefined && raw.startsWith("=") && /\{\{|\}\}/.test(raw);
    const literal = exact ?? (raw.startsWith("=") ? raw.slice(1) : raw);
    // Only an origin entirely before interpolation is fixed. A literal suffix,
    // encoding call or a host/path condition never proves an allowlist.
    const prefix = expression
      ? literal.slice(0, literal.indexOf("{{"))
      : literal;
    const match = /^https?:\/\/[^/?#{}\\\s]+[/?#]/i.exec(prefix);
    if (expression && !match)
      scope.value(flow, "/url", raw, "http_destination");
    else if (expression)
      scope.finding(
        "http_fixed_origin_dynamic_resource",
        "/url",
        flow.resolve(node.key, raw),
      );
    const url = !expression
      ? URL.parse(literal)
      : match
        ? URL.parse(match[0])
        : null;
    if (
      url &&
      /^(?:localhost|127(?:\.\d+){3}|10(?:\.\d+){3}|192\.168(?:\.\d+){2}|169\.254(?:\.\d+){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d+){2}|\[::1\])$/i.test(
        url.hostname,
      )
    )
      scope.finding(
        "http_local_or_private_destination_candidate",
        "/url",
        undefined,
        "medium",
      );
    if (
      expression &&
      match &&
      flow.resolve(node.key, raw).status !== "resolved"
    )
      scope.diagnostic("http_resource_provenance_unresolved");
    if (!expression && (!url || !["http:", "https:"].includes(url.protocol)))
      scope.diagnostic("http_destination_format_unresolved");
    scope.diagnostic("dns_redirect_and_network_access_unverified");
    scope.finish();
  }
  return finish(rule);
}
/** Declared fields and bounded abstract values only; never I/O to destinations. */
export function analyzeDefinitionRisks(
  context: Context,
  flow: ValueFlow,
): RuleResult[] {
  return [
    database(context, flow),
    fileOperations(context, flow),
    mappedHttp(context, flow),
  ];
}
