import { parse } from "acorn";
import { parseReference } from "./n8n.js";
import type { NormalizedNode } from "./n8n.js";
import { isObject } from "./static-context.js";
import type { Context, JsonObject } from "./static-context.js";
import { locationFor, stableId } from "./static-contract.js";
import type {
  Category,
  Coverage,
  Finding,
  RuleResult,
  StaticLocation,
} from "./static-contract.js";

// Field semantics checked against n8n source commit
// 86dff76e10efba250a4d3e57760e4eb5d2bbea25. typeVersion is not an npm version.
const webhookVersions = new Set([2, 2.1, 2.2]);
const httpVersions = new Set([3, 4, 4.1, 4.2, 4.3, 4.4, 4.5]);
const codeVersions = new Set([1, 2]);
const subworkflowVersions = new Set([1, 1.1, 1.2, 1.3, 1.4]);
const rootLocation: StaticLocation = { nodeKey: null, pointer: "" };

function makeRule(ruleId: string, category: Category): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.0.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}

class Scope {
  private findingIds: string[] = [];
  private diagnosticIds: string[] = [];

  constructor(
    private readonly rule: RuleResult,
    private readonly node: NormalizedNode,
  ) {}

  finding(
    code: string,
    suffix: string,
    severity: Finding["severity"] = "info",
    claim: Finding["claim"] = "configuration",
    assumptions: string[] = [],
    extraEvidence: Finding["evidence"] = [],
  ): void {
    const location = locationFor(this.node, suffix);
    const id = stableId(this.rule.ruleId, location, code);
    if (this.findingIds.includes(id)) return;
    this.findingIds.push(id);
    this.rule.findings.push({
      id,
      ruleId: this.rule.ruleId,
      category: this.rule.category,
      severity,
      claim,
      location,
      evidence: [{ code, location }, ...extraEvidence],
      assumptions: [
        "static_file_configuration_only",
        ...(this.node.disabled ? ["node_disabled_in_file"] : []),
        ...assumptions,
      ],
      remediation: {
        code: "review_configuration_and_required_access",
        checks: ["rescan_exact_file", "verify_runtime_conditions_separately"],
      },
    });
  }

  diagnostic(code: string, suffix = ""): void {
    const location = locationFor(this.node, suffix);
    const id = stableId(this.rule.ruleId, location, code);
    if (this.diagnosticIds.includes(id)) return;
    this.diagnosticIds.push(id);
    this.rule.diagnostics.push({ id, code, location });
  }

  finish(): void {
    const status: Coverage["status"] = this.diagnosticIds.length
      ? this.findingIds.length
        ? "partial"
        : "unsupported"
      : "checked";
    this.rule.coverage.push({
      location: locationFor(this.node),
      status,
      findingIds: this.findingIds,
      diagnosticIds: this.diagnosticIds,
    });
  }
}

function finishRule(rule: RuleResult): RuleResult {
  if (rule.coverage.length === 0) {
    rule.coverage.push({
      location: rootLocation,
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  }
  return rule;
}

function present(object: JsonObject, key: string): boolean {
  return Object.hasOwn(object, key);
}

function requestAuthentication(context: Context): RuleResult {
  const rule = makeRule("N8N_REQUEST_AUTH_SETTINGS", "request_auth");
  for (const node of context.nodes) {
    if (node.type !== "n8n-nodes-base.webhook") continue;
    const scope = new Scope(rule, node);
    if (!webhookVersions.has(node.typeVersion)) {
      scope.diagnostic("unsupported_node_version", "/typeVersion");
      scope.finish();
      continue;
    }
    const authentication = present(node.parameters, "authentication")
      ? node.parameters.authentication
      : "none";
    const location = present(node.parameters, "authentication")
      ? "/parameters/authentication"
      : "/parameters";
    const credentialName =
      authentication === "basicAuth"
        ? "httpBasicAuth"
        : authentication === "headerAuth"
          ? "httpHeaderAuth"
          : authentication === "jwtAuth"
            ? "jwtAuth"
            : undefined;
    if (authentication === "none") {
      scope.finding(
        present(node.parameters, "authentication")
          ? "webhook_authentication_none"
          : "webhook_authentication_default_none",
        location,
        "medium",
        "configuration",
        [
          "upstream_authentication_not_observed",
          "workflow_activation_unverified",
        ],
      );
    } else if (credentialName !== undefined) {
      scope.finding(
        "webhook_authentication_configured",
        location,
        "info",
        "configuration",
        [
          "credential_validity_not_checked",
          "upstream_authentication_not_observed",
        ],
      );
      const credentials = node.raw.credentials;
      const reference = isObject(credentials)
        ? credentials[credentialName]
        : undefined;
      if (
        !isObject(reference) ||
        ![reference.id, reference.name].some(
          (value) => typeof value === "string" && value.trim().length > 0,
        )
      ) {
        scope.diagnostic(
          "authentication_credential_reference_missing",
          present(node.raw, "credentials") ? "/credentials" : "",
        );
      }
    } else {
      scope.diagnostic("unsupported_authentication_mode", location);
    }
    scope.finish();
  }
  return finishRule(rule);
}

function transportSettings(context: Context): RuleResult {
  const rule = makeRule("N8N_TRANSPORT_SETTINGS", "transport");
  for (const node of context.nodes) {
    if (node.type !== "n8n-nodes-base.httpRequest") continue;
    const scope = new Scope(rule, node);
    if (!httpVersions.has(node.typeVersion)) {
      scope.diagnostic("unsupported_node_version", "/typeVersion");
      scope.finish();
      continue;
    }
    const options = node.parameters.options;
    if (options !== undefined && !isObject(options)) {
      scope.diagnostic("unsupported_transport_options", "/parameters/options");
    } else if (isObject(options)) {
      const value = options.allowUnauthorizedCerts;
      if (value === true) {
        scope.finding(
          "tls_certificate_validation_disabled",
          "/parameters/options/allowUnauthorizedCerts",
          "high",
          "configuration",
          ["actual_transport_not_observed"],
        );
      } else if (value !== undefined && value !== false) {
        scope.diagnostic(
          "dynamic_certificate_validation_option",
          "/parameters/options/allowUnauthorizedCerts",
        );
      }
    }
    const rawUrl = node.parameters.url;
    const urlLocation = present(node.parameters, "url")
      ? "/parameters/url"
      : "/parameters";
    if (typeof rawUrl !== "string" || rawUrl.startsWith("=")) {
      scope.diagnostic("transport_url_unresolved", urlLocation);
    } else {
      const url = URL.parse(rawUrl);
      if (!url || !["http:", "https:"].includes(url.protocol)) {
        scope.diagnostic("unsupported_transport_url", urlLocation);
      } else {
        if (url.protocol === "http:") {
          scope.finding(
            "plaintext_http_url",
            urlLocation,
            "medium",
            "configuration",
            ["deployment_network_context_unverified"],
          );
        }
        if (url.username || url.password) {
          scope.finding(
            "url_contains_authentication_material",
            urlLocation,
            "high",
            "configuration",
            ["credential_validity_not_checked"],
          );
        }
      }
    }
    scope.finish();
  }
  return finishRule(rule);
}

function immediateWebhookReference(
  context: Context,
  node: NormalizedNode,
  command: string,
): NormalizedNode | undefined {
  const templates = [...command.matchAll(/\{\{([^{}]+)\}\}/g)];
  if (
    templates.length !== 1 ||
    templates[0]?.[1] === undefined ||
    [...command.matchAll(/\{\{/g)].length !== 1
  )
    return;
  const reference = parseReference(templates[0][1]);
  if (
    !reference ||
    ["__proto__", "constructor", "prototype"].includes(reference.field)
  )
    return;
  const incoming = context.edges.filter(({ to }) => to === node.key);
  if (
    incoming.length !== 1 ||
    incoming[0]?.input !== 0 ||
    incoming[0].output !== 0
  )
    return;
  const source = context.nodeByKey.get(incoming[0].from);
  if (
    !source ||
    source.disabled ||
    node.disabled ||
    source.type !== "n8n-nodes-base.webhook" ||
    !webhookVersions.has(source.typeVersion) ||
    source.parameters.multipleMethods === true ||
    (source.parameters.options !== undefined &&
      (!isObject(source.parameters.options) ||
        Object.keys(source.parameters.options).length !== 0)) ||
    source.raw.continueOnFail === true ||
    (source.raw.onError !== undefined &&
      source.raw.onError !== "stopWorkflow") ||
    context.unsupportedEdges.some(
      ({ from, to }) =>
        from === node.key ||
        to === node.key ||
        from === source.key ||
        to === source.key,
    ) ||
    (reference.kind === "direct" && reference.nodeName !== source.name)
  )
    return;
  return source;
}

function commandContent(
  context: Context,
  node: NormalizedNode,
  scope: Scope,
): void {
  const command = node.parameters.command;
  const suffix = present(node.parameters, "command")
    ? "/parameters/command"
    : "/parameters";
  if (typeof command !== "string" || command.length === 0) {
    scope.diagnostic("command_content_missing", suffix);
    return;
  }
  scope.finding(
    "command_execution_capability",
    suffix,
    "medium",
    "configuration",
    ["runtime_account_permissions_unverified"],
  );
  if (!command.startsWith("=")) return;
  const source = immediateWebhookReference(context, node, command);
  if (source) {
    scope.finding(
      "webhook_body_used_in_command_expression",
      suffix,
      "high",
      "supported_path",
      ["single_json_webhook_item", "shell_context_not_executed"],
      [{ code: "webhook_body_source", location: locationFor(source) }],
    );
  } else {
    scope.finding("dynamic_command_expression", suffix, "medium", "candidate", [
      "expression_not_evaluated",
    ]);
    scope.diagnostic("command_input_origin_unresolved", suffix);
  }
}

function memberName(value: unknown): string | undefined {
  if (!isObject(value) || value.type !== "MemberExpression") return;
  const property = value.property;
  if (!isObject(property)) return;
  if (
    value.computed === false &&
    property.type === "Identifier" &&
    typeof property.name === "string"
  )
    return property.name;
  if (
    value.computed === true &&
    property.type === "Literal" &&
    typeof property.value === "string"
  )
    return property.value;
}

function literalRequire(value: unknown): string | undefined {
  if (
    !isObject(value) ||
    value.type !== "CallExpression" ||
    !isObject(value.callee) ||
    value.callee.type !== "Identifier" ||
    value.callee.name !== "require" ||
    !Array.isArray(value.arguments) ||
    value.arguments.length !== 1
  )
    return;
  const argument = value.arguments[0];
  return isObject(argument) &&
    argument.type === "Literal" &&
    typeof argument.value === "string"
    ? argument.value
    : undefined;
}

function wholeInput(value: unknown): boolean {
  if (!isObject(value)) return false;
  if (value.type === "Identifier" && value.name === "$json") return true;
  if (
    value.type !== "CallExpression" ||
    !isObject(value.callee) ||
    !Array.isArray(value.arguments)
  )
    return false;
  const object = value.callee.object;
  if (!isObject(object) || object.type !== "Identifier") return false;
  const member = memberName(value.callee);
  if (
    object.name === "$input" &&
    ["all", "first", "last"].includes(member ?? "") &&
    value.arguments.length === 0
  )
    return true;
  return (
    object.name === "JSON" &&
    member === "stringify" &&
    value.arguments.length === 1 &&
    wholeInput(value.arguments[0])
  );
}

/** Bounded syntax inventory only. This never runs code or proves its bindings. */
export function inspectJavaScript(source: string): Set<string> {
  const ast = parse(source, {
    ecmaVersion: "latest",
    sourceType: "script",
    allowReturnOutsideFunction: true,
    // The pinned n8n task runner places Code contents inside an async wrapper.
    allowAwaitOutsideFunction: true,
  });
  const candidates = new Set<string>();
  const stack: unknown[] = [ast];
  let visited = 0;
  while (stack.length > 0) {
    const value = stack.pop();
    if (!isObject(value)) continue;
    if (++visited > 50_000) throw new Error("ast_limit");
    if (value.type === "CallExpression" || value.type === "NewExpression") {
      const callee = value.callee;
      if (isObject(callee) && callee.type === "Identifier") {
        if (callee.name === "eval") candidates.add("javascript_eval_call");
        if (callee.name === "Function")
          candidates.add("javascript_function_constructor");
      }
      if (isObject(callee) && callee.type === "MemberExpression") {
        if (
          isObject(callee.object) &&
          callee.object.type === "Identifier" &&
          callee.object.name === "console" &&
          ["log", "info", "warn", "error", "debug", "dir", "table"].includes(
            memberName(callee) ?? "",
          ) &&
          Array.isArray(value.arguments) &&
          value.arguments.some(wholeInput)
        )
          candidates.add("javascript_whole_input_log_call");
        const dependency = literalRequire(callee.object);
        if (
          (dependency === "child_process" ||
            dependency === "node:child_process") &&
          ["exec", "execSync", "spawn", "spawnSync"].includes(
            memberName(callee) ?? "",
          )
        )
          candidates.add("javascript_process_execution_call");
      }
      const dependency = literalRequire(value);
      if (
        [
          "child_process",
          "node:child_process",
          "fs",
          "node:fs",
          "fs/promises",
          "node:fs/promises",
          "vm",
          "node:vm",
        ].includes(dependency ?? "")
      )
        candidates.add("javascript_privileged_module_reference");
    }
    for (const child of Object.values(value)) {
      if (Array.isArray(child)) stack.push(...child);
      else if (isObject(child)) stack.push(child);
    }
  }
  return candidates;
}

function executableContent(context: Context): RuleResult {
  const rule = makeRule("N8N_EXECUTABLE_CONTENT", "code_execution");
  for (const node of context.nodes) {
    if (
      ![
        "n8n-nodes-base.executeCommand",
        "n8n-nodes-base.ssh",
        "n8n-nodes-base.code",
        "n8n-nodes-base.function",
        "n8n-nodes-base.functionItem",
      ].includes(node.type)
    )
      continue;
    const scope = new Scope(rule, node);
    if (
      node.type === "n8n-nodes-base.executeCommand" ||
      node.type === "n8n-nodes-base.ssh"
    ) {
      if (node.typeVersion !== 1)
        scope.diagnostic("unsupported_node_version", "/typeVersion");
      else if (
        node.type === "n8n-nodes-base.ssh" &&
        (present(node.parameters, "resource")
          ? node.parameters.resource
          : "command") !== "command"
      ) {
        if (node.parameters.resource !== "file")
          scope.diagnostic("unsupported_ssh_resource", "/parameters");
      } else if (
        node.type === "n8n-nodes-base.ssh" &&
        (present(node.parameters, "operation")
          ? node.parameters.operation
          : "execute") !== "execute"
      ) {
        scope.diagnostic("unsupported_ssh_operation", "/parameters");
      } else commandContent(context, node, scope);
      scope.finish();
      continue;
    }
    scope.finding(
      "custom_code_node_declared",
      "/type",
      "info",
      "configuration",
      ["runtime_sandbox_permissions_unverified"],
    );
    if (
      node.type !== "n8n-nodes-base.code" ||
      !codeVersions.has(node.typeVersion)
    ) {
      scope.diagnostic("unsupported_code_profile", "/typeVersion");
      scope.finish();
      continue;
    }
    const language =
      node.typeVersion === 1
        ? "javaScript"
        : present(node.parameters, "language")
          ? node.parameters.language
          : "javaScript";
    if (language !== "javaScript") {
      scope.diagnostic(
        "unsupported_code_language",
        present(node.parameters, "language")
          ? "/parameters/language"
          : "/parameters",
      );
    } else if (typeof node.parameters.jsCode !== "string") {
      scope.diagnostic("javascript_source_missing", "/parameters");
    } else {
      try {
        const candidates = inspectJavaScript(node.parameters.jsCode);
        for (const code of candidates) {
          if (code === "javascript_whole_input_log_call") continue;
          scope.finding(
            code,
            "/parameters/jsCode",
            code === "javascript_privileged_module_reference"
              ? "medium"
              : "high",
            "candidate",
            [
              "lexical_binding_unverified",
              "runtime_sandbox_permissions_unverified",
              "bounded_ast_patterns_only",
            ],
          );
        }
      } catch {
        scope.diagnostic("javascript_parse_unavailable", "/parameters/jsCode");
      }
    }
    scope.finish();
  }
  return finishRule(rule);
}

const privilegeProfiles = new Map<
  string,
  { versions: Set<number>; code: string }
>([
  [
    "n8n-nodes-base.executeCommand",
    { versions: new Set([1]), code: "local_command_capability" },
  ],
  [
    "n8n-nodes-base.ssh",
    { versions: new Set([1]), code: "remote_shell_or_file_capability" },
  ],
  [
    "n8n-nodes-base.readBinaryFile",
    { versions: new Set([1]), code: "local_file_read_capability" },
  ],
  [
    "n8n-nodes-base.writeBinaryFile",
    { versions: new Set([1]), code: "local_file_write_capability" },
  ],
  [
    "n8n-nodes-base.readWriteFile",
    { versions: new Set([1, 1.1]), code: "local_file_access_capability" },
  ],
  [
    "n8n-nodes-base.code",
    { versions: codeVersions, code: "custom_code_capability" },
  ],
]);

// A reviewed capability inventory is deliberately separate from expression,
// value-flow and runtime permission profiles. Exact versions come from the
// pinned node description/dispatch, never a range inferred from a sample.
const builtinProfiles = new Map<
  string,
  { versions: Set<number>; code: string }
>([
  [
    "n8n-nodes-base.webhook",
    { versions: webhookVersions, code: "request_endpoint_capability" },
  ],
  [
    "n8n-nodes-base.httpRequest",
    { versions: httpVersions, code: "outbound_http_capability" },
  ],
  [
    "n8n-nodes-base.postgres",
    {
      versions: new Set([2.4, 2.5, 2.6, 2.8]),
      code: "database_access_capability",
    },
  ],
  [
    "n8n-nodes-base.if",
    {
      versions: new Set([1, 2, 2.1, 2.2, 2.3, 2.4]),
      code: "conditional_routing_capability",
    },
  ],
  [
    "n8n-nodes-base.respondToWebhook",
    {
      versions: new Set([1, 1.1, 1.2, 1.3, 1.4, 1.5]),
      code: "webhook_response_capability",
    },
  ],
  [
    "n8n-nodes-base.stickyNote",
    { versions: new Set([1]), code: "workflow_annotation_declared" },
  ],
  [
    "n8n-nodes-base.manualTrigger",
    { versions: new Set([1]), code: "manual_trigger_capability" },
  ],
  [
    "n8n-nodes-base.scheduleTrigger",
    {
      versions: new Set([1, 1.1, 1.2, 1.3, 1.4]),
      code: "scheduled_trigger_capability",
    },
  ],
  [
    "n8n-nodes-base.errorTrigger",
    { versions: new Set([1]), code: "error_event_trigger_capability" },
  ],
  [
    "n8n-nodes-base.noOp",
    { versions: new Set([1]), code: "pass_through_capability" },
  ],
]);

function dependencies(context: Context): RuleResult {
  const rule = makeRule("N8N_DEPENDENCY_CAPABILITIES", "dependencies");
  rule.profileVersion = "1.1.0";
  for (const node of context.nodes) {
    const scope = new Scope(rule, node);
    const privilege = privilegeProfiles.get(node.type);
    if (privilege !== undefined) {
      scope.finding(privilege.code, "/type", "info", "configuration", [
        "runtime_account_permissions_unverified",
        "installed_package_version_unverified",
      ]);
      if (!privilege.versions.has(node.typeVersion))
        scope.diagnostic("unsupported_node_version", "/typeVersion");
    } else if (node.type === "n8n-nodes-base.executeWorkflow") {
      scope.finding(
        "subworkflow_execution_declared",
        "/type",
        "info",
        "configuration",
        ["referenced_workflow_not_executed"],
      );
      if (!subworkflowVersions.has(node.typeVersion))
        scope.diagnostic("unsupported_node_version", "/typeVersion");
      const inline =
        node.parameters.source === "parameter" &&
        typeof node.parameters.workflowJson === "string" &&
        node.parameters.workflowJson.trim().length > 0;
      scope.diagnostic(
        inline
          ? "inline_subworkflow_not_analyzed"
          : "subworkflow_content_not_provided",
        "/parameters",
      );
    } else if (node.type.startsWith("@n8n/n8n-nodes-langchain.")) {
      scope.finding("ai_node_declared", "/type", "info", "configuration", [
        "model_and_tool_permissions_unverified",
      ]);
      scope.diagnostic("ai_node_semantics_unreviewed", "/typeVersion");
    } else if (!node.type.startsWith("n8n-nodes-base.")) {
      scope.finding(
        "community_or_external_node_declared",
        "/type",
        "info",
        "configuration",
        ["package_name_and_type_are_untrusted_declarations"],
      );
      scope.diagnostic(
        "installed_package_version_and_content_missing",
        "/type",
      );
    } else {
      const profile = builtinProfiles.get(node.type);
      if (profile === undefined)
        scope.diagnostic("builtin_capability_profile_unreviewed", "/type");
      else if (!profile.versions.has(node.typeVersion))
        scope.diagnostic("unsupported_node_version", "/typeVersion");
      else
        scope.finding(profile.code, "/type", "info", "configuration", [
          "capability_inventory_only",
          "operation_and_dataflow_not_established_by_inventory",
          "installed_package_version_unverified",
        ]);
    }
    if (
      context.unsupportedEdges.some(
        ({ from, channel }) => from === node.key && channel === "ai_tool",
      )
    ) {
      scope.finding(
        "ai_tool_connection_declared",
        "/type",
        "info",
        "configuration",
        ["model_and_tool_permissions_unverified"],
      );
      scope.diagnostic("ai_tool_approval_and_access_unverified", "/type");
    } else if (context.unsupportedEdges.some(({ from }) => from === node.key)) {
      scope.diagnostic("non_main_connection_semantics_unreviewed", "/type");
    }
    scope.finish();
  }
  return finishRule(rule);
}

export function analyzeSettings(context: Context): RuleResult[] {
  return [
    requestAuthentication(context),
    transportSettings(context),
    executableContent(context),
    dependencies(context),
  ];
}
