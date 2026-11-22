import { parse } from "acorn";
import type {
  AssessmentEvidence,
  DataClass,
  SinkKind,
} from "./assessment-evidence.js";
import {
  assessDestination,
  canonicalEvidenceField,
} from "./assessment-evidence.js";
import type { NormalizedNode } from "./n8n.js";
import { isObject } from "./static-context.js";
import type { Context } from "./static-context.js";
import { locationFor, stableId } from "./static-contract.js";
import type { Finding, RuleResult, StaticLocation } from "./static-contract.js";
import type { AbstractValue, ValueFlow } from "./value-flow.js";

const base = "n8n-nodes-base.";
const root: StaticLocation = { nodeKey: null, pointer: "/nodes" };
const httpVersions = [3, 4, 4.1, 4.2, 4.3, 4.4, 4.5];
const responseVersions = [1, 1.1, 1.2, 1.3, 1.4, 1.5];
type Field = { pointer: string; value: unknown; name?: string };
type Profile = {
  sink: SinkKind;
  recipients: Field[];
  content: Field[];
  diagnostics: string[];
  opaqueDestination?: boolean;
};

function makeRule(ruleId: string, category: "egress" | "output"): RuleResult {
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
  readonly findings = new Set<string>();
  readonly diagnostics = new Set<string>();
  constructor(
    readonly rule: RuleResult,
    readonly node: NormalizedNode,
  ) {}
  diagnostic(code: string): void {
    let location = locationFor(this.node, "/parameters");
    if (this.rule.diagnostics.length >= 128) {
      code = "diagnostic_limit";
      location = root;
    }
    const id = stableId(this.rule.ruleId, location, code);
    if (!this.rule.diagnostics.some((item) => item.id === id))
      this.rule.diagnostics.push({ id, code, location });
    this.diagnostics.add(id);
  }
  finding(
    code: string,
    pointer: string,
    claim: Finding["claim"] = "configuration",
    value?: AbstractValue,
    severity: Finding["severity"] = "info",
    policyCodes: string[] = [],
  ): void {
    const location = locationFor(this.node, pointer);
    const id = stableId(this.rule.ruleId, location, code);
    if (this.rule.findings.some((item) => item.id === id)) {
      this.findings.add(id);
      return;
    }
    if (this.rule.findings.length >= 128) {
      this.diagnostic("finding_limit");
      return;
    }
    const evidence: Finding["evidence"] = [{ code, location }];
    for (const policyCode of policyCodes)
      if (
        [
          "destination_not_allowlisted",
          "destination_denylisted",
          "data_class_not_allowed",
        ].includes(policyCode)
      )
        evidence.push({ code: policyCode, location });
    for (const origin of value?.origins ?? []) {
      // Field paths contain user-controlled keys and remain private to the flow engine.
      if (evidence.length >= 16) break;
      const source = this.context?.nodeByKey.get(origin.nodeKey);
      if (
        source &&
        !evidence.some((item) => item.location.nodeKey === source.key)
      )
        evidence.push({
          code:
            origin.kind === "database"
              ? "database_result_origin"
              : "data_origin",
          location: locationFor(source, "/parameters"),
        });
    }
    for (const path of value?.paths ?? [])
      for (const key of path) {
        if (evidence.length >= 16) break;
        const hop = this.context?.nodeByKey.get(key);
        if (hop && !evidence.some((item) => item.location.nodeKey === hop.key))
          evidence.push({
            code: "data_flow_hop",
            location: locationFor(hop, "/parameters"),
          });
      }
    this.rule.findings.push({
      id,
      ruleId: this.rule.ruleId,
      category: this.rule.category,
      severity,
      claim,
      location,
      evidence,
      assumptions: [
        "static_definition_only",
        "runtime_values_unverified",
        "transfer_not_proof_of_leak",
      ],
      remediation: {
        code: "review_destination_and_minimize_data",
        checks: [
          "verify_recipient_and_purpose",
          "select_required_fields",
          "rescan_changed_file",
        ],
      },
    });
    this.findings.add(id);
  }
  context?: Context;
  finish(): void {
    this.rule.coverage.push({
      location: locationFor(this.node, "/parameters"),
      status: this.diagnostics.size ? "partial" : "checked",
      findingIds: [...this.findings],
      diagnosticIds: [...this.diagnostics],
    });
  }
}

function add(
  profile: Profile,
  list: "recipients" | "content",
  pointer: string,
  value: unknown,
  required = false,
  name?: string,
): void {
  if (value !== undefined && value !== "")
    profile[list].push({ pointer: "/parameters/" + pointer, value, name });
  else if (required) profile.diagnostics.push("required_send_field_missing");
}
function options(value: unknown, profile: Profile): Record<string, unknown> {
  if (value === undefined) return {};
  if (isObject(value)) return value;
  profile.diagnostics.push("send_options_unresolved");
  profile.opaqueDestination = true;
  return {};
}
function unsupported(profile: Profile, code: string): Profile {
  profile.diagnostics.push(code);
  profile.opaqueDestination = true;
  return profile;
}

/** Exact field semantics are pinned to n8n 86dff76e10efba250a4d3e57760e4eb5d2bbea25. */
function sendProfile(node: NormalizedNode): Profile | undefined {
  const p = node.parameters;
  const type = node.type.slice(base.length);
  if (
    !["emailSend", "gmail", "slack", "telegram", "httpRequest"].includes(
      type,
    ) ||
    !node.type.startsWith(base)
  )
    return;
  const profile: Profile = {
    sink:
      type === "httpRequest"
        ? "http"
        : type === "emailSend" || type === "gmail"
          ? "email"
          : (type as "slack" | "telegram"),
    recipients: [],
    content: [],
    diagnostics: [],
  };
  if (type === "httpRequest") {
    if (!httpVersions.includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    add(profile, "recipients", "url", p.url, true);
    // The URL's query/path can themselves contain transferred data.
    add(profile, "content", "url", p.url);
    for (const [enabled, mode, pairs, json] of [
      ["sendQuery", "specifyQuery", "queryParameters", "jsonQuery"],
      ["sendHeaders", "specifyHeaders", "headerParameters", "jsonHeaders"],
    ]) {
      if (p[enabled!] === undefined || p[enabled!] === false) continue;
      if (p[enabled!] !== true) {
        profile.diagnostics.push("http_send_switch_unresolved");
        continue;
      }
      const selected = p[mode!] ?? "keypair";
      if (selected === "json") add(profile, "content", json!, p[json!], true);
      else if (selected === "keypair") pairsContent(profile, pairs!, p[pairs!]);
      else profile.diagnostics.push("http_parameter_mode_unresolved");
    }
    if (p.sendBody === true) {
      const contentType = p.contentType ?? "json";
      const selected = p.specifyBody ?? "keypair";
      if (contentType === "binaryData")
        profile.diagnostics.push("binary_payload_unavailable");
      else if (
        contentType === "raw" ||
        (contentType === "form-urlencoded" && selected === "string")
      )
        add(profile, "content", "body", p.body, true);
      else if (contentType === "json" && selected === "json")
        add(profile, "content", "jsonBody", p.jsonBody, true);
      else if (
        ["json", "form-urlencoded", "multipart-form-data"].includes(
          String(contentType),
        ) &&
        (selected === "keypair" || contentType === "multipart-form-data")
      )
        pairsContent(profile, "bodyParameters", p.bodyParameters);
      else profile.diagnostics.push("http_body_mode_unresolved");
    } else if (p.sendBody !== undefined && p.sendBody !== false)
      profile.diagnostics.push("http_send_switch_unresolved");
    const opts = options(p.options, profile);
    const redirects =
      isObject(opts.redirect) && isObject(opts.redirect.redirect)
        ? opts.redirect.redirect.followRedirects
        : undefined;
    if (redirects !== false)
      profile.diagnostics.push("redirect_destination_unverified");
    return profile;
  }
  if (type === "emailSend") {
    if (![2, 2.1].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "email") !== "email" ||
      (p.operation ?? "send") !== "send"
    )
      return unsupported(profile, "unsupported_send_operation");
    const opts = options(p.options, profile);
    add(profile, "recipients", "toEmail", p.toEmail, true);
    for (const key of ["ccEmail", "bccEmail"])
      add(profile, "recipients", "options/" + key, opts[key]);
    add(profile, "content", "subject", p.subject);
    const format = p.emailFormat ?? (node.typeVersion === 2 ? "text" : "html");
    if (format === "text" || format === "both")
      add(profile, "content", "text", p.text);
    if (format === "html" || format === "both")
      add(profile, "content", "html", p.html);
    if (!["text", "html", "both"].includes(String(format)))
      profile.diagnostics.push("email_format_unresolved");
    if (opts.attachments || opts.fileAttachments)
      profile.diagnostics.push("binary_payload_unavailable");
    return profile;
  }
  if (type === "gmail") {
    if (![2, 2.1, 2.2].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "message") !== "message" ||
      (p.operation ?? "send") !== "send"
    )
      return unsupported(profile, "unsupported_send_operation");
    const opts = options(p.options, profile);
    add(profile, "recipients", "sendTo", p.sendTo, true);
    for (const key of ["ccList", "bccList"])
      add(profile, "recipients", "options/" + key, opts[key]);
    add(profile, "content", "subject", p.subject);
    add(profile, "content", "message", p.message, true);
    if (opts.attachmentsUi)
      profile.diagnostics.push("binary_payload_unavailable");
    return profile;
  }
  if (type === "slack") {
    if (![2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "message") !== "message" ||
      !["post", "schedule"].includes(String(p.operation ?? "post"))
    )
      return unsupported(profile, "unsupported_send_operation");
    const destinationField =
      p.select === "channel"
        ? "channelId"
        : p.select === "user"
          ? "user"
          : undefined;
    if (!destinationField)
      profile.diagnostics.push("message_recipient_mode_unresolved");
    else {
      const locator = p[destinationField];
      if (isObject(locator) && ["id", "list"].includes(String(locator.mode)))
        add(
          profile,
          "recipients",
          destinationField + "/value",
          locator.value,
          true,
        );
      else {
        add(
          profile,
          "recipients",
          destinationField,
          isObject(locator) ? locator.value : locator,
        );
        profile.opaqueDestination = true;
        profile.diagnostics.push("recipient_identity_unresolved");
      }
    }
    const messageType = p.messageType ?? "text";
    if (messageType === "text" || messageType === "block")
      add(profile, "content", "text", p.text);
    if (messageType === "block") {
      add(profile, "content", "blocksUi", p.blocksUi, true);
      profile.diagnostics.push("structured_message_overrides_unverified");
      profile.opaqueDestination = true;
    } else if (messageType === "attachment")
      add(profile, "content", "attachments", p.attachments, true);
    else if (messageType !== "text")
      profile.diagnostics.push("message_format_unresolved");
    const opts = options(p.otherOptions, profile);
    const known = new Set([
      "includeLinkToWorkflow",
      "thread_ts",
      "reply_broadcast",
      "unfurl_links",
      "unfurl_media",
      "mrkdwn",
      "link_names",
      "sendAsUser",
    ]);
    if (Object.keys(opts).some((key) => !known.has(key))) {
      profile.diagnostics.push("message_options_overrides_unverified");
      profile.opaqueDestination = true;
    }
    if ((opts.includeLinkToWorkflow ?? node.typeVersion >= 2.1) !== false)
      profile.diagnostics.push("instance_workflow_link_included");
    return profile;
  }
  if (![1, 1.1, 1.2].includes(node.typeVersion))
    return unsupported(profile, "unsupported_node_version");
  if (
    (p.resource ?? "message") !== "message" ||
    (p.operation ?? "sendMessage") !== "sendMessage"
  )
    return unsupported(profile, "unsupported_send_operation");
  add(profile, "recipients", "chatId", p.chatId, true);
  add(profile, "content", "text", p.text, true);
  const extra = options(p.additionalFields, profile);
  const known = new Set([
    "appendAttribution",
    "disable_notification",
    "disable_web_page_preview",
    "parse_mode",
    "reply_to_message_id",
    "message_thread_id",
  ]);
  if (Object.keys(extra).some((key) => !known.has(key))) {
    profile.diagnostics.push("message_options_overrides_unverified");
    profile.opaqueDestination = true;
  }
  return profile;
}

function pairsContent(profile: Profile, key: string, value: unknown): void {
  if (value === undefined) return;
  if (!isObject(value) || !Array.isArray(value.parameters)) {
    profile.diagnostics.push("http_parameters_shape_unresolved");
    return;
  }
  for (const [index, pair] of value.parameters.entries()) {
    if (!isObject(pair)) {
      profile.diagnostics.push("http_parameters_shape_unresolved");
      continue;
    }
    if (pair.parameterType === "formBinaryData")
      profile.diagnostics.push("binary_payload_unavailable");
    else
      add(
        profile,
        "content",
        `${key}/parameters/${index}/value`,
        pair.value,
        false,
        typeof pair.name === "string" ? pair.name : undefined,
      );
    add(profile, "content", `${key}/parameters/${index}/name`, pair.name);
  }
}

function classes(
  value: AbstractValue,
  evidence?: AssessmentEvidence,
): DataClass[] {
  const values = new Set<DataClass>();
  let unclassified = false;
  for (const origin of value.origins) {
    const exact = evidence?.classifications?.filter(
      (item) =>
        item.nodeKey === origin.nodeKey &&
        canonicalEvidenceField(item.field) === origin.fieldPath,
    );
    if (exact?.length) for (const item of exact) values.add(item.dataClass);
    else if (origin.kind !== "literal") unclassified = true;
  }
  // Policies are sets, not a severity ranking: a secret can be permitted while
  // personal data is forbidden in the same object or serialized string.
  for (const sensitivity of value.sensitivityClasses) {
    if (sensitivity === "secret_candidate") values.add("secret");
    else if (sensitivity === "pii_candidate") values.add("personal");
    else if (sensitivity === "public_literal") values.add("public");
  }
  // Exact annotations classify their origin only. They cannot make unknown joins public.
  if (
    value.sensitivityClasses.includes("unknown") &&
    (!values.size ||
      unclassified ||
      value.fullObject ||
      value.status !== "resolved")
  )
    values.add("unknown");
  if (value.fullObject && !value.fields) values.add("unknown");
  // A known sensitive part must not hide an unclassified origin in a join.
  if (
    unclassified &&
    !value.sensitivityClasses.every((kind) => kind === "public_literal")
  )
    values.add("unknown");
  if (value.status !== "resolved") values.add("unknown");
  return [...values];
}

function data(
  scope: Scope,
  field: Field,
  value: AbstractValue,
  evidence?: AssessmentEvidence,
  forceCandidate = false,
): DataClass[] {
  const classified = classes(value, evidence);
  if (value.status !== "resolved")
    scope.diagnostic("payload_provenance_unresolved");
  const path =
    value.status === "resolved" &&
    value.origins.some((origin) => origin.kind !== "literal") &&
    !forceCandidate;
  const claim = path ? "supported_path" : "candidate";
  if (classified.includes("secret"))
    scope.finding(
      "secret_candidate_transferred",
      field.pointer,
      claim,
      value,
      "high",
    );
  if (classified.includes("personal"))
    scope.finding(
      "personal_data_candidate_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  if (
    !classified.includes("secret") &&
    !classified.includes("personal") &&
    value.fullObject
  )
    scope.finding(
      "whole_object_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  else if (
    !classified.includes("secret") &&
    !classified.includes("personal") &&
    value.origins.some((origin) => origin.kind !== "literal")
  )
    scope.finding("data_field_transferred", field.pointer, claim, value);
  if (value.origins.some((origin) => origin.kind === "database"))
    scope.finding(
      "database_result_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  if (classified.includes("unknown"))
    scope.diagnostic("transferred_data_sensitivity_unverified");
  return classified;
}

function destinations(sink: SinkKind, value: unknown): (string | null)[] {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    String(value).trim().startsWith("=")
  )
    return [null];
  const text = String(value).trim();
  if (!text) return [null];
  if (sink === "email") {
    const recipients = text.split(",");
    if (recipients.length > 128) return [null];
    return recipients.map((part) =>
      /^[^\s<>(),;@]+@[^\s<>(),;@]+\.[^\s<>(),;@]+$/.test(part.trim())
        ? part.trim()
        : null,
    );
  }
  if (sink === "http") {
    try {
      const url = new URL(text);
      return [
        url.protocol === "https:" || url.protocol === "http:" ? url.href : null,
      ];
    } catch {
      return [null];
    }
  }
  return [text];
}

function policy(
  scope: Scope,
  sink: SinkKind,
  destination: string | null,
  dataClasses: DataClass[],
  evidence?: AssessmentEvidence,
): void {
  const assessment = assessDestination(
    evidence,
    scope.node.key,
    sink,
    destination,
    dataClasses,
  );
  if (assessment.status === "disallowed")
    scope.finding(
      "trusted_policy_transfer_disallowed",
      "/parameters",
      "configuration",
      undefined,
      "high",
      assessment.codes,
    );
  if (assessment.status === "unknown")
    scope.diagnostic("trusted_policy_transfer_unresolved");
}

function outgoing(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const result = makeRule("N8N_EXTENDED_OUTBOUND_DATA", "egress");
  for (const node of context.nodes) {
    const profile = sendProfile(node);
    if (!profile) continue;
    const scope = new Scope(result, node);
    scope.context = context;
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    scope.finding(
      profile.diagnostics.some(
        (code) =>
          code === "unsupported_send_operation" ||
          code === "unsupported_node_version",
      )
        ? "external_connector_declared"
        : "outbound_send_capability",
      "/type",
    );
    profile.diagnostics.forEach((code) => scope.diagnostic(code));
    const allClasses = new Set<DataClass>();
    for (const field of profile.content) {
      const value = flow.resolve(node.key, field.value, {
        fieldName: field.name,
      });
      data(scope, field, value, evidence).forEach((kind) =>
        allClasses.add(kind),
      );
    }
    for (const field of profile.recipients) {
      const value = flow.resolve(node.key, field.value);
      if (value.status !== "resolved")
        scope.diagnostic("recipient_provenance_unresolved");
      if (typeof field.value === "string" && field.value.startsWith("="))
        scope.finding(
          "dynamic_recipient_or_destination",
          field.pointer,
          value.status === "resolved" &&
            value.origins.some((origin) => origin.kind !== "literal")
            ? "supported_path"
            : "candidate",
          value,
          "medium",
        );
      for (const destination of destinations(profile.sink, field.value))
        policy(
          scope,
          profile.sink,
          profile.opaqueDestination ? null : destination,
          [...allClasses],
          evidence,
        );
    }
    if (profile.opaqueDestination || !profile.recipients.length)
      policy(scope, profile.sink, null, [...allClasses], evidence);
    if (
      node.raw.continueOnFail === true ||
      node.raw.onError !== undefined ||
      node.raw.alwaysOutputData === true
    )
      scope.diagnostic("nonstandard_execution_semantics");
    scope.finish();
  }
  return finish(result);
}

function response(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const result = makeRule("N8N_EXTENDED_OUTPUT_DATA", "output");
  for (const node of context.nodes) {
    const respond = node.type === base + "respondToWebhook";
    const last =
      node.type === base + "webhook" &&
      node.parameters.responseMode === "lastNode";
    const code = node.type === base + "code";
    if (!respond && !last && !code) continue;
    const scope = new Scope(result, node);
    scope.context = context;
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    if (code) {
      logFields(scope, flow, evidence);
      scope.finish();
      continue;
    }
    const versions = respond ? responseVersions : [2, 2.1, 2.2];
    if (!versions.includes(node.typeVersion)) {
      scope.diagnostic("unsupported_node_version");
      scope.finish();
      continue;
    }
    const p = node.parameters;
    const mode = respond
      ? (p.respondWith ?? "firstIncomingItem")
      : (p.responseData ?? "firstEntryJson");
    const opts = isObject(p.options) ? p.options : {};
    if (
      mode === "noData" ||
      (last && p.responseData === undefined && opts.noResponseBody === true)
    ) {
      scope.finish();
      continue;
    }
    const values: { field: Field; value: AbstractValue }[] = [];
    if (
      respond &&
      (mode === "firstIncomingItem" || mode === "allIncomingItems")
    )
      values.push({
        field: { pointer: "/parameters/respondWith", value: "" },
        value: flow.resolve(node.key, "={{ $json }}"),
      });
    else if (respond && (mode === "json" || mode === "text"))
      values.push({
        field: { pointer: "/parameters/responseBody", value: p.responseBody },
        value: flow.resolve(node.key, p.responseBody ?? ""),
      });
    else if (last && (mode === "allEntries" || mode === "firstEntryJson")) {
      const terminal = terminalNodes(context, node.key);
      if (!terminal.length) scope.diagnostic("last_response_source_unresolved");
      const field =
        typeof opts.responsePropertyName === "string" &&
        !opts.responsePropertyName.startsWith("=")
          ? opts.responsePropertyName
          : "";
      if (opts.responsePropertyName !== undefined && !field)
        scope.diagnostic("response_projection_unresolved");
      for (const source of terminal)
        values.push({
          field: { pointer: "/parameters/responseData", value: "" },
          value: flow.output(source.key, field),
        });
      if (terminal.length > 1)
        scope.diagnostic("last_response_order_unverified");
    } else {
      scope.diagnostic("response_mode_unresolved");
      scope.finish();
      continue;
    }
    const allClasses = new Set<DataClass>();
    for (const { field, value } of values)
      data(scope, field, value, evidence).forEach((kind) =>
        allClasses.add(kind),
      );
    policy(scope, "response", "caller", [...allClasses], evidence);
    scope.diagnostic("response_recipient_authorization_unverified");
    scope.finish();
  }
  return finish(result);
}

function terminalNodes(context: Context, start: string): NormalizedNode[] {
  const visited = new Set<string>();
  const queue = [start];
  const leaves: NormalizedNode[] = [];
  while (queue.length && visited.size <= 128) {
    const key = queue.shift()!;
    if (visited.has(key)) continue;
    visited.add(key);
    const next = context.edges.filter((edge) => edge.from === key);
    if (!next.length && key !== start) {
      const node = context.nodeByKey.get(key);
      if (node) leaves.push(node);
    }
    for (const edge of next) queue.push(edge.to);
  }
  return leaves;
}

function logFields(
  scope: Scope,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): void {
  const node = scope.node;
  if (
    ![1, 2].includes(node.typeVersion) ||
    (node.parameters.language ?? "javaScript") !== "javaScript" ||
    typeof node.parameters.jsCode !== "string"
  ) {
    scope.diagnostic("unsupported_log_code_profile");
    return;
  }
  const source = node.parameters.jsCode;
  try {
    const ast: unknown = parse(source, {
      ecmaVersion: "latest",
      sourceType: "script",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
    });
    const pending: unknown[] = [ast];
    let count = 0;
    const argumentsToInspect: { start: number; end: number }[] = [];
    while (pending.length && count++ < 10000) {
      const item = pending.pop();
      if (!isObject(item)) continue;
      if (
        item.type === "CallExpression" &&
        isObject(item.callee) &&
        item.callee.type === "MemberExpression" &&
        item.callee.computed === false &&
        isObject(item.callee.object) &&
        item.callee.object.type === "Identifier" &&
        item.callee.object.name === "console" &&
        isObject(item.callee.property) &&
        ["log", "info", "warn", "error", "debug", "table", "dir"].includes(
          String(item.callee.property.name),
        )
      ) {
        for (const arg of Array.isArray(item.arguments) ? item.arguments : [])
          if (
            isObject(arg) &&
            Number.isInteger(arg.start) &&
            Number.isInteger(arg.end)
          )
            argumentsToInspect.push({
              start: arg.start as number,
              end: arg.end as number,
            });
      }
      for (const child of Object.values(item)) {
        if (Array.isArray(child)) pending.push(...child);
        else if (isObject(child)) pending.push(child);
      }
    }
    if (pending.length) scope.diagnostic("javascript_ast_limit");
    for (const arg of argumentsToInspect.slice(0, 128)) {
      const value = flow.resolve(
        node.key,
        "={{ " + source.slice(arg.start, arg.end) + " }}",
      );
      const kinds = data(
        scope,
        { pointer: "/parameters/jsCode", value: "" },
        value,
        evidence,
        true,
      );
      scope.finding(
        "console_output_call_candidate",
        "/parameters/jsCode",
        "candidate",
        value,
        "low",
      );
      policy(scope, "log", "execution_log", kinds, evidence);
    }
    if (argumentsToInspect.length > 128) scope.diagnostic("log_argument_limit");
    // Parse-only AST matching does not establish lexical bindings or all logging APIs.
    scope.diagnostic("code_logging_semantics_partial");
  } catch {
    scope.diagnostic("javascript_parse_unavailable");
  }
}

function finish(result: RuleResult): RuleResult {
  if (!result.coverage.length)
    result.coverage.push({
      location: root,
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  return result;
}

export function analyzeExtendedSinks(
  context: Context,
  valueFlow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult[] {
  return [
    outgoing(context, valueFlow, evidence),
    response(context, valueFlow, evidence),
  ];
}
