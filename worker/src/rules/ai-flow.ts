import { createHash } from "node:crypto";
import type { NormalizedNode, UnsupportedEdge } from "../workflow/n8n.js";
import type { Context } from "../workflow/static-context.js";
import { isObject, stringSelector } from "../workflow/static-context.js";
import {
  locationFor,
  stableId,
  type Evidence,
  type Finding,
  type RuleResult,
  type StaticLocation,
} from "../contracts/static-contract.js";
import {
  assessDestination,
  type AssessmentEvidence,
  type DataClass,
} from "../assessment/assessment-evidence.js";
import { isExternalValue } from "../workflow/value-flow.js";
import type { AbstractValue, ValueFlow } from "../workflow/value-flow.js";
import {
  binaryInputProvenance,
  type BinaryInput,
} from "../workflow/binary-provenance.js";
import {
  parseLiteralJsonData,
  resolveLiteralData,
  transferDataClasses,
} from "./extended-sinks.js";

const prefix = "@n8n/n8n-nodes-langchain.";
const versions = (...values: number[]) => new Set(values);
type Role =
  | "agent"
  | "agent_tool"
  | "chain"
  | "qa"
  | "model"
  | "memory"
  | "retriever"
  | "parser"
  | "http_tool"
  | "sql_tool"
  | "code_tool"
  | "workflow_tool"
  | "retrieval_tool"
  | "utility_tool"
  | "lookup_tool"
  | "vector_tool"
  | "vector_store"
  | "embedding"
  | "document_loader"
  | "text_splitter";
type Profile = { role: Role; versions: ReadonlySet<number> };

// Version declarations and dispatch are pinned in docs/ai-flow.md. These are
// contracts for definitions and possible data paths, never execution profiles.
const profiles = new Map<string, Profile>([
  [
    prefix + "agent",
    { role: "agent", versions: versions(1.7, 1.8, 1.9, 2, 2.1, 2.2) },
  ],
  [prefix + "agentTool", { role: "agent_tool", versions: versions(2.2) }],
  [
    prefix + "chainLlm",
    { role: "chain", versions: versions(1.5, 1.6, 1.7, 1.8, 1.9) },
  ],
  [
    prefix + "chainRetrievalQa",
    { role: "qa", versions: versions(1.3, 1.4, 1.5, 1.6, 1.7) },
  ],
  [
    prefix + "lmChatOpenAi",
    { role: "model", versions: versions(1, 1.1, 1.2, 1.3) },
  ],
  [
    prefix + "lmChatGoogleGemini",
    { role: "model", versions: versions(1, 1.1, 1.2) },
  ],
  [prefix + "lmChatOpenRouter", { role: "model", versions: versions(1) }],
  [prefix + "lmChatGroq", { role: "model", versions: versions(1) }],
  [
    prefix + "memoryMongoDbChat",
    { role: "memory", versions: versions(1, 1.1) },
  ],
  [
    prefix + "embeddingsGoogleGemini",
    { role: "embedding", versions: versions(1) },
  ],
  [
    prefix + "embeddingsOpenAi",
    { role: "embedding", versions: versions(1, 1.1, 1.2) },
  ],
  [
    prefix + "vectorStorePinecone",
    { role: "vector_store", versions: versions(1) },
  ],
  [
    prefix + "vectorStoreSupabase",
    { role: "vector_store", versions: versions(1.3) },
  ],
  [
    prefix + "documentDefaultDataLoader",
    { role: "document_loader", versions: versions(1, 1.1) },
  ],
  [
    prefix + "textSplitterRecursiveCharacterTextSplitter",
    { role: "text_splitter", versions: versions(1) },
  ],
  [prefix + "toolWikipedia", { role: "lookup_tool", versions: versions(1) }],
  [
    "n8n-nodes-base.rssFeedReadTool",
    { role: "lookup_tool", versions: versions(1.2) },
  ],
  [
    "n8n-nodes-base.dateTimeTool",
    { role: "utility_tool", versions: versions(2) },
  ],
  [
    "n8n-nodes-base.cryptoTool",
    { role: "utility_tool", versions: versions(1) },
  ],
  [
    prefix + "memoryBufferWindow",
    { role: "memory", versions: versions(1, 1.1, 1.2, 1.3, 1.4) },
  ],
  [
    prefix + "memoryPostgresChat",
    { role: "memory", versions: versions(1, 1.1, 1.2, 1.3, 1.4) },
  ],
  [
    prefix + "memoryRedisChat",
    { role: "memory", versions: versions(1, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6) },
  ],
  [
    prefix + "retrieverVectorStore",
    { role: "retriever", versions: versions(1) },
  ],
  [
    prefix + "outputParserStructured",
    { role: "parser", versions: versions(1, 1.1, 1.2, 1.3) },
  ],
  [
    prefix + "toolHttpRequest",
    { role: "http_tool", versions: versions(1, 1.1) },
  ],
  [
    prefix + "toolCode",
    { role: "code_tool", versions: versions(1, 1.1, 1.2, 1.3) },
  ],
  [
    prefix + "toolWorkflow",
    {
      role: "workflow_tool",
      versions: versions(1, 1.1, 1.2, 1.3, 2, 2.1, 2.2),
    },
  ],
  [
    prefix + "toolVectorStore",
    { role: "retrieval_tool", versions: versions(1, 1.1) },
  ],
  [
    "n8n-nodes-base.httpRequestTool",
    { role: "http_tool", versions: versions(3, 4, 4.1, 4.2, 4.3, 4.4, 4.5) },
  ],
  [
    "n8n-nodes-base.postgresTool",
    {
      role: "sql_tool",
      versions: versions(2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8),
    },
  ],
]);

function profile(node: NormalizedNode): Profile | undefined {
  const result = profiles.get(node.type);
  if (!result?.versions.has(node.typeVersion)) return;
  if (result.role === "vector_store") {
    const mode = node.parameters.mode ?? "retrieve";
    if (
      !["insert", "load", "retrieve", "retrieve-as-tool", "update"].includes(
        stringSelector(mode),
      ) ||
      typeof mode !== "string"
    )
      return;
    if (mode === "retrieve-as-tool") return { ...result, role: "vector_tool" };
  }
  if (
    result.role === "agent" &&
    node.typeVersion < 2 &&
    node.parameters.agent !== undefined &&
    node.parameters.agent !== "toolsAgent"
  )
    return;
  return result;
}

/** Reviewed static definition only; does not mean enabled, executable or safe. */
export function isReviewedAiNode(
  context: Context,
  node: NormalizedNode,
): boolean {
  return context.nodeByKey.has(node.key) && profile(node) !== undefined;
}

function isAgent(role: Role): boolean {
  return role === "agent" || role === "agent_tool";
}
function isConsumer(role: Role): boolean {
  return isAgent(role) || role === "chain" || role === "qa";
}
function isTool(role: Role): boolean {
  return role.endsWith("_tool");
}

/** Exact typed-port compatibility, independently of runtime calls or approval. */
export function coveredAiEdge(
  context: Context,
  edge: UnsupportedEdge,
): boolean {
  const source = context.nodeByKey.get(edge.from);
  const target = context.nodeByKey.get(edge.to);
  if (
    !source ||
    !target ||
    source.disabled ||
    target.disabled ||
    edge.output !== 0
  )
    return false;
  const from = profile(source)?.role;
  const to = profile(target)?.role;
  if (!from || !to) return false;
  const incoming = context.unsupportedEdges.filter(
    (item) => item.to === target.key && item.channel === edge.channel,
  );
  switch (edge.channel) {
    case "ai_languageModel": {
      if (
        from !== "model" ||
        !(
          isConsumer(to) ||
          to === "retrieval_tool" ||
          (to === "parser" && target.parameters.autoFix === true)
        )
      )
        return false;
      const max =
        ((to === "agent" && target.typeVersion >= 2) ||
          to === "agent_tool" ||
          to === "chain") &&
        target.parameters.needsFallback === true
          ? 2
          : 1;
      return (
        edge.input < max &&
        incoming.length <= max &&
        incoming.filter((item) => item.input === edge.input).length === 1
      );
    }
    case "ai_memory":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "memory" &&
        isAgent(to)
      );
    case "ai_tool":
      return edge.input === 0 && isTool(from) && isAgent(to);
    case "ai_outputParser":
      return (
        from === "parser" &&
        edge.input === 0 &&
        incoming.length === 1 &&
        (isAgent(to) || to === "chain") &&
        (target.parameters.hasOutputParser === undefined ||
          target.parameters.hasOutputParser === true)
      );
    case "ai_retriever":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "retriever" &&
        to === "qa"
      );
    case "ai_vectorStore":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "vector_store" &&
        (source.parameters.mode ?? "retrieve") === "retrieve" &&
        (to === "retriever" || to === "retrieval_tool")
      );
    case "ai_embedding":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "embedding" &&
        (to === "vector_store" || to === "vector_tool")
      );
    case "ai_document":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "document_loader" &&
        to === "vector_store" &&
        target.parameters.mode === "insert"
      );
    case "ai_textSplitter":
      return (
        edge.input === 0 &&
        incoming.length === 1 &&
        from === "text_splitter" &&
        to === "document_loader" &&
        (target.typeVersion === 1 ||
          target.parameters.textSplittingMode === "custom")
      );
    default:
      return false;
  }
}

export interface AiPromptInputs {
  inputs: {
    value: unknown;
    pointer: string;
    literalData?: boolean;
    nodeKey?: string;
  }[];
  diagnostics: string[];
}

/** Selected prompt inputs only. Every caller must retain unknown AI output. */
function promptInputs(
  node: NormalizedNode,
  includeTool = false,
  context?: Context,
): AiPromptInputs | undefined {
  const role = profile(node)?.role;
  if (!role || !isConsumer(role) || (role === "agent_tool" && !includeTool))
    return;
  const result: AiPromptInputs = { inputs: [], diagnostics: [] };
  const add = (value: unknown, pointer: string) =>
    result.inputs.push({ value, pointer });
  const unknown = (code: string, pointer = "/parameters") => {
    result.diagnostics.push(code);
    add(undefined, pointer);
  };
  const parameters = node.parameters;
  const promptType =
    role === "agent_tool" ? "define" : (parameters.promptType ?? "auto");
  if (role !== "agent_tool" && parameters.promptType === null)
    unknown("ai_prompt_selector_unresolved");
  else if (promptType === "auto")
    add("={{ $json.chatInput }}", "/parameters/text");
  else if (promptType === "guardrails")
    add("={{ $json.guardrailsInput }}", "/parameters/text");
  else if (promptType === "define") {
    add(parameters.text, "/parameters/text");
    if (typeof parameters.text !== "string")
      unknown("ai_prompt_text_unresolved", "/parameters/text");
  } else unknown("ai_prompt_selector_unresolved");

  const options = parameters.options;
  if (options !== undefined && !isObject(options)) {
    add(options, "/parameters/options");
    unknown("ai_prompt_options_unresolved", "/parameters/options");
  } else {
    const selected = role === "qa" ? "systemPromptTemplate" : "systemMessage";
    if (isObject(options) && Object.hasOwn(options, selected))
      add(options[selected], `/parameters/options/${selected}`);
  }
  if (isAgent(role)) {
    // The default enables a possible transfer, not evidence that a file is
    // missing. Presence and JSON-to-file dependencies are inspected separately.
    if (
      !isObject(options) ||
      options.passthroughBinaryImages !== false ||
      (options.passthroughBinaryPdfs !== undefined &&
        options.passthroughBinaryPdfs !== false)
    ) {
      const binary = context ? binaryInputProvenance(context, node) : undefined;
      if (binary?.state !== "none") {
        result.inputs.push(...(binary?.inputs ?? []));
        unknown("ai_binary_prompt_content_unverified", "/parameters/options");
        result.diagnostics.push(
          ...(binary?.diagnostics ?? ["binary_provenance_unresolved"]),
        );
      }
    }
  }
  if (role === "chain" && parameters.messages !== undefined) {
    if (!isObject(parameters.messages)) {
      add(parameters.messages, "/parameters");
      unknown("ai_chat_message_shape_unresolved");
    } else {
      const messages = parameters.messages.messageValues ?? [];
      if (!Array.isArray(messages)) unknown("ai_chat_message_shape_unresolved");
      else {
        if (messages.length > 32) unknown("ai_prompt_field_limit");
        for (const message of messages.slice(0, 32)) {
          if (!isObject(message)) {
            unknown("ai_chat_message_shape_unresolved");
            continue;
          }
          if (message.message !== undefined)
            add(message.message, "/parameters");
          if (
            message.messageType !== undefined &&
            message.messageType !== "text"
          ) {
            if (message.imageUrl !== undefined)
              add(message.imageUrl, "/parameters");
            if (message.messageType === "imageBinary") {
              const binary = context
                ? binaryInputProvenance(context, node)
                : undefined;
              result.inputs.push(...(binary?.inputs ?? []));
              result.diagnostics.push(
                ...(binary?.diagnostics ?? ["binary_provenance_unresolved"]),
              );
              if (binary?.state === "none")
                unknown("ai_binary_prompt_input_missing");
            } else if (message.messageType !== "imageUrl")
              unknown("ai_chat_message_type_unresolved");
            unknown("ai_binary_prompt_content_unverified");
          }
        }
      }
    }
  }
  return result;
}

export function aiPromptInputs(
  node: NormalizedNode,
  context?: Context,
): AiPromptInputs | undefined {
  return promptInputs(node, false, context);
}

function makeRule(
  ruleId: string,
  category: RuleResult["category"],
): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.2.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}

class Scope {
  readonly findingIds = new Set<string>();
  readonly diagnosticIds = new Set<string>();
  constructor(
    readonly rule: RuleResult,
    readonly node: NormalizedNode,
    readonly context: Context,
  ) {}
  diagnostic(code: string, pointer = "/parameters"): void {
    const location = locationFor(this.node, pointer);
    const id = stableId(this.rule.ruleId, location, code);
    if (this.rule.diagnostics.some((item) => item.id === id)) {
      this.diagnosticIds.add(id);
      return;
    }
    if (this.rule.diagnostics.length >= 64) {
      this.limit();
      return;
    }
    this.rule.diagnostics.push({ id, code, location });
    this.diagnosticIds.add(id);
  }
  private limit(): void {
    const location: StaticLocation = { nodeKey: null, pointer: "" };
    const id = stableId(this.rule.ruleId, location, "ai_analysis_result_limit");
    if (!this.rule.diagnostics.some((item) => item.id === id))
      this.rule.diagnostics.push({
        id,
        code: "ai_analysis_result_limit",
        location,
      });
    this.diagnosticIds.add(id);
  }
  finding(
    code: string,
    options: {
      pointer?: string;
      severity?: Finding["severity"];
      claim?: Finding["claim"];
      values?: AbstractValue[];
      related?: NormalizedNode[];
      extraCodes?: string[];
    } = {},
  ): void {
    const location = locationFor(this.node, options.pointer ?? "/parameters");
    const id = stableId(this.rule.ruleId, location, code);
    const existing = this.rule.findings.find((item) => item.id === id);
    if (!existing && this.rule.findings.length >= 64) {
      this.limit();
      return;
    }
    const evidence: Evidence[] = existing?.evidence ?? [{ code, location }];
    const add = (code: string, location: StaticLocation) => {
      if (
        !evidence.some(
          (item) =>
            item.code === code &&
            item.location.nodeKey === location.nodeKey &&
            item.location.pointer === location.pointer,
        )
      ) {
        if (evidence.length >= 20)
          this.diagnostic("ai_evidence_location_limit");
        else evidence.push({ code, location });
      }
    };
    for (const extra of options.extraCodes ?? []) add(extra, location);
    for (const related of options.related ?? [])
      add("ai_connected_definition", locationFor(related, "/type"));
    for (const value of options.values ?? []) {
      for (const origin of value.origins) {
        const source = this.context.nodeByKey.get(origin.nodeKey);
        if (source)
          add("ai_prompt_data_origin", locationFor(source, "/parameters"));
      }
    }
    if (!existing)
      this.rule.findings.push({
        id,
        ruleId: this.rule.ruleId,
        category: this.rule.category,
        severity: options.severity ?? "info",
        claim: options.claim ?? "configuration",
        location,
        evidence,
        assumptions: [
          "static_definition_only",
          "ai_invocation_not_observed",
          "model_and_tool_permissions_unverified",
          "transfer_not_proof_of_leak",
        ],
        remediation: {
          code: "review_ai_data_and_tool_boundaries",
          checks: [
            "minimize_prompt_and_context_data",
            "validate_tool_arguments_outside_model",
            "restrict_tool_credentials_and_destinations",
            "enforce_required_approval_at_runtime",
          ],
        },
      });
    this.findingIds.add(id);
  }
  finish(unsupported = false): void {
    this.rule.coverage.push({
      location: locationFor(this.node, "/parameters"),
      status: unsupported
        ? "unsupported"
        : this.diagnosticIds.size
          ? "partial"
          : "checked",
      findingIds: [...this.findingIds],
      diagnosticIds: [...this.diagnosticIds],
    });
  }
}

function finish(rule: RuleResult): RuleResult {
  if (!rule.coverage.length)
    rule.coverage.push({
      location: { nodeKey: null, pointer: "" },
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  return rule;
}

function related(
  context: Context,
  node: NormalizedNode,
  channel?: string,
): NormalizedNode[] {
  return context.unsupportedEdges
    .filter(
      (edge) =>
        edge.to === node.key &&
        (channel === undefined || edge.channel === channel),
    )
    .map((edge) => context.nodeByKey.get(edge.from)!)
    .filter(Boolean);
}

function inspectMarkers(parameters: unknown): {
  fromAi: boolean;
  dynamic: boolean;
  truncated: boolean;
  unresolved: boolean;
  placeholder: boolean;
  argumentDeclarations: string[];
} {
  const result = {
    fromAi: false,
    dynamic: false,
    truncated: false,
    unresolved: false,
    placeholder: false,
    argumentDeclarations: [] as string[],
  };
  const pending = [parameters];
  let count = 0;
  while (pending.length) {
    if (++count > 512) {
      result.truncated = true;
      break;
    }
    const current = pending.pop();
    if (typeof current === "string") {
      if (current.length > 65536) result.truncated = true;
      const bounded = current.slice(0, 65536);
      // Only the matched call contributes schema arguments. Surrounding fixed
      // request text is not part of the model's generated argument schema.
      const pattern = /\$fromAI\s*\(/gi;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(bounded))) {
        result.fromAi = true;
        if (result.argumentDeclarations.length >= 32) {
          result.truncated = true;
          break;
        }
        let cursor = pattern.lastIndex;
        let parentheses = 1;
        let quote = "";
        while (cursor < bounded.length && parentheses) {
          const character = bounded[cursor++]!;
          if (quote) {
            if (character === "\\") cursor++;
            else if (character === quote) quote = "";
          } else if (["'", '"', "`"].includes(character)) quote = character;
          else if (character === "(") parentheses++;
          else if (character === ")") parentheses--;
        }
        if (parentheses) {
          result.unresolved = true;
          break;
        }
        result.argumentDeclarations.push(bounded.slice(match.index, cursor));
        pattern.lastIndex = cursor;
      }
      result.dynamic ||= bounded.startsWith("=");
      result.placeholder ||= /\{[^{}]+\}/.test(bounded);
    } else if (Array.isArray(current)) pending.push(...current.slice(0, 513));
    else if (isObject(current))
      pending.push(...Object.values(current).slice(0, 513));
  }
  return result;
}

function fromAiSchemaMode(
  node: NormalizedNode,
): "active" | "inactive" | "unresolved" {
  if (
    node.type === "n8n-nodes-base.httpRequestTool" ||
    node.type === "n8n-nodes-base.postgresTool" ||
    (["utility_tool", "lookup_tool"].includes(profile(node)?.role ?? "") &&
      node.type.startsWith("n8n-nodes-base.")) ||
    profile(node)?.role === "agent_tool"
  )
    return "active";
  if (profile(node)?.role === "workflow_tool" && node.typeVersion >= 2) {
    const inputs = node.parameters.workflowInputs;
    if (inputs === undefined) return "inactive";
    if (!isObject(inputs)) return "unresolved";
    if (inputs.schema === undefined) return "inactive";
    if (!Array.isArray(inputs.schema)) return "unresolved";
    return inputs.schema.length ? "active" : "inactive";
  }
  // Native Code, Workflow V1, HTTP and vector-store tools have their own
  // schema builders. Their code and inactive parameters are not fromAI input.
  return "inactive";
}

function staticToolExampleSchema(
  raw: unknown,
  allFieldsRequired: boolean,
): string | undefined {
  // Match only generate-schema 2.6.0's flat object/primitive subset. Values
  // become type names, never enum/default/example values in model content.
  // Objects are also accepted by n8n's pinned asSchemaText helper.
  const text =
    typeof raw === "string"
      ? raw
      : isObject(raw)
        ? JSON.stringify(raw)
        : undefined;
  if (text === undefined || text.startsWith("=") || text.length > 8192) return;
  const parsed = parseLiteralJsonData(text);
  if (!parsed.parsed || parsed.diagnostics.length || !isObject(parsed.value))
    return;
  const entries = Object.entries(parsed.value);
  if (entries.length > 64) return;
  const properties: Record<string, { type: string }> = Object.create(null);
  for (const [name, value] of entries) {
    if (
      name.length > 128 ||
      ["__proto__", "prototype", "constructor"].includes(name) ||
      Object.hasOwn(Object.prototype, name) ||
      (value !== null &&
        !["string", "number", "boolean"].includes(typeof value)) ||
      (typeof value === "number" && !Number.isFinite(value))
    )
      return;
    properties[name] = { type: value === null ? "null" : typeof value };
  }
  return JSON.stringify({
    $schema: "http://json-schema.org/draft-04/schema#",
    type: "object",
    properties,
    ...(allFieldsRequired && entries.length
      ? { required: entries.map(([name]) => name) }
      : {}),
  });
}

function nativeToolSchemaInputs(node: NormalizedNode): AiPromptInputs {
  const result: AiPromptInputs = { inputs: [], diagnostics: [] };
  const role = profile(node)?.role;
  if (
    role !== "code_tool" &&
    !(role === "workflow_tool" && node.typeVersion < 2)
  )
    return result;
  const enabled = node.parameters.specifyInputSchema;
  if (enabled === undefined || enabled === false) return result;
  if (enabled !== true) {
    result.diagnostics.push("ai_tool_schema_enablement_unresolved");
    result.inputs.push({ value: undefined, pointer: "/parameters" });
  }
  const selector =
    node.parameters.schemaType === undefined
      ? "fromJson"
      : node.parameters.schemaType;
  const fields =
    selector === "fromJson"
      ? ["jsonSchemaExample"]
      : selector === "manual"
        ? ["inputSchema"]
        : ["inputSchema", "jsonSchemaExample"];
  if (fields.length > 1)
    result.diagnostics.push("ai_tool_schema_selector_unresolved");
  for (const field of fields) {
    const value = node.parameters[field];
    if (field === "inputSchema") {
      result.inputs.push({ value, pointer: "/parameters/inputSchema" });
      if (value === undefined)
        result.diagnostics.push("ai_tool_schema_content_unverified");
    } else {
      // JSON examples supply structure, not their original literal values.
      const derived = staticToolExampleSchema(
        value,
        role === "code_tool" && node.typeVersion >= 1.3,
      );
      if (derived !== undefined) {
        result.inputs.push({
          value: derived,
          pointer: "/parameters/jsonSchemaExample",
          literalData: true,
        });
        continue;
      }
      if (typeof value === "string" && value.startsWith("="))
        result.inputs.push({ value, pointer: "/parameters/jsonSchemaExample" });
      result.inputs.push({ value: undefined, pointer: "/parameters" });
      result.diagnostics.push(
        "ai_tool_example_derived_schema_content_unverified",
      );
    }
  }
  return result;
}

type ModelRequestInputs = {
  inputs: {
    value: unknown;
    pointer: string;
    jsonData?: boolean;
    fieldName?: string;
  }[];
  diagnostics: string[];
};

function modelRequestInputs(node: NormalizedNode): ModelRequestInputs {
  const result: ModelRequestInputs = { inputs: [], diagnostics: [] };
  let count = 0;
  const unknown = (code: string) => {
    if (!result.diagnostics.includes(code)) {
      result.inputs.push({ value: undefined, pointer: "/parameters/options" });
      result.diagnostics.push(code);
    }
  };
  const add = (
    value: unknown,
    pointer: string,
    depth = 0,
    fieldName?: string,
  ): void => {
    if (value === undefined) return;
    if (++count > 128 || depth > 8) {
      unknown("ai_model_request_field_limit");
      return;
    }
    if (isObject(value) || Array.isArray(value)) {
      const entries = Object.entries(value);
      if (entries.length > 128) unknown("ai_model_request_field_limit");
      for (const [name, child] of entries.slice(0, 128)) {
        if (count >= 128) {
          unknown("ai_model_request_field_limit");
          break;
        }
        add(child, pointer, depth + 1, Array.isArray(value) ? fieldName : name);
      }
    } else result.inputs.push({ value, pointer, fieldName });
  };
  const addJson = (value: unknown, pointer: string): void => {
    if (typeof value !== "string") add(value, pointer);
    else if (++count <= 128)
      result.inputs.push({ value, pointer, jsonData: true });
    else unknown("ai_model_request_field_limit");
  };
  if (profile(node)?.role !== "model") {
    unknown("ai_model_request_profile_unreviewed");
    return result;
  }
  const options =
    node.parameters.options === undefined ? {} : node.parameters.options;
  if (!isObject(options)) {
    add(options, "/parameters/options");
    unknown("ai_model_request_options_unresolved");
    return result;
  }
  // These profiles describe request data, not local retries/timeouts. Static
  // model identifiers and numeric generation controls are routing/configuration.
  if (node.type !== prefix + "lmChatOpenAi") {
    if (node.type === prefix + "lmChatOpenRouter") {
      const routing = options.providerRouting;
      if (routing !== undefined && !isObject(routing)) {
        add(routing, "/parameters/options");
        unknown("ai_model_request_options_unresolved");
      } else if (isObject(routing))
        for (const field of ["order", "only", "ignore"])
          add(routing[field], "/parameters/options/providerRouting");
    }
    return result;
  }
  if (options.extraBody)
    addJson(options.extraBody, "/parameters/options/extraBody");
  const enabled = node.parameters.responsesApiEnabled;
  if (enabled === undefined || enabled === false) return result;
  if (enabled !== true) unknown("ai_model_response_api_selector_unresolved");
  for (const field of ["promptCacheKey", "safetyIdentifier", "conversationId"])
    add(options[field], `/parameters/options/${field}`);
  if (options.metadata)
    addJson(options.metadata, "/parameters/options/metadata");
  const prompt = options.promptConfig;
  if (prompt !== undefined && prompt !== null && prompt !== false) {
    if (!isObject(prompt) || !isObject(prompt.promptOptions)) {
      add(prompt, "/parameters/options/promptConfig");
      unknown("ai_model_prompt_configuration_unresolved");
    } else {
      for (const field of ["promptId", "version"])
        add(prompt.promptOptions[field], "/parameters/options/promptConfig");
      if (prompt.promptOptions.variables)
        addJson(
          prompt.promptOptions.variables,
          "/parameters/options/promptConfig",
        );
    }
  }
  const text = options.textFormat;
  if (text !== undefined && text !== null && text !== false) {
    if (!isObject(text) || !isObject(text.textOptions)) {
      add(text, "/parameters/options/textFormat");
      unknown("ai_model_text_format_unresolved");
    } else {
      const format = text.textOptions;
      if (format.type === "json_schema") {
        add(format.name, "/parameters/options/textFormat");
        addJson(format.schema, "/parameters/options/textFormat");
      } else if (
        format.type !== undefined &&
        format.type !== "text" &&
        format.type !== "json_object"
      ) {
        add(format.name, "/parameters/options/textFormat");
        addJson(format.schema, "/parameters/options/textFormat");
        unknown("ai_model_text_format_unresolved");
      }
    }
  }
  const tools = node.parameters.builtInTools;
  if (tools !== undefined && tools !== null && tools !== false) {
    if (!isObject(tools)) {
      add(tools, "/parameters/builtInTools");
      unknown("ai_model_builtin_tool_options_unresolved");
    } else {
      for (const [name, fields] of [
        ["webSearch", ["allowedDomains", "country", "city", "region"]],
        ["fileSearch", ["vectorStoreIds", "filters"]],
      ] as const) {
        const tool = tools[name];
        if (tool === undefined || tool === null || tool === false) continue;
        if (!isObject(tool)) {
          add(tool, "/parameters/builtInTools");
          unknown("ai_model_builtin_tool_options_unresolved");
        } else
          for (const field of fields)
            if (name === "fileSearch" && (field !== "filters" || tool[field]))
              addJson(tool[field], "/parameters/builtInTools");
            else if (name !== "fileSearch")
              add(tool[field], "/parameters/builtInTools");
      }
      if (
        [tools.webSearch, tools.fileSearch, tools.codeInterpreter].some(
          (value) => value !== undefined && value !== null && value !== false,
        )
      )
        unknown("ai_builtin_tool_permissions_and_results_unverified");
    }
  }
  return result;
}

const capabilityCodes: Record<Role, string> = {
  agent: "ai_agent_prompt_contract_declared",
  agent_tool: "ai_nested_agent_tool_declared",
  chain: "ai_prompt_chain_contract_declared",
  qa: "ai_retrieval_chain_contract_declared",
  model: "ai_model_provider_declared",
  memory: "ai_memory_context_source_declared",
  retriever: "ai_retrieved_document_source_declared",
  parser: "ai_output_format_contract_declared",
  http_tool: "ai_http_tool_capability_declared",
  sql_tool: "ai_sql_tool_capability_declared",
  code_tool: "ai_code_tool_capability_declared",
  workflow_tool: "ai_workflow_tool_capability_declared",
  retrieval_tool: "ai_retrieval_tool_capability_declared",
  utility_tool: "ai_utility_tool_capability_declared",
  lookup_tool: "ai_lookup_tool_capability_declared",
  vector_tool: "ai_vector_search_tool_capability_declared",
  vector_store: "ai_vector_store_capability_declared",
  embedding: "ai_embedding_provider_declared",
  document_loader: "ai_document_loader_declared",
  text_splitter: "ai_text_splitter_declared",
};

function contracts(
  context: Context,
  evidence?: AssessmentEvidence,
): RuleResult {
  const rule = makeRule("N8N_AI_CONNECTION_CONTRACTS", "dependencies");
  for (const node of context.nodes) {
    const edges = context.unsupportedEdges.filter(
      (edge) => edge.from === node.key || edge.to === node.key,
    );
    if (
      !node.type.startsWith(prefix) &&
      !profiles.has(node.type) &&
      !edges.length
    )
      continue;
    const scope = new Scope(rule, node, context);
    if (node.disabled) {
      scope.diagnostic("ai_disabled_node_not_invoked");
      scope.finish();
      continue;
    }
    const selected = profile(node);
    if (!selected) {
      scope.diagnostic("ai_node_profile_unreviewed", "/typeVersion");
      scope.finish(true);
      continue;
    }
    const role = selected.role;
    scope.finding(capabilityCodes[role]);
    scope.diagnostic("ai_runtime_invocation_and_permissions_unverified");
    for (const edge of edges.filter((edge) => edge.to === node.key)) {
      const source = context.nodeByKey.get(edge.from)!;
      if (!coveredAiEdge(context, edge))
        scope.diagnostic("ai_connection_contract_unresolved");
      scope.finding("ai_typed_connection_declared", { related: [source] });
    }
    const inputs = aiPromptInputs(node, context);
    for (const code of inputs?.diagnostics ?? []) scope.diagnostic(code);
    if (isConsumer(role)) {
      const models = related(context, node, "ai_languageModel");
      const enabledModelPorts = edges
        .filter(
          (edge) =>
            edge.to === node.key &&
            edge.channel === "ai_languageModel" &&
            edge.output === 0 &&
            !context.nodeByKey.get(edge.from)!.disabled,
        )
        .map((edge) => edge.input);
      if (!enabledModelPorts.includes(0))
        scope.diagnostic("ai_required_model_connection_missing");
      if (
        ((role === "agent" && node.typeVersion >= 2) ||
          role === "agent_tool" ||
          role === "chain") &&
        node.parameters.needsFallback === true &&
        !enabledModelPorts.includes(1)
      )
        scope.diagnostic("ai_required_fallback_model_missing");
      if (models.length > 1 || node.parameters.needsFallback === true)
        scope.diagnostic("ai_model_selection_and_fallback_unverified");
      if (
        node.parameters.needsFallback !== undefined &&
        typeof node.parameters.needsFallback !== "boolean"
      )
        scope.diagnostic("ai_fallback_selector_unresolved");
      if (
        node.parameters.hasOutputParser !== undefined &&
        typeof node.parameters.hasOutputParser !== "boolean"
      )
        scope.diagnostic("ai_output_parser_selector_unresolved");
      if (
        node.parameters.hasOutputParser === true &&
        !related(context, node, "ai_outputParser").length
      )
        scope.diagnostic("ai_required_output_parser_missing");
      if (role === "qa" && !related(context, node, "ai_retriever").length)
        scope.diagnostic("ai_required_retriever_connection_missing");
    }
    if (role === "parser") {
      scope.finding("ai_output_parser_is_not_sanitizer");
      if (node.parameters.autoFix === true)
        scope.diagnostic("ai_output_parser_retry_model_content_unverified");
      else if (
        node.parameters.autoFix !== undefined &&
        node.parameters.autoFix !== false
      )
        scope.diagnostic("ai_output_parser_retry_selector_unresolved");
    }
    if (role === "memory") {
      scope.diagnostic("ai_memory_content_and_session_isolation_unverified");
      if (
        node.parameters.sessionIdType === "customKey" &&
        typeof node.parameters.sessionKey === "string" &&
        node.parameters.sessionKey.length > 0 &&
        !node.parameters.sessionKey.startsWith("=")
      )
        scope.finding("ai_memory_constant_session_key_candidate", {
          claim: "candidate",
          severity: "medium",
        });
    }
    if (role === "retriever" || role === "retrieval_tool") {
      scope.diagnostic("ai_retrieved_content_and_access_unverified");
      if (!related(context, node, "ai_vectorStore").length)
        scope.diagnostic("ai_required_vector_store_connection_missing");
    }
    if (role === "vector_store" || role === "vector_tool") {
      if (
        !related(context, node, "ai_embedding").some(
          (source) => !source.disabled && profile(source)?.role === "embedding",
        )
      )
        scope.diagnostic("ai_required_embedding_connection_missing");
      if (
        node.parameters.mode === "insert" &&
        !related(context, node, "ai_document").some(
          (source) =>
            !source.disabled && profile(source)?.role === "document_loader",
        )
      )
        scope.diagnostic("ai_required_document_connection_missing");
      if (
        node.parameters.useReranker !== undefined &&
        node.parameters.useReranker !== false
      )
        scope.diagnostic("ai_vector_reranker_unreviewed");
    }
    if (
      role === "lookup_tool" &&
      node.type === "n8n-nodes-base.rssFeedReadTool"
    ) {
      scope.diagnostic("ai_lookup_tool_request_content_unverified");
      if (
        typeof node.parameters.url !== "string" ||
        node.parameters.url.startsWith("=")
      ) {
        scope.diagnostic("ai_lookup_tool_destination_unresolved");
        scope.finding("ai_lookup_tool_dynamic_destination_candidate", {
          severity: "medium",
          claim: "candidate",
        });
      }
    }
    if (isTool(role)) {
      scope.diagnostic("ai_tool_arguments_and_result_unverified");
      const markers = inspectMarkers(node.parameters);
      if (markers.truncated) scope.diagnostic("ai_parameter_inspection_limit");
      if (markers.dynamic)
        scope.diagnostic("ai_subnode_expression_item_binding_unverified");
      const schemaMode = fromAiSchemaMode(node);
      if (schemaMode === "unresolved")
        scope.diagnostic("ai_tool_schema_enablement_unresolved");
      if (schemaMode !== "inactive" && markers.unresolved)
        scope.diagnostic("ai_from_ai_declaration_unresolved");
      if (schemaMode === "active" && markers.fromAi)
        scope.finding("ai_model_supplied_tool_arguments_declared", {
          severity: "medium",
        });
      if (
        role === "http_tool" &&
        node.type === prefix + "toolHttpRequest" &&
        markers.placeholder
      )
        scope.finding("ai_http_tool_placeholders_declared");
      if (role === "sql_tool")
        scope.diagnostic("ai_sql_tool_permissions_and_query_effect_unverified");
      if (role === "code_tool")
        scope.diagnostic("ai_code_tool_sandbox_and_effects_unverified");
      if (role === "workflow_tool") {
        scope.diagnostic("ai_tool_subworkflow_content_and_access_unverified");
        const source = node.parameters.source ?? "database";
        if (source !== "database" && source !== "parameter")
          scope.diagnostic("ai_tool_workflow_source_unresolved");
        else if (source === "database") {
          const selector = isObject(node.parameters.workflowId)
            ? node.parameters.workflowId.value
            : node.parameters.workflowId;
          if (
            typeof selector !== "string" ||
            selector.length === 0 ||
            selector.startsWith("=")
          )
            scope.diagnostic("ai_tool_workflow_target_unresolved");
        }
      }
      for (const edge of edges.filter(
        (edge) => edge.from === node.key && edge.channel === "ai_tool",
      )) {
        const consumer = context.nodeByKey.get(edge.to)!;
        const approval = evidence?.aiApprovals.find(
          (item) =>
            item.nodeKey === consumer.key &&
            item.toolNodeKeys.includes(node.key),
        );
        scope.finding(
          approval?.required
            ? "ai_tool_approval_declared_required"
            : "ai_tool_approval_not_declared",
          {
            related: [consumer],
            severity: approval?.required ? "info" : "medium",
          },
        );
        scope.diagnostic(
          approval?.required
            ? "ai_runtime_approval_enforcement_unverified"
            : "ai_approval_evidence_missing",
        );
      }
    }
    scope.finish();
  }
  return finish(rule);
}

function classify(
  values: AbstractValue[],
  evidence?: AssessmentEvidence,
): DataClass[] {
  const result = new Set<DataClass>();
  for (const value of values)
    for (const dataClass of transferDataClasses(value, evidence))
      result.add(dataClass);
  if (!result.size) result.add("unknown");
  return [...result];
}

function modelDestination(node: NormalizedNode): string | null {
  if (node.type === prefix + "lmChatGroq" && profile(node)?.role === "model")
    return "https://api.groq.com";
  // OpenAI/Gemini/OpenRouter credentials may override their default host.
  // Only an explicit OpenAI options.baseURL has precedence over credentials.
  if (
    profile(node)?.role !== "model" ||
    node.type !== prefix + "lmChatOpenAi" ||
    !isObject(node.parameters.options)
  )
    return null;
  const configured = node.parameters.options.baseURL;
  if (typeof configured !== "string" || configured.startsWith("=")) return null;
  const url = URL.parse(configured);
  return url &&
    ["https:", "http:"].includes(url.protocol) &&
    !url.username &&
    !url.password
    ? url.origin
    : null;
}

function opaqueValue(node: NormalizedNode): AbstractValue {
  // Undefined is a public JavaScript literal in ValueFlow. Here it represents
  // omitted runtime contents, so construct an explicit unknown abstract value.
  return {
    status: "unknown",
    presence: "unknown",
    origins: [],
    sensitivity: "unknown",
    sensitivityClasses: ["unknown"],
    sensitivityBasis: [],
    trust: "unknown",
    transforms: [],
    guards: [],
    paths: [],
    fullObject: false,
    fieldsComplete: false,
    diagnosticCodes: ["ai_runtime_context_content_unverified"],
    valueId: createHash("sha256")
      .update(`ai_unresolved_context:${node.key}`)
      .digest("hex"),
  };
}

function collectContext(
  context: Context,
  root: NormalizedNode,
  scope: Scope,
): NormalizedNode[] {
  const visited = new Set<string>([root.key]);
  const active = new Set<string>();
  const result: NormalizedNode[] = [];
  const walk = (node: NormalizedNode, depth: number): void => {
    if (depth > 8) {
      scope.diagnostic("ai_context_depth_limit");
      return;
    }
    active.add(node.key);
    for (const edge of context.unsupportedEdges.filter(
      (item) => item.to === node.key && item.channel !== "ai_languageModel",
    )) {
      if (active.has(edge.from)) {
        scope.diagnostic("ai_context_cycle_unresolved");
        continue;
      }
      if (visited.has(edge.from)) continue;
      visited.add(edge.from);
      const source = context.nodeByKey.get(edge.from)!;
      if (!coveredAiEdge(context, edge))
        scope.diagnostic("ai_context_connection_unresolved");
      if (source.disabled) {
        scope.diagnostic("ai_disabled_context_not_invoked");
        continue;
      }
      result.push(source);
      walk(source, depth + 1);
    }
    active.delete(node.key);
  };
  walk(root, 0);
  return result;
}

function promptData(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const rule = makeRule("N8N_AI_PROMPT_DATA", "egress");
  for (const node of context.nodes) {
    const role = profile(node)?.role;
    const inputs: AiPromptInputs | undefined =
      promptInputs(node, true, context) ??
      (role === "retrieval_tool" ||
      (role === "parser" &&
        node.parameters.autoFix !== undefined &&
        node.parameters.autoFix !== false)
        ? {
            inputs: [
              { value: undefined, pointer: "/parameters" },
              ...(role === "parser" && node.parameters.prompt !== undefined
                ? [{ value: node.parameters.prompt, pointer: "/parameters" }]
                : []),
            ],
            diagnostics: [
              role === "parser"
                ? "ai_output_parser_retry_model_content_unverified"
                : "ai_retrieval_tool_query_and_context_unverified",
            ],
          }
        : undefined);
    if (!inputs || node.disabled) continue;
    const scope = new Scope(rule, node, context);
    const values = inputs.inputs.map((input) =>
      input.value === undefined
        ? opaqueValue(node)
        : flow.resolve(input.nodeKey ?? node.key, input.value),
    );
    // Retrying a parser can resend the preceding model output. Retrieval tools
    // and $fromAI-driven nested agents receive model-generated arguments. Keep
    // the initiating prompt's candidates, with unknown actual argument/output.
    if (
      role === "parser" ||
      role === "retrieval_tool" ||
      (role === "agent_tool" && inspectMarkers(node.parameters).fromAi)
    ) {
      values.push(opaqueValue(node));
      for (const edge of context.unsupportedEdges.filter(
        (item) =>
          item.from === node.key &&
          (item.channel === "ai_tool" || item.channel === "ai_outputParser"),
      )) {
        const parent = context.nodeByKey.get(edge.to)!;
        if (parent.disabled) continue;
        for (const input of promptInputs(parent, true, context)?.inputs ?? [])
          values.push(
            input.value === undefined
              ? opaqueValue(parent)
              : flow.resolve(input.nodeKey ?? parent.key, input.value),
          );
      }
      scope.diagnostic("ai_generated_argument_or_retry_content_unverified");
    }
    for (const code of inputs.diagnostics) scope.diagnostic(code);
    if (
      values.some(
        (value, index) =>
          inputs.inputs[index]?.value !== undefined &&
          value.status !== "resolved",
      )
    )
      scope.diagnostic("ai_prompt_expression_partial");
    const tools = related(context, node, "ai_tool").filter(
      (tool) => !tool.disabled,
    );
    if (tools.length && values.some((value) => isExternalValue(value)))
      scope.finding("ai_external_prompt_may_influence_tool_selection", {
        severity: "medium",
        claim: "candidate",
        values,
        related: tools,
      });
    else if (tools.length)
      scope.diagnostic("ai_prompt_influence_on_tool_selection_unverified");

    const contextNodes = collectContext(context, node, scope);
    for (const source of contextNodes) {
      const role = profile(source)?.role;
      if (
        context.unsupportedEdges.some(
          (edge) =>
            edge.from === source.key &&
            (edge.to === node.key ||
              contextNodes.some((item) => item.key === edge.to)) &&
            !coveredAiEdge(context, edge),
        )
      )
        values.push(opaqueValue(source));
      if (role === "parser") {
        const schemaType = source.parameters.schemaType;
        const manualField =
          source.typeVersion <= 1.1 ? "jsonSchema" : "inputSchema";
        const fields =
          schemaType === "fromJson"
            ? ["jsonSchemaExample"]
            : schemaType === undefined ||
                schemaType === "manual" ||
                schemaType === ""
              ? [manualField]
              : [manualField, "jsonSchemaExample"];
        for (const field of fields)
          if (source.parameters[field] !== undefined) {
            const configured = source.parameters[field];
            // An example is transformed into a schema. Its literal example
            // values are not proved to be included in model instructions.
            if (
              field !== "jsonSchemaExample" ||
              (typeof configured === "string" && configured.startsWith("="))
            )
              values.push(flow.resolve(source.key, configured));
            if (field === "jsonSchemaExample") {
              values.push(opaqueValue(source));
              scope.diagnostic("ai_example_derived_schema_content_unverified");
            }
          }
        if (fields.length > 1) {
          values.push(opaqueValue(source));
          scope.diagnostic("ai_parser_schema_selector_unresolved");
        }
        if (
          source.parameters.autoFix !== undefined &&
          source.parameters.autoFix !== false
        )
          scope.diagnostic("ai_output_parser_retry_model_content_unverified");
      } else {
        // A tool response, retrieved document, or memory history is additional
        // model context. JSON definitions alone cannot establish its contents.
        values.push(opaqueValue(source));
        scope.diagnostic(
          role === "memory"
            ? "ai_memory_context_content_unverified"
            : role === "retriever" || role === "retrieval_tool"
              ? "ai_retrieved_context_content_unverified"
              : "ai_tool_or_context_result_unverified",
        );
      }
      if (role && isTool(role)) {
        const field = ["code_tool", "workflow_tool", "retrieval_tool"].includes(
          role,
        )
          ? "description"
          : "toolDescription";
        if (
          source.parameters[field] !== undefined &&
          source.parameters.descriptionType !== "auto"
        )
          values.push(flow.resolve(source.key, source.parameters[field]));
        const schema = nativeToolSchemaInputs(source);
        for (const input of schema.inputs)
          values.push(
            input.value === undefined
              ? opaqueValue(source)
              : input.literalData
                ? resolveLiteralData(flow, source.key, input.value)
                : flow.resolve(source.key, input.value),
          );
        for (const code of schema.diagnostics) scope.diagnostic(code);
        const markers = inspectMarkers(source.parameters);
        const schemaMode = fromAiSchemaMode(source);
        if (schemaMode !== "inactive") {
          for (const declaration of markers.argumentDeclarations)
            values.push(flow.resolveExpression(source.key, declaration));
          if (markers.unresolved)
            scope.diagnostic("ai_from_ai_declaration_unresolved");
          if (schemaMode === "unresolved")
            scope.diagnostic("ai_tool_schema_enablement_unresolved");
        }
        if (markers.truncated)
          scope.diagnostic("ai_parameter_inspection_limit");
        if ((schemaMode !== "inactive" && markers.fromAi) || markers.dynamic)
          scope.diagnostic("ai_subnode_expression_item_binding_unverified");
      }
    }
    const models = related(context, node, "ai_languageModel").filter(
      (model) =>
        !model.disabled &&
        context.unsupportedEdges.some(
          (edge) =>
            edge.from === model.key &&
            edge.to === node.key &&
            edge.channel === "ai_languageModel" &&
            coveredAiEdge(context, edge),
        ),
    );
    if (!models.length) {
      scope.diagnostic("ai_required_model_connection_missing");
      scope.finish();
      continue;
    }
    const requestValues = new Map<string, AbstractValue[]>();
    for (const model of models) {
      const selected = modelRequestInputs(model);
      const inputs = selected.inputs.flatMap((input): AbstractValue[] => {
        if (input.value === undefined) return [opaqueValue(model)];
        if (input.jsonData && typeof input.value === "string") {
          const parsed = parseLiteralJsonData(input.value);
          for (const code of parsed.diagnostics) scope.diagnostic(code);
          return [
            ...(parsed.value === undefined
              ? []
              : [
                  parsed.parsed
                    ? resolveLiteralData(flow, model.key, parsed.value)
                    : flow.resolve(model.key, parsed.value),
                ]),
            ...(parsed.diagnostics.length ? [opaqueValue(model)] : []),
          ];
        }
        return [
          flow.resolve(model.key, input.value, { fieldName: input.fieldName }),
        ];
      });
      requestValues.set(model.key, inputs);
      for (const code of selected.diagnostics) scope.diagnostic(code);
      if (inputs.some((value) => value.status !== "resolved"))
        scope.diagnostic("ai_model_request_expression_partial");
    }
    const allValues = [...values, ...[...requestValues.values()].flat()];
    const classes = classify(allValues, evidence);
    for (const dataClass of classes) {
      const code =
        dataClass === "secret"
          ? "ai_prompt_to_model_secret_candidate"
          : dataClass === "personal"
            ? "ai_prompt_to_model_pii_candidate"
            : dataClass === "internal"
              ? "ai_prompt_to_model_internal_component"
              : dataClass === "public"
                ? "ai_prompt_public_component_declared"
                : "ai_prompt_to_model_unknown_component";
      scope.finding(code, {
        severity:
          dataClass === "secret"
            ? "high"
            : dataClass === "personal"
              ? "medium"
              : "info",
        claim: dataClass === "public" ? "configuration" : "candidate",
        values: allValues,
        related: [...models, ...contextNodes],
      });
    }
    if (classes.includes("unknown"))
      scope.diagnostic("ai_model_context_sensitivity_unverified");
    scope.diagnostic("ai_model_invocation_and_output_unverified");
    for (const model of models) {
      const edge = context.unsupportedEdges.find(
        (item) =>
          item.from === model.key &&
          item.to === node.key &&
          item.channel === "ai_languageModel",
      );
      const destination =
        edge && coveredAiEdge(context, edge) ? modelDestination(model) : null;
      if (destination === null)
        scope.diagnostic("ai_model_endpoint_from_credentials_unverified");
      const decision = assessDestination(
        evidence,
        model.key,
        "ai_model",
        destination,
        classify(
          [...values, ...(requestValues.get(model.key) ?? [])],
          evidence,
        ),
      );
      if (decision.status === "disallowed")
        scope.finding("trusted_policy_transfer_disallowed", {
          severity: "high",
          related: [model],
          extraCodes: decision.codes,
        });
      else if (decision.status === "unknown")
        scope.diagnostic(
          decision.codes.some(
            (code) =>
              code === "policy_not_provided" || code === "policy_rule_missing",
          )
            ? "ai_model_transfer_policy_not_configured"
            : "ai_model_transfer_policy_unresolved",
        );
    }
    scope.finish();
  }
  return finish(rule);
}

function vectorType(node: NormalizedNode): boolean {
  return [
    prefix + "vectorStorePinecone",
    prefix + "vectorStoreSupabase",
  ].includes(node.type);
}

function embeddingDestination(node: NormalizedNode): string | null {
  if (
    profile(node)?.role !== "embedding" ||
    node.type !== prefix + "embeddingsOpenAi" ||
    !isObject(node.parameters.options)
  )
    return null;
  const value = node.parameters.options.baseURL;
  if (typeof value !== "string" || value.startsWith("=")) return null;
  const url = URL.parse(value);
  return url &&
    ["https:", "http:"].includes(url.protocol) &&
    !url.username &&
    !url.password
    ? url.origin
    : null;
}

// Whole document serialization/splitting can retain any descendant class. This
// does not infer the contents of unknown input or the embedding vector itself.
function documentContents(value: AbstractValue): AbstractValue {
  return {
    ...value,
    guards: [],
    origins: value.origins.map((origin) =>
      origin.kind === "literal"
        ? origin
        : {
            ...origin,
            includesDescendants: true,
            projectionUnknown: true,
          },
    ),
  };
}

function vectorData(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const rule = makeRule("N8N_AI_VECTOR_DATA", "egress");
  const resolveInputs = (
    inputs: BinaryInput[],
    fallback: NormalizedNode,
  ): AbstractValue[] =>
    inputs.map((item) =>
      item.value === undefined
        ? opaqueValue(context.nodeByKey.get(item.nodeKey) ?? fallback)
        : documentContents(flow.resolve(item.nodeKey, item.value)),
    );
  const metadataValues = (
    raw: unknown,
    store: NormalizedNode,
    scope: Scope,
  ): AbstractValue[] => {
    const result: AbstractValue[] = [];
    let visits = 0;
    const walk = (value: unknown, fieldName?: string, depth = 0): void => {
      if (++visits > 128 || depth > 8) {
        scope.diagnostic("ai_document_analysis_limit");
        return;
      }
      if (isObject(value) || Array.isArray(value)) {
        const entries = Object.entries(value);
        if (entries.length > 128)
          scope.diagnostic("ai_document_analysis_limit");
        for (const [key, child] of entries.slice(0, 128))
          walk(child, Array.isArray(value) ? fieldName : key, depth + 1);
      } else
        result.push(
          documentContents(flow.resolve(store.key, value, { fieldName })),
        );
    };
    if (!isObject(raw) || !Array.isArray(raw.metadataValues)) {
      scope.diagnostic("ai_document_metadata_unresolved");
      result.push(opaqueValue(store));
      walk(raw);
    } else {
      for (const entry of raw.metadataValues.slice(0, 64)) {
        if (
          !isObject(entry) ||
          typeof entry.name !== "string" ||
          entry.value === undefined
        ) {
          scope.diagnostic("ai_document_metadata_unresolved");
          result.push(opaqueValue(store));
          walk(entry);
        } else {
          walk(entry.name);
          walk(
            entry.value,
            entry.name.startsWith("=") ? undefined : entry.name,
          );
        }
      }
      if (raw.metadataValues.length > 64)
        scope.diagnostic("ai_document_analysis_limit");
    }
    if (visits > 128) result.push(opaqueValue(store));
    return result;
  };
  const classesFinding = (
    scope: Scope,
    stem: string,
    values: AbstractValue[],
    relatedNodes: NormalizedNode[],
  ) => {
    for (const kind of classify(values, evidence))
      scope.finding(
        stem +
          (kind === "secret"
            ? "_secret_candidate"
            : kind === "personal"
              ? "_pii_candidate"
              : "_" + kind + "_component"),
        {
          severity:
            kind === "secret"
              ? "high"
              : kind === "personal"
                ? "medium"
                : "info",
          claim: kind === "public" ? "configuration" : "candidate",
          values,
          related: relatedNodes,
        },
      );
  };
  const policy = (
    scope: Scope,
    target: NormalizedNode,
    sink: "ai_model" | "ai_vector_store",
    destination: string | null,
    values: AbstractValue[],
  ) => {
    const decision = assessDestination(
      evidence,
      target.key,
      sink,
      destination,
      classify(values, evidence),
    );
    if (decision.status === "disallowed")
      scope.finding("trusted_policy_transfer_disallowed", {
        severity: "high",
        claim: "candidate",
        related: [target],
        values,
        extraCodes: decision.codes,
      });
    else if (decision.status === "unknown")
      scope.diagnostic(
        decision.codes.every(
          (code) =>
            code === "policy_not_provided" || code === "policy_rule_missing",
        )
          ? "ai_vector_transfer_policy_not_configured"
          : "ai_vector_transfer_policy_unresolved",
      );
  };
  for (const store of context.nodes.filter(vectorType)) {
    const scope = new Scope(rule, store, context);
    if (store.disabled) {
      scope.diagnostic("ai_disabled_node_not_invoked");
      scope.finish();
      continue;
    }
    const selected = profile(store);
    const mode = store.parameters.mode ?? "retrieve";
    if (!selected || !["vector_store", "vector_tool"].includes(selected.role)) {
      scope.diagnostic("ai_vector_profile_unreviewed");
      scope.finish(true);
      continue;
    }
    const embeddings = related(context, store, "ai_embedding").filter(
      (node) => !node.disabled,
    );
    const validEmbeddingEdges = context.unsupportedEdges.filter(
      (edge) =>
        edge.to === store.key &&
        edge.channel === "ai_embedding" &&
        coveredAiEdge(context, edge),
    );
    if (!validEmbeddingEdges.length)
      scope.diagnostic("ai_required_embedding_connection_missing");
    if (
      embeddings.some((node) => profile(node)?.role !== "embedding") ||
      validEmbeddingEdges.length !== embeddings.length
    )
      scope.diagnostic("ai_embedding_connection_unresolved");
    const content: AbstractValue[] = [];
    const metadata: AbstractValue[] = [];
    const definitions: NormalizedNode[] = [store, ...embeddings];
    if (mode === "insert") {
      const loaders = related(context, store, "ai_document").filter(
        (node) => !node.disabled,
      );
      definitions.push(...loaders);
      if (!loaders.length) {
        scope.diagnostic("ai_required_document_connection_missing");
        content.push(
          opaqueValue(store),
          documentContents(flow.resolve(store.key, "={{ $json }}")),
        );
      }
      if (loaders.length > 8) scope.diagnostic("ai_document_analysis_limit");
      for (const loader of loaders.slice(0, 8)) {
        const edge = context.unsupportedEdges.find(
          (entry) =>
            entry.from === loader.key &&
            entry.to === store.key &&
            entry.channel === "ai_document",
        );
        if (
          profile(loader)?.role !== "document_loader" ||
          !edge ||
          !coveredAiEdge(context, edge)
        ) {
          scope.diagnostic("ai_document_connection_unresolved");
          content.push(
            opaqueValue(loader),
            documentContents(flow.resolve(store.key, "={{ $json }}")),
          );
          continue;
        }
        const p = loader.parameters;
        const options = p.options === undefined ? {} : p.options;
        if (!isObject(options)) {
          scope.diagnostic("ai_document_options_unresolved");
          content.push(opaqueValue(loader));
          metadata.push(flow.resolve(store.key, options));
        } else {
          if (options.metadata !== undefined)
            metadata.push(...metadataValues(options.metadata, store, scope));
          if (options.pointers !== undefined && options.pointers !== "") {
            // Keep all possible input candidates until pointer selection and
            // JSONLoader's string-leaf semantics have a reviewed profile.
            scope.diagnostic("ai_document_selection_unresolved");
            content.push(opaqueValue(loader));
          }
        }
        const dataType = p.dataType ?? "json";
        if (dataType === "binary") {
          const binary = binaryInputProvenance(context, store);
          for (const code of binary.diagnostics) scope.diagnostic(code);
          if (binary.state === "none")
            scope.diagnostic("ai_document_binary_input_missing");
          else {
            content.push(...resolveInputs(binary.inputs, store));
            scope.diagnostic("ai_document_binary_content_unverified");
          }
          // A missing/unknown attachment is not an empty public document.
          content.push(opaqueValue(loader));
          if (p.binaryMode !== undefined && p.binaryMode !== "allInputData")
            scope.diagnostic("ai_document_binary_selection_unresolved");
        } else if (dataType === "json") {
          const jsonMode = p.jsonMode ?? "allInputData";
          if (jsonMode === "allInputData")
            content.push(
              documentContents(flow.resolve(store.key, "={{ $json }}")),
            );
          else if (jsonMode === "expressionData" && p.jsonData !== undefined) {
            // n8n uses TextLoader for a string and JSONLoader for an object;
            // a literal JSON-looking string is not parsed into expressions.
            content.push(documentContents(flow.resolve(store.key, p.jsonData)));
          } else {
            scope.diagnostic("ai_document_selector_unresolved");
            content.push(
              opaqueValue(loader),
              documentContents(flow.resolve(store.key, "={{ $json }}")),
            );
            if (p.jsonData !== undefined)
              content.push(
                documentContents(flow.resolve(store.key, p.jsonData)),
              );
          }
        } else {
          scope.diagnostic("ai_document_selector_unresolved");
          content.push(
            opaqueValue(loader),
            documentContents(flow.resolve(store.key, "={{ $json }}")),
          );
          if (p.jsonData !== undefined)
            content.push(documentContents(flow.resolve(store.key, p.jsonData)));
          content.push(
            ...resolveInputs(
              binaryInputProvenance(context, store).inputs,
              store,
            ),
          );
        }
        const splitMode = p.textSplittingMode ?? "simple";
        if (
          loader.typeVersion === 1.1 &&
          splitMode !== "simple" &&
          splitMode !== "custom"
        )
          scope.diagnostic("ai_document_splitter_unresolved");
        for (const splitEdge of context.unsupportedEdges.filter(
          (entry) =>
            entry.to === loader.key && entry.channel === "ai_textSplitter",
        )) {
          if (loader.typeVersion === 1.1 && splitMode === "simple") continue;
          if (!coveredAiEdge(context, splitEdge))
            scope.diagnostic("ai_document_splitter_unresolved");
        }
      }
    } else if (mode === "load") {
      if (typeof store.parameters.prompt !== "string") {
        scope.diagnostic("ai_vector_query_input_unresolved");
        content.push(opaqueValue(store));
      }
      if (store.parameters.prompt !== undefined)
        content.push(
          documentContents(flow.resolve(store.key, store.parameters.prompt)),
        );
    } else if (mode === "retrieve" || mode === "retrieve-as-tool") {
      const seen = new Set<string>([store.key]);
      const walk = (node: NormalizedNode, depth: number): void => {
        if (depth > 8 || seen.size > 32) {
          scope.diagnostic("ai_document_analysis_limit");
          return;
        }
        for (const edge of context.unsupportedEdges.filter(
          (entry) =>
            entry.from === node.key &&
            ["ai_vectorStore", "ai_retriever", "ai_tool"].includes(
              entry.channel,
            ),
        )) {
          const consumer = context.nodeByKey.get(edge.to)!;
          if (consumer.disabled) continue;
          if (seen.has(consumer.key)) {
            scope.diagnostic("ai_vector_query_connection_unresolved");
            continue;
          }
          seen.add(consumer.key);
          definitions.push(consumer);
          if (!coveredAiEdge(context, edge))
            scope.diagnostic("ai_vector_query_connection_unresolved");
          const inputs = promptInputs(consumer, true, context);
          if (inputs) {
            for (const code of inputs.diagnostics) scope.diagnostic(code);
            content.push(
              ...resolveInputs(
                inputs.inputs.map((item) => ({
                  ...item,
                  nodeKey: item.nodeKey ?? consumer.key,
                })),
                consumer,
              ),
            );
          } else if (
            isConsumer(profile(consumer)?.role ?? "vector_store") ||
            consumer.type === prefix + "agent"
          )
            scope.diagnostic("ai_vector_query_input_unresolved");
          walk(consumer, depth + 1);
        }
      };
      walk(store, 0);
      // Retrieval can use an LLM-generated query, not necessarily the literal
      // user prompt. Retain prompt dependencies plus the unknown query.
      content.push(opaqueValue(store));
      scope.diagnostic("ai_vector_query_and_results_unverified");
    } else {
      scope.diagnostic("ai_vector_update_profile_unreviewed");
      content.push(
        opaqueValue(store),
        documentContents(flow.resolve(store.key, "={{ $json }}")),
      );
    }
    if (!content.length) content.push(opaqueValue(store));
    if (
      content.some(
        (value) =>
          value.diagnosticCodes.some(
            (code) => code !== "ai_runtime_context_content_unverified",
          ) && value.status !== "resolved",
      )
    )
      scope.diagnostic("ai_document_provenance_unresolved");
    const storageValues = [...content, ...metadata];
    const storeOptions = store.parameters.options;
    if (isObject(storeOptions) && storeOptions.metadata !== undefined)
      storageValues.push(
        ...metadataValues(storeOptions.metadata, store, scope),
      );
    if (
      store.parameters.useReranker !== undefined &&
      store.parameters.useReranker !== false
    )
      scope.diagnostic("ai_vector_reranker_unreviewed");
    const stem = mode === "insert" ? "ai_document" : "ai_query";
    classesFinding(
      scope,
      stem + "_to_vector_store",
      storageValues,
      definitions,
    );
    policy(scope, store, "ai_vector_store", null, storageValues);
    scope.diagnostic("ai_vector_store_endpoint_and_access_unverified");
    for (const embedding of embeddings.slice(0, 8)) {
      classesFinding(scope, stem + "_to_embedding", content, [
        embedding,
        store,
      ]);
      const destination = validEmbeddingEdges.some(
        (edge) => edge.from === embedding.key,
      )
        ? embeddingDestination(embedding)
        : null;
      policy(scope, embedding, "ai_model", destination, content);
      if (destination === null)
        scope.diagnostic("ai_embedding_endpoint_from_credentials_unverified");
    }
    if (embeddings.length > 8) scope.diagnostic("ai_document_analysis_limit");
    scope.diagnostic("ai_vector_runtime_operations_unverified");
    scope.finish();
  }
  return finish(rule);
}

export function analyzeAiFlow(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult[] {
  return [
    contracts(context, evidence),
    promptData(context, flow, evidence),
    vectorData(context, flow, evidence),
  ];
}
