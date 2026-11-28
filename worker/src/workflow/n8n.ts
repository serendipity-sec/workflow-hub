import { createHash } from "node:crypto";
import { limits } from "../contracts/contract.js";
import type {
  Diagnostic,
  DiagnosticCode,
  ErrorCode,
} from "../contracts/contract.js";

type JsonObject = Record<string, unknown>;

export class WorkflowError extends Error {
  constructor(
    readonly code: ErrorCode,
    readonly pointer?: string,
  ) {
    super(code);
    this.name = "WorkflowError";
  }
}

export type Reference =
  | { kind: "current"; field: string }
  | { kind: "direct"; field: string; nodeName: string };

export interface NormalizedNode {
  id: string;
  identity: "explicit_id" | "name_derived";
  name: string;
  key: string;
  type: string;
  typeVersion: number;
  pointer: string;
  disabled: boolean;
  parameters: JsonObject;
  raw: JsonObject;
}

export interface MainEdge {
  from: string;
  to: string;
  output: number;
  input: number;
}

export interface UnsupportedEdge extends MainEdge {
  channel: string;
}

export interface FieldReference {
  consumer: string;
  pointer: string;
  reference: Reference;
  source: string | null;
}

export interface NormalizedWorkflow {
  nodes: NormalizedNode[];
  edges: MainEdge[];
  unsupportedEdges: UnsupportedEdge[];
  references: FieldReference[];
  diagnostics: Diagnostic[];
}

const webhook = "n8n-nodes-base.webhook";
const ifNode = "n8n-nodes-base.if";
const postgres = "n8n-nodes-base.postgres";
const subworkflow = "n8n-nodes-base.executeWorkflow";

const supportedVersions = new Map([
  [webhook, 2],
  [ifNode, 2.2],
  [postgres, 2.8],
]);

// NodeConnectionTypes in the pinned n8n release, including known unsupported AI channels.
const connectionChannels = new Set([
  "main",
  "ai_agent",
  "ai_chain",
  "ai_document",
  "ai_embedding",
  "ai_languageModel",
  "ai_memory",
  "ai_outputParser",
  "ai_retriever",
  "ai_reranker",
  "ai_textSplitter",
  "ai_tool",
  "ai_vectorStore",
]);

export function parseReference(expression: string): Reference | undefined {
  const text = expression.trim();
  const current = /^\$json\.body\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(text);
  if (current?.[1]) return { kind: "current", field: current[1] };

  const direct =
    /^\$\((['"])([^'"\\]+)\1\)\.first\(\)\.json\.body\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(
      text,
    );
  if (direct?.[2] && direct[3] && /^[ -~]+$/.test(direct[2])) {
    return { kind: "direct", field: direct[3], nodeName: direct[2] };
  }
}

// Validate depth and decoded property names before JSON.parse can collapse duplicate keys.
class JsonStructure {
  private offset = 0;
  private readonly primitive =
    /(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/y;

  constructor(private readonly text: string) {}

  check(): void {
    this.scanValue(1);
    this.skipWhitespace();
    if (this.offset !== this.text.length)
      throw new WorkflowError("invalid_json");
  }

  private skipWhitespace(): void {
    while (/[ \t\r\n]/.test(this.text.charAt(this.offset))) this.offset++;
  }

  private take(char: string): boolean {
    if (this.text[this.offset] !== char) return false;
    this.offset++;
    return true;
  }

  private expect(char: string): void {
    if (!this.take(char)) throw new WorkflowError("invalid_json");
  }

  private scanString(): string {
    const start = this.offset;
    this.expect('"');
    while (this.offset < this.text.length) {
      const char = this.text[this.offset++];
      if (char === '"') return this.text.slice(start, this.offset);
      if (char === "\\") this.offset++;
    }
    throw new WorkflowError("invalid_json");
  }

  private scanValue(depth: number): void {
    this.skipWhitespace();
    const char = this.text[this.offset];
    if (char === "{" || char === "[") {
      if (depth > limits.depth) throw new WorkflowError("depth_limit");
      this.offset++;
      if (char === "{") this.scanObject(depth);
      else this.scanArray(depth);
      return;
    }
    if (char === '"') {
      this.scanString();
      return;
    }
    this.primitive.lastIndex = this.offset;
    if (!this.primitive.test(this.text))
      throw new WorkflowError("invalid_json");
    this.offset = this.primitive.lastIndex;
  }

  private scanObject(depth: number): void {
    const keys = new Set<string>();
    this.skipWhitespace();
    if (this.take("}")) return;
    do {
      this.skipWhitespace();
      const rawKey = this.scanString();
      const key = parseJson(rawKey);
      if (typeof key !== "string") throw new WorkflowError("invalid_json");
      if (keys.has(key)) throw new WorkflowError("duplicate_key");
      keys.add(key);
      this.skipWhitespace();
      this.expect(":");
      this.scanValue(depth + 1);
      this.skipWhitespace();
    } while (this.take(","));
    this.expect("}");
  }

  private scanArray(depth: number): void {
    this.skipWhitespace();
    if (this.take("]")) return;
    do {
      this.scanValue(depth + 1);
      this.skipWhitespace();
    } while (this.take(","));
    this.expect("]");
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new WorkflowError("invalid_json");
  }
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decodeWorkflow(bytes: Buffer): unknown {
  if (bytes.length > limits.fileBytes)
    throw new WorkflowError("file_too_large");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new WorkflowError("invalid_utf8");
  }
  new JsonStructure(text).check();
  return parseJson(text);
}

function identified(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeNodes(entries: unknown[]): NormalizedNode[] {
  if (entries.length > limits.nodes)
    throw new WorkflowError("graph_limit", "/nodes");
  const names = new Set<string>();
  const keys = new Set<string>();
  return entries.map((entry, index) => {
    const pointer = `/nodes/${index}`;
    if (!isObject(entry)) throw new WorkflowError("invalid_workflow", pointer);
    const { name, type, typeVersion, parameters, disabled } = entry;
    // n8n accepts exports without node IDs. Derive only an internal identity;
    // never mutate the original document, bytes, or its hash. The namespace
    // separates this from ordinary IDs; collision checks still apply below.
    const id =
      entry.id === undefined
        ? `\u0000n8n-name-identity-v1\u0000${JSON.stringify([name, type])}`
        : entry.id;
    if (
      !identified(id) ||
      (entry.id !== undefined &&
        typeof id === "string" &&
        id.startsWith("\u0000n8n-name-identity-v1\u0000")) ||
      /[\uD800-\uDFFF]/u.test(id) ||
      !identified(name) ||
      !identified(type) ||
      typeof typeVersion !== "number" ||
      !Number.isFinite(typeVersion) ||
      typeVersion <= 0 ||
      !isObject(parameters) ||
      (disabled !== undefined && typeof disabled !== "boolean")
    ) {
      throw new WorkflowError("invalid_workflow", pointer);
    }
    const key = createHash("sha256").update(id, "utf8").digest("hex");
    if (names.has(name) || keys.has(key))
      throw new WorkflowError("identity_collision", pointer);
    names.add(name);
    keys.add(key);
    return {
      id,
      identity: entry.id === undefined ? "name_derived" : "explicit_id",
      name,
      key,
      type,
      typeVersion,
      pointer,
      disabled: disabled ?? false,
      parameters,
      raw: entry,
    };
  });
}

function mainOutputCount(node: NormalizedNode): number {
  if (supportedVersions.get(node.type) !== node.typeVersion) return Infinity;
  const methods = node.parameters.httpMethod;
  let count = node.type === ifNode ? 2 : 1;
  if (node.type === webhook && node.parameters.multipleMethods === true) {
    // n8n's multi-method field defaults to GET and POST when it is omitted.
    count =
      methods === undefined
        ? 2
        : Array.isArray(methods)
          ? methods.length
          : Infinity;
  }
  return count + (node.raw.onError === "continueErrorOutput" ? 1 : 0);
}

function normalizeConnections(
  connections: JsonObject,
  names: ReadonlyMap<string, NormalizedNode>,
) {
  const edges: MainEdge[] = [];
  const unsupportedEdges: UnsupportedEdge[] = [];
  const seen = new Set<string>();
  const pointer = "/connections";
  for (const [fromName, channels] of Object.entries(connections)) {
    const from = names.get(fromName);
    if (!from || !isObject(channels))
      throw new WorkflowError("broken_connection", pointer);
    const outputs = mainOutputCount(from);
    for (const [channel, groups] of Object.entries(channels)) {
      if (!connectionChannels.has(channel) || !Array.isArray(groups))
        throw new WorkflowError("broken_connection", pointer);
      if (groups.length > limits.edges)
        throw new WorkflowError("graph_limit", pointer);
      for (const [output, entries] of groups.entries()) {
        // n8n uses null for an unwired output. Keep the following output indices intact.
        if (entries === null) continue;
        if (!Array.isArray(entries))
          throw new WorkflowError("broken_connection", pointer);
        for (const entry of entries) {
          if (edges.length + unsupportedEdges.length >= limits.edges)
            throw new WorkflowError("graph_limit", pointer);
          if (!isObject(entry))
            throw new WorkflowError("broken_connection", pointer);
          const { node: toName, type, index: input } = entry;
          const to = typeof toName === "string" ? names.get(toName) : undefined;
          if (
            !to ||
            type !== channel ||
            typeof input !== "number" ||
            !Number.isSafeInteger(input) ||
            input < 0 ||
            (channel === "main" &&
              (output >= outputs ||
                (supportedVersions.get(to.type) === to.typeVersion &&
                  (to.type === webhook || input !== 0))))
          ) {
            throw new WorkflowError("broken_connection", pointer);
          }
          const edge = { from: from.key, to: to.key, output, input };
          const signature = JSON.stringify([
            channel,
            edge.from,
            output,
            edge.to,
            input,
          ]);
          if (seen.has(signature))
            throw new WorkflowError("broken_connection", pointer);
          seen.add(signature);
          if (channel === "main") edges.push(edge);
          else unsupportedEdges.push({ ...edge, channel });
        }
      }
    }
  }
  return { edges, unsupportedEdges };
}

function hasTemplate(value: string): boolean {
  return (
    value.trimStart().startsWith("=") ||
    value.includes("{{") ||
    value.includes("}}")
  );
}

function soleTemplate(value: string): string | undefined {
  const open = value.indexOf("{{");
  const close = value.indexOf("}}");
  if (
    open < 0 ||
    close < open + 2 ||
    value.includes("{{", open + 2) ||
    value.includes("}}", close + 2)
  )
    return;
  return value.slice(open + 2, close);
}

type FieldLocation = Pick<FieldReference, "consumer" | "pointer">;

function unsupportedNodeConfiguration(
  node: NormalizedNode,
): string | undefined {
  if (node.disabled) return "/disabled";
  if (
    node.raw.continueOnFail === true ||
    (node.raw.onError !== undefined && node.raw.onError !== "stopWorkflow")
  )
    return "";
  if (node.type === webhook && Array.isArray(node.parameters.httpMethod)) {
    return "/parameters/httpMethod";
  }
  if (node.type === webhook && node.parameters.multipleMethods === true) {
    return "/parameters/multipleMethods";
  }
  if (node.type === postgres) {
    if (node.parameters.resource !== "database") return "/parameters/resource";
    if (node.parameters.operation !== "executeQuery")
      return "/parameters/operation";
  }
}

// Only supported carrier fields are inspected. Their actual query and condition semantics are checked by the rule.
function fieldReferences(
  node: NormalizedNode,
  names: ReadonlyMap<string, NormalizedNode>,
  references: FieldReference[],
  unsupported: FieldLocation[],
): void {
  if (
    unsupportedNodeConfiguration(node) !== undefined ||
    supportedVersions.get(node.type) !== node.typeVersion
  )
    return;
  function add(expression: string | undefined, suffix: string): void {
    const location = {
      consumer: node.key,
      pointer: `${node.pointer}${suffix}`,
    };
    const reference =
      expression === undefined ? undefined : parseReference(expression);
    if (!reference) {
      unsupported.push(location);
      return;
    }
    const source =
      reference.kind === "direct"
        ? (names.get(reference.nodeName)?.key ?? null)
        : null;
    references.push({ ...location, reference, source });
    if (reference.kind === "direct" && source === null)
      unsupported.push(location);
  }

  if (node.type === ifNode) {
    const conditions = node.parameters.conditions;
    if (isObject(conditions) && Array.isArray(conditions.conditions)) {
      const condition = conditions.conditions[0];
      if (
        isObject(condition) &&
        typeof condition.leftValue === "string" &&
        hasTemplate(condition.leftValue)
      ) {
        add(
          /^=\{\{([\s\S]*?)\}\}$/.exec(condition.leftValue)?.[1],
          "/parameters/conditions/conditions/0/leftValue",
        );
      }
    }
  }
  if (node.type === postgres) {
    const { query, options } = node.parameters;
    if (typeof query === "string" && hasTemplate(query)) {
      add(soleTemplate(query), "/parameters/query");
    }
    if (
      isObject(options) &&
      typeof options.queryReplacement === "string" &&
      hasTemplate(options.queryReplacement)
    ) {
      add(
        /^=\{\{\s*\[([\s\S]*?)\]\s*\}\}$/.exec(options.queryReplacement)?.[1],
        "/parameters/options/queryReplacement",
      );
    }
  }
}

function downstream(
  nodes: NormalizedNode[],
  edges: MainEdge[],
  references: FieldReference[],
) {
  const adjacency = new Map(nodes.map(({ key }) => [key, new Set<string>()]));
  for (const { from, to } of edges) adjacency.get(from)?.add(to);
  for (const { source, consumer } of references) {
    if (source !== null) adjacency.get(source)?.add(consumer);
  }

  return function affected(start: string[]): string[] {
    const reached = new Set(start);
    for (const key of reached) {
      for (const next of adjacency.get(key) ?? []) reached.add(next);
    }
    return [...reached].sort();
  };
}

function diagnosticsFor(
  document: JsonObject,
  {
    nodes,
    edges,
    unsupportedEdges,
    references,
  }: Omit<NormalizedWorkflow, "diagnostics">,
  unsupportedReferences: FieldLocation[],
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const affected = downstream(
    nodes,
    [...edges, ...unsupportedEdges],
    references,
  );
  const allNodes = nodes.map(({ key }) => key).sort();
  function add(code: DiagnosticCode, location: string, start: string[]): void {
    diagnostics.push({ code, location, affected: affected(start) });
  }
  for (const node of nodes) {
    const { type, typeVersion, key, pointer, parameters } = node;
    const version = supportedVersions.get(type);
    const unsupported = unsupportedNodeConfiguration(node);
    if (
      type === subworkflow &&
      (parameters.source !== "parameter" ||
        !identified(parameters.workflowJson))
    )
      add("subworkflow_missing", `${pointer}/parameters`, [key]);
    else if (version === undefined)
      add("unsupported_node", `${pointer}/type`, [key]);
    else if (version !== typeVersion)
      add("unsupported_version", `${pointer}/typeVersion`, [key]);
    else if (unsupported !== undefined)
      add("unsupported_config", `${pointer}${unsupported}`, [key]);
  }
  for (const { consumer, pointer } of unsupportedReferences) {
    add("unsupported_expression", pointer, [consumer]);
  }
  if (unsupportedEdges.length > 0) {
    add(
      "unsupported_connection",
      "/connections",
      unsupportedEdges.flatMap(({ from, to }) => [from, to]),
    );
  }
  const { settings, pinData } = document;
  if (
    settings !== undefined &&
    (!isObject(settings) ||
      Object.entries(settings).some(
        ([name, value]) => name !== "executionOrder" || value !== "v1",
      ))
  ) {
    diagnostics.push({
      code: "unsupported_config",
      location: "/settings",
      affected: allNodes,
    });
  }
  if (
    pinData !== undefined &&
    (!isObject(pinData) || Object.keys(pinData).length > 0)
  ) {
    diagnostics.push({
      code: "unsupported_config",
      location: "/pinData",
      affected: allNodes,
    });
  }
  return diagnostics;
}

export function parseWorkflow(bytes: Buffer): NormalizedWorkflow {
  const document = decodeWorkflow(bytes);
  if (!isObject(document)) throw new WorkflowError("invalid_workflow");
  if (!Array.isArray(document.nodes))
    throw new WorkflowError("invalid_workflow", "/nodes");
  if (!isObject(document.connections))
    throw new WorkflowError("broken_connection", "/connections");

  const nodes = normalizeNodes(document.nodes);
  const names = new Map(nodes.map((node) => [node.name, node]));
  const connections = normalizeConnections(document.connections, names);
  const references: FieldReference[] = [];
  const unsupportedReferences: FieldLocation[] = [];
  for (const node of nodes)
    fieldReferences(node, names, references, unsupportedReferences);
  const normalized = { nodes, ...connections, references };
  return {
    ...normalized,
    diagnostics: diagnosticsFor(document, normalized, unsupportedReferences),
  };
}
