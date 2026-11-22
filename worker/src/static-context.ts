import { parseWorkflow } from "./n8n.js";
import type { MainEdge, NormalizedNode, UnsupportedEdge } from "./n8n.js";
import type { StaticLocation } from "./static-contract.js";

export type JsonObject = Record<string, unknown>;

export interface ScalarField {
  index: number;
  kind: "key" | "value";
  value: string;
  /** Internal only: may contain an uploaded secret or identifying property key. */
  pointer: string;
  /** Safe structural location. Unknown property names are never copied here. */
  location: StaticLocation;
}

export interface Context {
  document: JsonObject;
  nodes: NormalizedNode[];
  edges: MainEdge[];
  unsupportedEdges: UnsupportedEdge[];
  nodeByKey: ReadonlyMap<string, NormalizedNode>;
  nodeByName: ReadonlyMap<string, NormalizedNode>;
  /** Describes connection channels only, not semantic support or safety. */
  topology: "complete" | "partial";
  fields: ScalarField[];
}

export function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const rootKeys = new Set([
  "nodes",
  "connections",
  "settings",
  "pinData",
  "staticData",
  "meta",
  "name",
  "id",
  "tags",
  "active",
  "versionId",
]);

const nodeKeys = new Set([
  "id",
  "name",
  "type",
  "typeVersion",
  "parameters",
  "credentials",
  "disabled",
  "position",
  "notes",
  "notesInFlow",
  "webhookId",
  "continueOnFail",
  "onError",
  "alwaysOutputData",
  "executeOnce",
  "retryOnFail",
  "maxTries",
  "waitBetweenTries",
]);

// This is an output-location vocabulary, not a node support allowlist. A rule
// still checks the precise node version, operation and field semantics itself.
const structuralKeys = new Set([
  "authentication",
  "httpMethod",
  "path",
  "responseMode",
  "responseData",
  "responseBody",
  "respondWith",
  "options",
  "conditions",
  "combinator",
  "leftValue",
  "rightValue",
  "operator",
  "type",
  "operation",
  "resource",
  "query",
  "queryReplacement",
  "url",
  "method",
  "sendHeaders",
  "headerParameters",
  "parameters",
  "name",
  "value",
  "headers",
  "headersJson",
  "jsonHeaders",
  "sendBody",
  "bodyParameters",
  "body",
  "jsonBody",
  "specifyBody",
  "contentType",
  "bodyContentType",
  "queryParameters",
  "sendQuery",
  "allowUnauthorizedCerts",
  "ignoreResponseCode",
  "redirect",
  "redirects",
  "followRedirects",
  "maxRedirects",
  "proxy",
  "timeout",
  "rejectUnauthorized",
  "allowUnauthorizedCertificates",
  "ssl",
  "tls",
  "sslCertificates",
  "command",
  "executeOnce",
  "jsCode",
  "pythonCode",
  "functionCode",
  "language",
  "mode",
  "source",
  "workflowId",
  "workflowJson",
  "workflowInputs",
  "waitForSubWorkflow",
  "fileSelector",
  "filePath",
  "fileName",
  "dataPropertyName",
  "binaryPropertyName",
  "fromEmail",
  "toEmail",
  "toRecipients",
  "subject",
  "text",
  "html",
  "channel",
  "channelId",
  "chatId",
  "message",
  "select",
  "value1",
  "value2",
  "values",
  "assignments",
  "includeOtherFields",
  "keepOnlySet",
  "executionOrder",
  "saveDataErrorExecution",
  "saveDataSuccessExecution",
  "saveExecutionProgress",
  "saveManualExecutions",
  "errorWorkflow",
  "callerPolicy",
  "callerIds",
]);

function pointerParts(pointer: string): string[] {
  if (pointer === "") return [];
  return pointer
    .slice(1)
    .split("/")
    .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/** Coarsen arbitrary keys to the closest structural ancestor safe to report. */
export function safeLocation(
  context: Pick<Context, "nodes" | "document">,
  pointer: string,
): StaticLocation {
  const parts = pointerParts(pointer);
  const root = parts[0];
  if (root === undefined || !rootKeys.has(root))
    return { nodeKey: null, pointer: "" };
  const safe = [root];
  let nodeKey: string | null = null;
  if (root === "nodes") {
    const index = parts[1];
    if (index === undefined || !/^(?:0|[1-9][0-9]*)$/.test(index))
      return { nodeKey, pointer: "/nodes" };
    const node = context.nodes[Number(index)];
    if (!node) return { nodeKey, pointer: "/nodes" };
    nodeKey = node.key;
    safe.push(index);
    const field = parts[2];
    if (field !== undefined && nodeKeys.has(field)) {
      safe.push(field);
      if (field === "parameters" || field === "position") {
        let current: unknown = node.raw[field];
        for (const part of parts.slice(3)) {
          if (Array.isArray(current)) {
            if (
              !/^(?:0|[1-9][0-9]*)$/.test(part) ||
              Number(part) >= current.length
            )
              break;
            current = current[Number(part)];
          } else if (
            isObject(current) &&
            structuralKeys.has(part) &&
            Object.hasOwn(current, part)
          ) {
            current = current[part];
          } else break;
          if (safe.join("/").length + part.length + 2 > 512) break;
          safe.push(part);
        }
      }
    }
  } else if (root === "settings") {
    let current: unknown = context.document.settings;
    for (const part of parts.slice(1)) {
      if (
        !isObject(current) ||
        !structuralKeys.has(part) ||
        !Object.hasOwn(current, part)
      )
        break;
      if (safe.join("/").length + part.length + 2 > 512) break;
      safe.push(part);
      current = current[part];
    }
  }
  return { nodeKey, pointer: "/" + safe.join("/") };
}

function collectFields(context: Context): ScalarField[] {
  const fields: ScalarField[] = [];
  function add(kind: ScalarField["kind"], value: string, pointer: string) {
    fields.push({
      index: fields.length,
      kind,
      value,
      pointer,
      location: safeLocation(context, pointer),
    });
  }
  function visit(value: unknown, pointer: string): void {
    if (typeof value === "string") {
      add("value", value, pointer);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${pointer}/${index}`));
    } else if (isObject(value)) {
      for (const [key, item] of Object.entries(value)) {
        const path = `${pointer}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`;
        add("key", key, path);
        visit(item, path);
      }
    }
  }
  visit(context.document, "");
  return fields;
}

export function createContext(bytes: Buffer): Context {
  // Keep the mature duplicate-key, encoding, depth, identity and graph checks.
  // Semantic diagnostics belong to the historical SQL profile, not every rule.
  const normalized = parseWorkflow(bytes);
  const document = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(bytes),
  ) as JsonObject;
  const context: Context = {
    document,
    nodes: normalized.nodes,
    edges: normalized.edges,
    unsupportedEdges: normalized.unsupportedEdges,
    nodeByKey: new Map(normalized.nodes.map((node) => [node.key, node])),
    nodeByName: new Map(normalized.nodes.map((node) => [node.name, node])),
    topology: normalized.unsupportedEdges.length > 0 ? "partial" : "complete",
    fields: [],
  };
  context.fields = collectFields(context);
  return context;
}
