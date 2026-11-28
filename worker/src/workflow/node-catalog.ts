import { parseExpressionAt } from "acorn";
import type { NormalizedNode } from "./n8n.js";
import { isObject } from "./static-context.js";

const prefix = "n8n-nodes-base.";
const langchainPrefix = "@n8n/n8n-nodes-langchain.";

export type CatalogLocalEffect = {
  kind: "passthrough" | "append_merge";
  inputs: number;
  outputs: number;
  preservesInput: boolean;
  preservesGuards: boolean;
};

export type CatalogServiceProfile =
  | {
      kind: "external_trigger";
      piiFieldPattern?: RegExp;
      piiBasis?: string;
    }
  | {
      kind: "external_service";
      piiFieldPattern?: RegExp;
      piiBasis?: string;
    }
  | {
      kind: "html_extract";
      sourceProperty: string;
    };

function hasOnlyKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function templateExpressions(value: string): string[] | undefined {
  const text = value.slice(1);
  const matches = [...text.matchAll(/\{\{([\s\S]*?)\}\}/g)];
  const remainder = text.replace(/\{\{([\s\S]*?)\}\}/g, "");
  if (remainder.includes("{{") || remainder.includes("}}")) return;
  return matches.map((match) => match[1]!.trim());
}

/**
 * Pure read-only parameter AST gate matching static-flow's safety rules:
 * rejects calls/mutations/getters/dynamic keys outside n8n's read accessors.
 */
export function isReadOnlyParameterTree(parameters: unknown): boolean {
  let remaining = 2048;
  const roots = new Set([
    "$json",
    "$input",
    "$node",
    "$now",
    "$today",
    "$env",
    "$vars",
    "$workflow",
    "$execution",
    "$itemIndex",
    "$runIndex",
    "undefined",
  ]);
  const safeKey = (key: unknown): boolean =>
    typeof key === "string" &&
    !["__proto__", "prototype", "constructor"].includes(key);
  const ast = (value: unknown, depth = 0): boolean => {
    if (--remaining < 0 || depth > 48 || !isObject(value)) return false;
    const child = (next: unknown): boolean => ast(next, depth + 1);
    if (value.type === "Literal")
      return (
        (!value.regex &&
          ["string", "number", "boolean"].includes(typeof value.value)) ||
        value.value === null
      );
    if (value.type === "Identifier")
      return typeof value.name === "string" && roots.has(value.name);
    if (value.type === "ChainExpression") return child(value.expression);
    if (value.type === "MemberExpression")
      return (
        child(value.object) &&
        isObject(value.property) &&
        (value.computed === true
          ? value.property.type === "Literal" &&
            (typeof value.property.value === "number" ||
              safeKey(value.property.value))
          : safeKey(value.property.name))
      );
    if (
      value.type === "CallExpression" &&
      isObject(value.callee) &&
      Array.isArray(value.arguments)
    ) {
      const callee = value.callee;
      if (callee.type === "Identifier" && callee.name === "$")
        return (
          value.arguments.length === 1 &&
          isObject(value.arguments[0]) &&
          value.arguments[0].type === "Literal" &&
          typeof value.arguments[0].value === "string"
        );
      if (
        callee.type !== "MemberExpression" ||
        callee.computed === true ||
        !isObject(callee.property) ||
        !["first", "last", "all"].includes(String(callee.property.name)) ||
        value.arguments.length > 0
      )
        return false;
      return (
        isObject(callee.object) &&
        ((callee.object.type === "Identifier" &&
          callee.object.name === "$input") ||
          (callee.object.type === "CallExpression" &&
            isObject(callee.object.callee) &&
            callee.object.callee.type === "Identifier" &&
            callee.object.callee.name === "$" &&
            child(callee.object)))
      );
    }
    if (["BinaryExpression", "LogicalExpression"].includes(String(value.type)))
      return child(value.left) && child(value.right);
    if (value.type === "UnaryExpression")
      return (
        ["!", "+", "-", "~", "typeof", "void"].includes(
          String(value.operator),
        ) && child(value.argument)
      );
    if (value.type === "ConditionalExpression")
      return (
        child(value.test) && child(value.consequent) && child(value.alternate)
      );
    if (value.type === "ArrayExpression" && Array.isArray(value.elements))
      return value.elements.every(
        (element) => element === null || child(element),
      );
    if (value.type === "ObjectExpression" && Array.isArray(value.properties))
      return value.properties.every(
        (property) =>
          isObject(property) &&
          property.type === "Property" &&
          property.kind === "init" &&
          property.method !== true &&
          property.computed !== true &&
          isObject(property.key) &&
          safeKey(property.key.name ?? property.key.value) &&
          child(property.value),
      );
    if (value.type === "TemplateLiteral" && Array.isArray(value.expressions))
      return value.expressions.every(child);
    return false;
  };
  const pending: { value: unknown; depth: number }[] = [
    { value: parameters, depth: 0 },
  ];
  while (pending.length) {
    if (--remaining < 0) return false;
    const { value, depth } = pending.pop()!;
    if (depth > 32) return false;
    if (typeof value === "string" && value.startsWith("=")) {
      if (value.length > 65536) return false;
      if (!value.includes("{{") && !value.includes("}}")) continue;
      const parts = templateExpressions(value);
      if (!parts) return false;
      for (const part of parts) {
        try {
          const expression = parseExpressionAt(part, 0, {
            ecmaVersion: "latest",
          });
          if (expression.end !== part.length || !ast(expression)) return false;
        } catch {
          return false;
        }
      }
    } else if (Array.isArray(value)) {
      if (value.length > 128) return false;
      pending.push(...value.map((next) => ({ value: next, depth: depth + 1 })));
    } else if (isObject(value)) {
      const entries = Object.entries(value);
      if (entries.length > 128 || entries.some(([key]) => !safeKey(key)))
        return false;
      pending.push(
        ...entries.map(([, next]) => ({ value: next, depth: depth + 1 })),
      );
    }
  }
  return true;
}

function validFilterConditions(filter: unknown): boolean {
  if (!isObject(filter)) return false;
  if (!Array.isArray(filter.conditions) || filter.conditions.length > 128)
    return false;
  if (
    filter.combinator !== undefined &&
    filter.combinator !== "and" &&
    filter.combinator !== "or"
  )
    return false;
  if (filter.options !== undefined && !isObject(filter.options)) return false;
  return filter.conditions.every(
    (condition) =>
      isObject(condition) &&
      isObject(condition.operator) &&
      typeof condition.operator.type === "string" &&
      typeof condition.operator.operation === "string" &&
      ["string", "number", "boolean", "dateTime", "array", "object"].includes(
        condition.operator.type,
      ),
  );
}

/**
 * Verified local item-subset / ordering / append-merge profiles.
 * Any dynamic code mode, cross-execution state, or unknown option returns undefined
 * so callers conservatively retain unresolved/opaque diagnostics.
 */
export function matchLocalCatalogEffect(
  node: NormalizedNode,
): CatalogLocalEffect | undefined {
  if (!isReadOnlyParameterTree(node.parameters)) return undefined;
  const p = node.parameters;
  if (
    node.type === prefix + "removeDuplicates" &&
    [1, 1.1, 2].includes(node.typeVersion)
  ) {
    const operation = p.operation ?? "removeDuplicateInputItems";
    if (
      operation !== "removeDuplicateInputItems" ||
      !hasOnlyKeys(p, [
        "operation",
        "compare",
        "fieldsToExclude",
        "fieldsToCompare",
        "options",
      ]) ||
      (p.compare !== undefined &&
        !["allFields", "allFieldsExcept", "selectedFields"].includes(
          typeof p.compare === "string" ? p.compare : "",
        )) ||
      (p.options !== undefined && !isObject(p.options))
    )
      return;
    const options = isObject(p.options) ? p.options : {};
    // `removeOtherFields: true` strips non-compared keys instead of preserving items.
    if (
      !hasOnlyKeys(options, ["disableDotNotation", "removeOtherFields"]) ||
      (options.disableDotNotation !== undefined &&
        typeof options.disableDotNotation !== "boolean") ||
      (options.removeOtherFields !== undefined &&
        options.removeOtherFields !== false)
    )
      return;
    return {
      kind: "passthrough",
      inputs: 1,
      outputs: 1,
      preservesInput: true,
      preservesGuards: true,
    };
  }

  if (node.type === prefix + "sort" && node.typeVersion === 1) {
    // `type: "code"` executes arbitrary user JS and must never match passthrough.
    const sortType = p.type ?? "simple";
    if (
      (sortType !== "simple" && sortType !== "random") ||
      !hasOnlyKeys(p, ["type", "sortFieldsUi", "options"]) ||
      (p.options !== undefined && !isObject(p.options))
    )
      return;
    const options = isObject(p.options) ? p.options : {};
    if (
      !hasOnlyKeys(options, ["disableDotNotation"]) ||
      (options.disableDotNotation !== undefined &&
        typeof options.disableDotNotation !== "boolean")
    )
      return;
    return {
      kind: "passthrough",
      inputs: 1,
      outputs: 1,
      preservesInput: true,
      preservesGuards: true,
    };
  }

  if (
    node.type === prefix + "filter" &&
    [2, 2.1, 2.2].includes(node.typeVersion)
  ) {
    if (
      !hasOnlyKeys(p, ["conditions", "looseTypeValidation", "options"]) ||
      (p.looseTypeValidation !== undefined &&
        typeof p.looseTypeValidation !== "boolean") ||
      (p.options !== undefined && !isObject(p.options)) ||
      (p.conditions !== undefined && !validFilterConditions(p.conditions))
    )
      return;
    const options = isObject(p.options) ? p.options : {};
    if (
      !hasOnlyKeys(options, ["ignoreCase"]) ||
      (options.ignoreCase !== undefined &&
        typeof options.ignoreCase !== "boolean")
    )
      return;
    // Filtering drops non-matching items without mutating kept items, but does
    // not claim a security guard here.
    return {
      kind: "passthrough",
      inputs: 1,
      outputs: 1,
      preservesInput: true,
      preservesGuards: true,
    };
  }

  if (node.type === prefix + "merge" && [2, 2.1].includes(node.typeVersion)) {
    const mode = p.mode ?? "append";
    const options = isObject(p.options) ? p.options : {};
    if (
      mode !== "append" ||
      !hasOnlyKeys(p, ["mode", "options"]) ||
      (p.options !== undefined && !isObject(p.options)) ||
      Object.keys(options).length > 0
    )
      return;
    return {
      kind: "append_merge",
      inputs: 2,
      outputs: 1,
      preservesInput: false,
      preservesGuards: false,
    };
  }

  return undefined;
}

const messageFieldPattern =
  /^(?:text|message|body|chatInput|caption|user|username|sender|author|from)$/i;

/**
 * Declarative profiles for additional external triggers, read connectors, and
 * HTML content extraction observed across real n8n workflows.
 */
export function matchCatalogServiceSource(
  node: NormalizedNode,
): CatalogServiceProfile | undefined {
  const p = node.parameters;
  if (
    (p.operation !== undefined && typeof p.operation !== "string") ||
    (p.resource !== undefined && typeof p.resource !== "string")
  )
    return undefined;
  const operation = p.operation ?? "";
  const resource = p.resource ?? "";

  if (
    (node.type === prefix + "slackTrigger" && [1].includes(node.typeVersion)) ||
    (node.type === prefix + "whatsAppTrigger" &&
      [1].includes(node.typeVersion)) ||
    (node.type === langchainPrefix + "chatTrigger" &&
      [1, 1.1].includes(node.typeVersion))
  ) {
    return {
      kind: "external_trigger",
      piiFieldPattern: messageFieldPattern,
      piiBasis: "service_message_schema_candidate",
    };
  }

  if (
    node.type === prefix + "html" &&
    [1, 1.1, 1.2].includes(node.typeVersion) &&
    p.operation === "extractHtmlContent" &&
    (p.sourceData === undefined || p.sourceData === "json") &&
    isReadOnlyParameterTree(p)
  ) {
    const rawProp = p.dataPropertyName ?? "data";
    if (
      typeof rawProp === "string" &&
      !rawProp.startsWith("=") &&
      /^[A-Za-z0-9_-]{1,64}$/.test(rawProp)
    ) {
      return {
        kind: "html_extract",
        sourceProperty: rawProp,
      };
    }
    return undefined;
  }

  const externalRead =
    (node.type === prefix + "httpRequest" &&
      [1, 2, 3, 4, 4.1, 4.2, 4.3, 4.4, 4.5].includes(node.typeVersion)) ||
    (node.type === prefix + "supabase" &&
      [1].includes(node.typeVersion) &&
      (p.resource === undefined || p.resource === "row") &&
      ["get", "getAll"].includes(operation)) ||
    (node.type === prefix + "youTube" &&
      [1].includes(node.typeVersion) &&
      ["get", "getAll"].includes(operation)) ||
    (node.type === prefix + "zendesk" &&
      [1].includes(node.typeVersion) &&
      ["get", "getAll"].includes(operation)) ||
    (node.type === prefix + "box" &&
      [1].includes(node.typeVersion) &&
      ["get", "search", "list"].includes(operation)) ||
    (node.type === prefix + "dropbox" &&
      [1].includes(node.typeVersion) &&
      ["list", "search"].includes(operation)) ||
    (node.type === prefix + "googleDrive" &&
      [3].includes(node.typeVersion) &&
      ["list", "search", "get"].includes(operation)) ||
    (node.type === prefix + "rssFeedRead" &&
      [1, 1.1, 1.2].includes(node.typeVersion)) ||
    (node.type === prefix + "discord" &&
      [2].includes(node.typeVersion) &&
      (resource === "message" || resource === "") &&
      ["get", "getAll"].includes(operation)) ||
    (node.type === prefix + "slack" &&
      [2, 2.1, 2.2, 2.3, 2.4, 2.5].includes(node.typeVersion) &&
      ["get", "getAll", "history", "replies", "search"].includes(operation)) ||
    (node.type === prefix + "telegram" &&
      [1, 1.1, 1.2].includes(node.typeVersion) &&
      resource === "chat" &&
      ["get", "administrators", "member"].includes(operation));

  if (externalRead) {
    const isMessaging = [
      prefix + "slack",
      prefix + "discord",
      prefix + "telegram",
      prefix + "zendesk",
    ].includes(node.type);
    return {
      kind: "external_service",
      ...(isMessaging
        ? {
            piiFieldPattern: messageFieldPattern,
            piiBasis: "service_message_schema_candidate",
          }
        : {}),
    };
  }

  return undefined;
}
