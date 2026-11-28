import { parse, parseExpressionAt } from "acorn";
import type { NormalizedNode } from "./n8n.js";
import { isObject, type Context } from "./static-context.js";

/** Internal dependencies only; never serialize parameter values or node names. */
export interface BinaryInput {
  nodeKey: string;
  value: unknown;
  pointer: string;
}
export interface BinaryProvenance {
  state: "none" | "possible" | "unknown";
  inputs: BinaryInput[];
  diagnostics: string[];
}
const base = "n8n-nodes-base.";
const none = (): BinaryProvenance => ({
  state: "none",
  inputs: [],
  diagnostics: [],
});
const input = (node: NormalizedNode, value: unknown): BinaryInput => ({
  nodeKey: node.key,
  value,
  pointer: "/parameters",
});

// This is a precondition for an absence proof, not a general purity analyzer.
// Calls with unreviewed effects, writes and excessive syntax keep unknown.
function readOnlyParameters(parameters: unknown): boolean {
  let visits = 0;
  const safe = (value: unknown, depth = 0): boolean => {
    if (++visits > 2048 || depth > 32 || !isObject(value)) return false;
    if (value.type === "Literal" || value.type === "Identifier") return true;
    if (value.type === "MemberExpression")
      return (
        safe(value.object, depth + 1) &&
        (!value.computed || safe(value.property, depth + 1))
      );
    if (value.type === "ChainExpression")
      return safe(value.expression, depth + 1);
    if (value.type === "UnaryExpression")
      return value.operator !== "delete" && safe(value.argument, depth + 1);
    if (value.type === "BinaryExpression" || value.type === "LogicalExpression")
      return safe(value.left, depth + 1) && safe(value.right, depth + 1);
    if (value.type === "ConditionalExpression")
      return (
        safe(value.test, depth + 1) &&
        safe(value.consequent, depth + 1) &&
        safe(value.alternate, depth + 1)
      );
    if (value.type === "ArrayExpression" && Array.isArray(value.elements))
      return value.elements.every(
        (item) => item === null || safe(item, depth + 1),
      );
    if (value.type === "ObjectExpression" && Array.isArray(value.properties))
      return value.properties.every(
        (property) =>
          isObject(property) &&
          property.type === "Property" &&
          property.kind === "init" &&
          !property.method &&
          (!property.computed || safe(property.key, depth + 1)) &&
          safe(property.value, depth + 1),
      );
    if (value.type === "TemplateLiteral" && Array.isArray(value.expressions))
      return value.expressions.every((item) => safe(item, depth + 1));
    if (
      value.type === "CallExpression" &&
      isObject(value.callee) &&
      Array.isArray(value.arguments)
    ) {
      const callee = value.callee;
      return (
        callee.type === "Identifier" &&
        callee.name === "$" &&
        value.arguments.length === 1 &&
        isObject(value.arguments[0]) &&
        value.arguments[0].type === "Literal" &&
        typeof value.arguments[0].value === "string"
      );
    }
    return false;
  };
  const walk = (value: unknown, depth = 0): boolean => {
    if (++visits > 2048 || depth > 16) return false;
    if (typeof value === "string") {
      if (!value.startsWith("=")) return true;
      if (value.length > 65536) return false;
      const expressions = [...value.matchAll(/\{\{([\s\S]*?)\}\}/g)];
      if (!expressions.length || expressions.length > 32) return false;
      if (/\{\{|\}\}/.test(value.replace(/\{\{[\s\S]*?\}\}/g, "")))
        return false;
      return expressions.every((match) => {
        try {
          const source = match[1]!.trim();
          const expression = parseExpressionAt(source, 0, {
            ecmaVersion: "latest",
          });
          return expression.end === source.length && safe(expression);
        } catch {
          return false;
        }
      });
    }
    return (
      !(isObject(value) || Array.isArray(value)) ||
      Object.values(value).every((child) => walk(child, depth + 1))
    );
  };
  return walk(parameters);
}

/** n8n's fixed dotted source-property subset, not arbitrary JavaScript. */
export function jsonFieldExpression(field: unknown): string | undefined {
  if (typeof field !== "string" || field.length > 512 || field.startsWith("="))
    return;
  const parts = field.split(".");
  if (
    !parts.length ||
    parts.some(
      (part) =>
        !/^[A-Za-z0-9_$-]+$/.test(part) ||
        ["__proto__", "constructor", "prototype"].includes(part),
    )
  )
    return;
  return (
    "={{ $json" +
    parts.map((part) => "[" + JSON.stringify(part) + "]").join("") +
    " }}"
  );
}

// A deliberately small parse-only proof: a single return of fresh JSON-only
// item literals. Calls, spreads, accessors and preceding statements are excluded.
function freshJsonOnlyCode(node: NormalizedNode): boolean {
  if (
    ![1, 2].includes(node.typeVersion) ||
    (node.parameters.language ?? "javaScript") !== "javaScript"
  )
    return false;
  const source = node.parameters.jsCode;
  if (typeof source !== "string" || source.length > 65536) return false;
  try {
    const ast: unknown = parse(source, {
      ecmaVersion: "latest",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
    });
    if (!isObject(ast) || !Array.isArray(ast.body) || ast.body.length !== 1)
      return false;
    const statement = ast.body[0];
    if (
      !isObject(statement) ||
      statement.type !== "ReturnStatement" ||
      !isObject(statement.argument)
    )
      return false;
    const returned = statement.argument;
    const items =
      returned.type === "ArrayExpression" && Array.isArray(returned.elements)
        ? returned.elements
        : [returned];
    if (!items.length || items.length > 32) return false;
    let visits = 0;
    const safe = (value: unknown, depth = 0): boolean => {
      if (++visits > 1024 || depth > 24 || !isObject(value)) return false;
      if (value.type === "Literal") return true;
      if (value.type === "ArrayExpression" && Array.isArray(value.elements))
        return value.elements.every(
          (entry) => entry === null || safe(entry, depth + 1),
        );
      if (value.type === "ObjectExpression" && Array.isArray(value.properties))
        return value.properties.every(
          (entry) =>
            isObject(entry) &&
            entry.type === "Property" &&
            entry.kind === "init" &&
            !entry.computed &&
            !entry.method &&
            safe(entry.value, depth + 1),
        );
      return false;
    };
    return items.every(
      (item) =>
        isObject(item) &&
        item.type === "ObjectExpression" &&
        Array.isArray(item.properties) &&
        item.properties.length === 1 &&
        item.properties.every(
          (property) =>
            isObject(property) &&
            property.type === "Property" &&
            !property.computed &&
            !property.method &&
            property.kind === "init" &&
            isObject(property.key) &&
            (property.key.name ?? property.key.value) === "json" &&
            safe(property.value),
        ),
    );
  } catch {
    return false;
  }
}

/** Presence/provenance only. No file bytes, node code or expressions are executed. */
export function binaryInputProvenance(
  context: Context,
  consumer: NormalizedNode,
): BinaryProvenance {
  let visits = 0;
  const active = new Set<string>();
  const cache = new Map<string, BinaryProvenance>();
  const unknown = (
    node: NormalizedNode,
    code = "binary_provenance_unresolved",
    inputs: BinaryInput[] = [],
  ): BinaryProvenance => ({
    state: "unknown",
    inputs: [...inputs, input(node, undefined)],
    diagnostics: [code],
  });
  const join = (values: BinaryProvenance[]): BinaryProvenance => {
    if (!values.length) return unknown(consumer);
    const inputs = values.flatMap((value) => value.inputs);
    const limited = inputs.length > 64;
    return {
      state:
        limited || values.some((value) => value.state === "unknown")
          ? "unknown"
          : values.some((value) => value.state === "possible")
            ? "possible"
            : "none",
      inputs: inputs.slice(0, 64),
      diagnostics: [
        ...new Set([
          ...values.flatMap((value) => value.diagnostics),
          ...(limited ? ["binary_provenance_limit"] : []),
        ]),
      ],
    };
  };
  const incoming = (node: NormalizedNode, depth: number): BinaryProvenance => {
    const edges = context.edges.filter((edge) => edge.to === node.key);
    if (edges.length > 32) return unknown(node, "binary_provenance_limit");
    return join(
      edges.map((edge) => {
        const source = context.nodeByKey.get(edge.from)!;
        const result = visit(source, depth + 1);
        if (edge.input !== 0)
          return join([result, unknown(node, "binary_connection_unresolved")]);
        if (
          edge.output !== 0 &&
          ![base + "if", base + "switch"].includes(source.type)
        )
          return join([result, unknown(source)]);
        return result;
      }),
    );
  };
  const visit = (node: NormalizedNode, depth: number): BinaryProvenance => {
    const cached = cache.get(node.key);
    if (cached) return cached;
    if (++visits > 128 || depth > 24)
      return unknown(node, "binary_provenance_limit");
    if (active.has(node.key)) return unknown(node, "binary_provenance_cycle");
    active.add(node.key);
    const p = node.parameters;
    let result: BinaryProvenance;
    if (node.disabled) result = incoming(node, depth);
    else if (
      context.document.pinData !== undefined &&
      (!isObject(context.document.pinData) ||
        Object.hasOwn(context.document.pinData, node.name))
    )
      result = join([
        incoming(node, depth),
        unknown(node, "binary_pinned_output_unverified", [
          input(node, "={{ $json }}"),
        ]),
      ]);
    else if (
      context.edges.some((edge) => edge.to === node.key && edge.input !== 0)
    )
      result = join([
        incoming(node, depth),
        unknown(node, "binary_connection_unresolved"),
      ]);
    else if (!readOnlyParameters(p))
      result = join([
        ...(context.edges.some((edge) => edge.to === node.key)
          ? [incoming(node, depth)]
          : []),
        unknown(node, "binary_expression_effects_unresolved", [
          input(node, "={{ $json }}"),
        ]),
      ]);
    else if (
      node.type === base + "set" &&
      [3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion)
    ) {
      const options = p.options === undefined ? {} : p.options;
      const assignments = isObject(p.assignments)
        ? p.assignments.assignments
        : undefined;
      const binaryAssignments = Array.isArray(assignments)
        ? assignments.filter(
            (entry) => isObject(entry) && entry.type === "binary",
          )
        : [];
      if (
        !isObject(options) ||
        (p.assignments !== undefined && !isObject(p.assignments)) ||
        (p.mode !== undefined && p.mode !== "manual" && p.mode !== "raw") ||
        (assignments !== undefined && !Array.isArray(assignments)) ||
        (Array.isArray(assignments) &&
          assignments.some(
            (entry) =>
              !isObject(entry) ||
              ![
                "string",
                "number",
                "boolean",
                "array",
                "object",
                "binary",
              ].includes(String(entry.type)),
          ))
      )
        result = join([incoming(node, depth), unknown(node)]);
      else if (binaryAssignments.length)
        result = join([
          incoming(node, depth),
          unknown(node, "binary_assignment_selection_unresolved"),
        ]);
      else if (
        node.typeVersion >= 3.4 &&
        (p.includeOtherFields === undefined ||
          p.includeOtherFields === false ||
          options.stripBinary === true)
      )
        result = none();
      else if (node.typeVersion < 3.4 && options.includeBinary === false)
        result = none();
      else if (
        (options.includeBinary !== undefined &&
          typeof options.includeBinary !== "boolean") ||
        (options.stripBinary !== undefined &&
          typeof options.stripBinary !== "boolean") ||
        (p.includeOtherFields !== undefined &&
          typeof p.includeOtherFields !== "boolean")
      )
        result = join([incoming(node, depth), unknown(node)]);
      else result = incoming(node, depth);
    } else if (node.type === base + "code" && freshJsonOnlyCode(node))
      result = none();
    else if (
      node.type === base + "convertToFile" &&
      [1, 1.1, 1.2].includes(node.typeVersion)
    ) {
      if (p.operation === "toJson")
        result = {
          state: "possible",
          inputs: [input(node, "={{ $json }}")],
          diagnostics: [],
        };
      else if (p.operation === "toText" || p.operation === "toBinary") {
        const expression = jsonFieldExpression(p.sourceProperty);
        result = {
          state: expression ? "possible" : "unknown",
          inputs: [input(node, expression ?? "={{ $json }}")],
          diagnostics: expression ? [] : ["binary_source_field_unresolved"],
        };
      } else
        result = unknown(node, "binary_conversion_profile_unresolved", [
          input(node, "={{ $json }}"),
        ]);
    } else if (
      (node.type === base + "if" &&
        [1, 2, 2.1, 2.2, 2.3].includes(node.typeVersion)) ||
      (node.type === base + "switch" &&
        [1, 2, 3, 3.1, 3.2, 3.3, 3.4].includes(node.typeVersion)) ||
      (node.type === base + "noOp" && node.typeVersion === 1)
    )
      result = incoming(node, depth);
    else if (node.type === base + "code")
      result = join([
        incoming(node, depth),
        unknown(node, "binary_provenance_unresolved", [
          input(node, "={{ $json }}"),
        ]),
      ]);
    else if (
      node.type === base + "readWriteFile" &&
      node.typeVersion === 1 &&
      (p.operation ?? "read") === "read"
    )
      result = {
        state: "possible",
        inputs: [input(node, undefined)],
        diagnostics: [],
      };
    else
      result = join([
        ...(context.edges.some((edge) => edge.to === node.key)
          ? [incoming(node, depth)]
          : []),
        unknown(node),
      ]);
    if (
      !node.disabled &&
      (node.raw.continueOnFail === true ||
        (node.raw.onError !== undefined &&
          node.raw.onError !== "stopWorkflow") ||
        node.raw.alwaysOutputData === true)
    )
      result = join([
        result,
        incoming(node, depth),
        unknown(node, "binary_error_output_unresolved"),
      ]);
    active.delete(node.key);
    cache.set(node.key, result);
    return result;
  };
  const result = incoming(consumer, 0);
  return readOnlyParameters(consumer.parameters)
    ? result
    : join([
        result,
        unknown(consumer, "binary_expression_effects_unresolved", [
          input(consumer, "={{ $json }}"),
        ]),
      ]);
}
