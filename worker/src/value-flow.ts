import { createHash } from "node:crypto";
import { parse, parseExpressionAt } from "acorn";
import type { NormalizedNode } from "./n8n.js";
import { isObject } from "./static-context.js";
import type { Context } from "./static-context.js";

// Internal analysis structures. Field names and guard literals are untrusted
// input data and MUST NOT be copied into public result evidence.
export type Sensitivity =
  "secret_candidate" | "pii_candidate" | "public_literal" | "unknown";
export type Origin = {
  nodeKey: string;
  fieldPath: string;
  kind:
    | "webhook"
    | "literal"
    | "credential"
    | "database"
    | "subworkflow"
    | "node_output";
};
export type TransformEvidence = {
  nodeKey: string;
  kind:
    | "numeric_conversion"
    | "url_component_encoding"
    | "html_escape"
    | "concatenation"
    | "object_mapping"
    | "serialization";
  inputValueIds: string[];
};
export type GuardEvidence = {
  nodeKey: string;
  outputs: number[];
  kind: "number_type" | "equals_literal" | "not_equals_literal";
  valueId: string;
  operator: string;
  literal?: string | number | boolean;
  origins: Origin[];
};
export interface AbstractValue {
  status: "resolved" | "partial" | "unknown";
  presence: "present" | "absent" | "unknown";
  origins: Origin[];
  sensitivity: Sensitivity;
  sensitivityClasses: Sensitivity[];
  sensitivityBasis: string[];
  trust: "external" | "internal" | "unknown";
  transforms: TransformEvidence[];
  guards: GuardEvidence[];
  paths: string[][];
  fullObject: boolean;
  diagnosticCodes: string[];
  valueId: string;
  fields?: Record<string, AbstractValue>;
  fieldsComplete?: boolean;
}
export interface FlowDiagnostic {
  nodeKey: string;
  code: string;
}
export interface SourceAnnotation {
  nodeKey: string;
  fieldPath: string;
  sensitivity: "secret_candidate" | "pii_candidate" | "public_literal";
  provenance: "operator" | "schema";
}
export interface ValueFlowOptions {
  sourceAnnotations?: readonly SourceAnnotation[];
}
export interface ResolveOptions {
  expressionMode?: "n8n" | "template";
  fieldName?: string;
}
export interface ValueFlow {
  resolve(
    nodeKey: string,
    value: unknown,
    options?: ResolveOptions,
  ): AbstractValue;
  output(nodeKey: string, fieldPath: string, port?: number): AbstractValue;
  readonly diagnostics: FlowDiagnostic[];
}

export const valueFlowLimits = {
  recursion: 64,
  requests: 4096,
  astNodes: 2048,
  fields: 128,
  alternatives: 64,
  annotations: 256,
} as const;

const prefix = "n8n-nodes-base.";
const hash = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const unique = <T>(values: T[]): T[] => [
  ...new Map(values.map((value) => [JSON.stringify(value), value])).values(),
];
const pointer = (parts: string[]): string =>
  parts.length
    ? "/" +
      parts
        .map((part) => part.replace(/~/g, "~0").replace(/\//g, "~1"))
        .join("/")
    : "";
const parts = (path: string): string[] =>
  path.startsWith("/")
    ? path
        .slice(1)
        .split("/")
        .map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    : path === ""
      ? []
      : path.split(".");
const safeParts = (path: string[]): boolean =>
  path.length <= 32 &&
  path.every(
    (part) =>
      part.length <= 256 &&
      !["__proto__", "prototype", "constructor"].includes(part),
  );
const severity = (sensitivity: Sensitivity): number =>
  ({ public_literal: 0, unknown: 1, pii_candidate: 2, secret_candidate: 3 })[
    sensitivity
  ];

function empty(nodeKey: string, code?: string, absent = false): AbstractValue {
  return {
    status: code ? "unknown" : "resolved",
    presence: absent ? "absent" : "unknown",
    origins: [],
    sensitivity: absent ? "public_literal" : "unknown",
    sensitivityClasses: [absent ? "public_literal" : "unknown"],
    sensitivityBasis: absent ? ["field_absent"] : [],
    trust: "unknown",
    transforms: [],
    guards: [],
    paths: [[nodeKey]],
    fullObject: false,
    diagnosticCodes: code ? [code] : [],
    valueId: hash([nodeKey, code ?? "absent"]),
  };
}

function guardKey(guard: GuardEvidence): string {
  return JSON.stringify([
    guard.nodeKey,
    guard.kind,
    guard.valueId,
    guard.operator,
    guard.literal,
  ]);
}

function join(
  values: AbstractValue[],
  nodeKey: string,
  code?: string,
): AbstractValue {
  if (!values.length) return empty(nodeKey, code ?? "input_not_connected");
  if (values.length === 1 && !code) return structuredClone(values[0]!);
  const ids = unique(values.map((value) => value.valueId));
  const commonGuards = values[0]!.guards
    .filter((guard) =>
      values.every((value) =>
        value.guards.some((other) => guardKey(other) === guardKey(guard)),
      ),
    )
    .map((guard) => ({
      ...guard,
      outputs: unique(
        values.flatMap((value) =>
          value.guards
            .filter((other) => guardKey(other) === guardKey(guard))
            .flatMap((other) => other.outputs),
        ),
      ),
    }));
  const sensitivityClasses = unique<Sensitivity>([
    ...values.flatMap((value) => value.sensitivityClasses),
    ...(code ? ["unknown" as const] : []),
  ]).sort((a, b) => severity(b) - severity(a));
  const origins = unique(values.flatMap((value) => value.origins));
  const paths = unique(values.flatMap((value) => value.paths));
  const limited =
    origins.length > valueFlowLimits.alternatives ||
    paths.length > valueFlowLimits.alternatives;
  if (limited && !sensitivityClasses.includes("unknown")) {
    sensitivityClasses.push("unknown");
    sensitivityClasses.sort((a, b) => severity(b) - severity(a));
  }
  const diagnostics = unique([
    ...values.flatMap((value) => value.diagnosticCodes),
    ...(code ? [code] : []),
    ...(limited ? ["flow_alternative_limit"] : []),
  ]);
  return {
    status: diagnostics.length
      ? origins.length
        ? "partial"
        : "unknown"
      : values.some((value) => value.status !== "resolved")
        ? "partial"
        : "resolved",
    presence: values.every((value) => value.presence === "present")
      ? "present"
      : values.every((value) => value.presence === "absent")
        ? "absent"
        : "unknown",
    origins: origins.slice(0, valueFlowLimits.alternatives),
    sensitivity: sensitivityClasses[0]!,
    sensitivityClasses,
    sensitivityBasis: unique(values.flatMap((value) => value.sensitivityBasis)),
    trust: values.every((value) => value.trust === "external")
      ? "external"
      : values.every((value) => value.trust === "internal")
        ? "internal"
        : "unknown",
    transforms: unique(values.flatMap((value) => value.transforms)).slice(
      0,
      valueFlowLimits.alternatives,
    ),
    guards: limited ? [] : commonGuards,
    paths: paths.slice(0, valueFlowLimits.alternatives),
    fullObject: values.some((value) => value.fullObject),
    diagnosticCodes: diagnostics,
    valueId: ids.length === 1 ? ids[0]! : hash(ids.sort()),
  };
}

export function buildValueFlow(
  context: Context,
  options: ValueFlowOptions = {},
): ValueFlow {
  return new ValueFlowAnalyzer(context, options);
}

class ValueFlowAnalyzer implements ValueFlow {
  readonly diagnostics: FlowDiagnostic[] = [];
  private readonly active = new Set<string>();
  private readonly cache = new Map<string, AbstractValue>();
  private requests = 0;
  constructor(
    private readonly context: Context,
    private readonly options: ValueFlowOptions,
  ) {}

  resolve(
    nodeKey: string,
    value: unknown,
    options: ResolveOptions = {},
  ): AbstractValue {
    return this.resolveValue(nodeKey, value, options, 0);
  }

  output(nodeKey: string, fieldPath: string, port = 0): AbstractValue {
    return this.nodeValue(nodeKey, parts(fieldPath), port, 0);
  }

  private note(nodeKey: string, code: string): void {
    if (
      this.diagnostics.length < 256 &&
      !this.diagnostics.some(
        (item) => item.nodeKey === nodeKey && item.code === code,
      )
    )
      this.diagnostics.push({ nodeKey, code });
  }

  private unknown(
    nodeKey: string,
    code: string,
    values: AbstractValue[] = [],
  ): AbstractValue {
    this.note(nodeKey, code);
    return values.length ? join(values, nodeKey, code) : empty(nodeKey, code);
  }

  private bounded(nodeKey: string, depth: number): boolean {
    this.requests++;
    if (
      depth > valueFlowLimits.recursion ||
      this.requests > valueFlowLimits.requests
    ) {
      this.note(nodeKey, "flow_budget_exceeded");
      return false;
    }
    return true;
  }

  private classify(name: string): {
    sensitivity: Sensitivity;
    basis: string[];
  } {
    if (
      /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)/i.test(
        name,
      )
    )
      return {
        sensitivity: "secret_candidate",
        basis: ["field_name_inference"],
      };
    if (/(?:email|phone|mobile|ssn|birth|address|full[_-]?name)/i.test(name))
      return { sensitivity: "pii_candidate", basis: ["field_name_inference"] };
    return { sensitivity: "unknown", basis: [] };
  }

  private literal(
    nodeKey: string,
    value: unknown,
    fieldName = "",
    depth = 0,
  ): AbstractValue {
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    if (isObject(value) || Array.isArray(value)) {
      const entries = Object.entries(value);
      if (entries.length === 0)
        return {
          ...empty(nodeKey),
          presence: "present",
          sensitivity: "public_literal",
          sensitivityClasses: ["public_literal"],
          sensitivityBasis: ["literal_definition"],
          trust: "internal",
          fullObject: true,
          fields: {},
          fieldsComplete: true,
          valueId: hash(["literal", value]),
        };
      const fields = Object.fromEntries(
        entries
          .slice(0, valueFlowLimits.fields)
          .map(([key, child]) => [
            pointer([key]),
            this.literal(nodeKey, child, key, depth + 1),
          ]),
      );
      const result = join(
        Object.values(fields),
        nodeKey,
        entries.length > valueFlowLimits.fields
          ? "flow_field_limit"
          : undefined,
      );
      return {
        ...result,
        presence: "present",
        fullObject: true,
        fields,
        fieldsComplete: entries.length <= valueFlowLimits.fields,
        valueId: hash([
          "object",
          Object.entries(fields).map(([key, child]) => [key, child.valueId]),
        ]),
      };
    }
    const inferred = this.classify(fieldName);
    const stringPii =
      typeof value === "string" &&
      /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value);
    const sensitivity =
      inferred.sensitivity !== "unknown"
        ? inferred.sensitivity
        : stringPii
          ? "pii_candidate"
          : "public_literal";
    return {
      status: "resolved",
      presence: "present",
      origins: [{ nodeKey, fieldPath: "", kind: "literal" }],
      sensitivity,
      sensitivityClasses: unique([
        sensitivity,
        ...(stringPii ? ["pii_candidate" as const] : []),
      ]),
      sensitivityBasis: inferred.basis.length
        ? inferred.basis
        : stringPii
          ? ["literal_format_inference"]
          : ["literal_definition"],
      trust: "internal",
      transforms: [],
      guards: [],
      paths: [[nodeKey]],
      fullObject: false,
      diagnosticCodes: [],
      valueId: hash(["literal", value]),
    };
  }

  private source(
    node: NormalizedNode,
    path: string[],
    kind: Origin["kind"],
    depth: number,
  ): AbstractValue {
    const fieldPath = pointer(path);
    const inferred = this.classify(path.at(-1) ?? "");
    const annotations = (this.options.sourceAnnotations ?? [])
      .slice(0, valueFlowLimits.annotations)
      .filter(
        (item) => item.nodeKey === node.key && safeParts(parts(item.fieldPath)),
      );
    const exactMatches = annotations.filter(
      (item) => pointer(parts(item.fieldPath)) === fieldPath,
    );
    const exact = exactMatches.sort(
      (a, b) => severity(b.sensitivity) - severity(a.sensitivity),
    )[0];
    const result: AbstractValue = {
      status: "resolved",
      presence: "unknown",
      origins: [{ nodeKey: node.key, fieldPath, kind }],
      sensitivity: exact?.sensitivity ?? inferred.sensitivity,
      sensitivityClasses: exact
        ? unique(exactMatches.map((item) => item.sensitivity))
        : [inferred.sensitivity],
      sensitivityBasis: exact
        ? ["trusted_" + exact.provenance + "_annotation"]
        : inferred.basis,
      trust:
        kind === "webhook" || kind === "subworkflow" ? "external" : "unknown",
      transforms: [],
      guards: [],
      paths: [[node.key]],
      fullObject: path.length === 0,
      diagnosticCodes: [],
      valueId: hash([kind, node.key, fieldPath]),
    };
    if (annotations.length && depth < valueFlowLimits.recursion) {
      result.fields = Object.fromEntries(
        annotations
          .filter((item) =>
            pointer(parts(item.fieldPath)).startsWith(fieldPath + "/"),
          )
          .slice(0, valueFlowLimits.fields)
          .map((item) => [
            pointer(parts(item.fieldPath)).slice(fieldPath.length),
            this.source(node, parts(item.fieldPath), kind, depth + 1),
          ]),
      );
      const aggregate = join(
        [result, ...Object.values(result.fields)],
        node.key,
      );
      result.sensitivity = aggregate.sensitivity;
      result.sensitivityClasses = aggregate.sensitivityClasses;
      result.sensitivityBasis = aggregate.sensitivityBasis;
    }
    if (
      (this.options.sourceAnnotations?.length ?? 0) >
      valueFlowLimits.annotations
    )
      return this.unknown(node.key, "source_annotation_limit", [result]);
    if (new Set(exactMatches.map((item) => item.sensitivity)).size > 1)
      return this.unknown(node.key, "source_annotation_conflict", [result]);
    return result;
  }

  private resolveValue(
    nodeKey: string,
    value: unknown,
    options: ResolveOptions,
    depth: number,
  ): AbstractValue {
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    if (
      typeof value !== "string" ||
      (options.expressionMode !== "template" && !value.startsWith("="))
    )
      return this.literal(nodeKey, value, options.fieldName, depth + 1);
    const text = value.startsWith("=") ? value.slice(1) : value;
    const matches = [...text.matchAll(/\{\{([\s\S]*?)\}\}/g)];
    if (!matches.length)
      return this.unknown(nodeKey, "expression_syntax_unsupported");
    const values = matches.map((match) =>
      this.expression(nodeKey, match[1]!, depth + 1),
    );
    const remainder = text.replace(/\{\{([\s\S]*?)\}\}/g, "");
    if (remainder.includes("{{") || remainder.includes("}}"))
      return this.unknown(nodeKey, "expression_syntax_unsupported", values);
    if (matches.length === 1 && text.trim() === matches[0]![0])
      return values[0]!;
    return this.transform(
      nodeKey,
      [...values, this.literal(nodeKey, remainder)],
      "concatenation",
    );
  }

  private expression(
    nodeKey: string,
    text: string,
    depth: number,
  ): AbstractValue {
    try {
      const ast = parseExpressionAt(text, 0, {
        ecmaVersion: "latest",
      }) as unknown;
      if (
        !isObject(ast) ||
        typeof ast.end !== "number" ||
        text.slice(ast.end).trim()
      )
        return this.unknown(nodeKey, "expression_syntax_unsupported");
      const stack: unknown[] = [ast];
      let count = 0;
      while (stack.length) {
        const value = stack.pop();
        if (!isObject(value)) continue;
        if (++count > valueFlowLimits.astNodes)
          return this.unknown(nodeKey, "expression_ast_limit");
        for (const child of Object.values(value)) {
          if (Array.isArray(child)) stack.push(...child);
          else if (isObject(child)) stack.push(child);
        }
      }
      return this.astValue(nodeKey, ast, depth + 1);
    } catch {
      return this.unknown(nodeKey, "expression_parse_unavailable");
    }
  }

  private transform(
    nodeKey: string,
    values: AbstractValue[],
    kind: TransformEvidence["kind"],
  ): AbstractValue {
    const merged = join(values, nodeKey);
    return {
      ...merged,
      fullObject: kind === "serialization" && merged.fullObject,
      guards: [],
      transforms: [
        ...merged.transforms,
        { nodeKey, kind, inputValueIds: values.map((value) => value.valueId) },
      ].slice(0, valueFlowLimits.alternatives),
      valueId: hash([kind, values.map((value) => value.valueId)]),
    };
  }

  private astValue(
    nodeKey: string,
    ast: Record<string, unknown>,
    depth: number,
  ): AbstractValue {
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    if (ast.type === "Literal")
      return this.literal(nodeKey, ast.value, "", depth + 1);
    if (
      ast.type === "CallExpression" &&
      isObject(ast.callee) &&
      ast.callee.type === "MemberExpression" &&
      isObject(ast.callee.object) &&
      ast.callee.object.name === "$input" &&
      isObject(ast.callee.property) &&
      ast.callee.property.name === "all" &&
      Array.isArray(ast.arguments) &&
      ast.arguments.length === 0
    )
      return { ...this.input(nodeKey, [], depth + 1), fullObject: true };
    const ref = this.reference(ast);
    if (ref) {
      if (!safeParts(ref.path))
        return this.unknown(nodeKey, "unsafe_field_reference");
      if (ref.kind === "current")
        return this.input(nodeKey, ref.path, depth + 1);
      if (ref.kind === "credential") {
        const owner = this.context.nodeByKey.get(nodeKey);
        if (!owner) return this.unknown(nodeKey, "node_missing");
        return {
          ...this.source(owner, ref.path, "credential", depth + 1),
          sensitivity: "secret_candidate",
          sensitivityClasses: ["secret_candidate"],
          sensitivityBasis: ["credential_reference"],
          trust: "internal",
        };
      }
      const source = this.context.nodeByName.get(ref.name!);
      if (!source || !this.connected(source.key, nodeKey))
        return this.unknown(nodeKey, "direct_reference_unconnected");
      return this.nodeValue(source.key, ref.path, 0, depth + 1);
    }
    if (
      ast.type === "CallExpression" &&
      isObject(ast.callee) &&
      Array.isArray(ast.arguments) &&
      ast.arguments.length === 1 &&
      isObject(ast.arguments[0])
    ) {
      const name =
        ast.callee.type === "Identifier" ? ast.callee.name : undefined;
      if (
        name === "Number" ||
        name === "parseInt" ||
        name === "parseFloat" ||
        name === "encodeURIComponent"
      )
        return this.transform(
          nodeKey,
          [this.astValue(nodeKey, ast.arguments[0], depth + 1)],
          name === "encodeURIComponent"
            ? "url_component_encoding"
            : "numeric_conversion",
        );
      if (
        ast.callee.type === "MemberExpression" &&
        isObject(ast.callee.object) &&
        ast.callee.object.name === "JSON" &&
        isObject(ast.callee.property) &&
        ast.callee.property.name === "stringify"
      )
        return this.transform(
          nodeKey,
          [this.astValue(nodeKey, ast.arguments[0], depth + 1)],
          "serialization",
        );
    }
    if (
      ast.type === "BinaryExpression" &&
      ast.operator === "+" &&
      isObject(ast.left) &&
      isObject(ast.right)
    )
      return this.transform(
        nodeKey,
        [
          this.astValue(nodeKey, ast.left, depth + 1),
          this.astValue(nodeKey, ast.right, depth + 1),
        ],
        "concatenation",
      );
    if (
      ast.type === "TemplateLiteral" &&
      Array.isArray(ast.expressions) &&
      Array.isArray(ast.quasis)
    )
      return this.transform(
        nodeKey,
        [
          ...ast.expressions.map((item) =>
            isObject(item)
              ? this.astValue(nodeKey, item, depth + 1)
              : this.unknown(nodeKey, "expression_syntax_unsupported"),
          ),
          ...ast.quasis.map((item) =>
            this.literal(
              nodeKey,
              isObject(item) && isObject(item.value) ? item.value.cooked : "",
            ),
          ),
        ],
        "concatenation",
      );
    if (ast.type === "ObjectExpression" && Array.isArray(ast.properties)) {
      const fields: Record<string, AbstractValue> = {};
      for (const item of ast.properties.slice(0, valueFlowLimits.fields)) {
        if (
          !isObject(item) ||
          item.type !== "Property" ||
          item.computed === true ||
          item.kind !== "init" ||
          !isObject(item.key) ||
          !isObject(item.value)
        )
          return this.unknown(
            nodeKey,
            "object_expression_unsupported",
            Object.values(fields),
          );
        const name =
          item.key.type === "Identifier" ? item.key.name : item.key.value;
        if (typeof name !== "string" || !safeParts([name]))
          return this.unknown(
            nodeKey,
            "unsafe_field_reference",
            Object.values(fields),
          );
        fields[pointer([name])] = this.astValue(nodeKey, item.value, depth + 1);
      }
      const result = join(
        Object.values(fields),
        nodeKey,
        ast.properties.length > valueFlowLimits.fields
          ? "flow_field_limit"
          : undefined,
      );
      return {
        ...result,
        fullObject: true,
        fields,
        fieldsComplete: ast.properties.length <= valueFlowLimits.fields,
        valueId: hash(
          Object.entries(fields).map(([name, value]) => [name, value.valueId]),
        ),
      };
    }
    if (ast.type === "ArrayExpression" && Array.isArray(ast.elements)) {
      const fields = Object.fromEntries(
        ast.elements
          .slice(0, valueFlowLimits.fields)
          .map((value, index) => [
            pointer([String(index)]),
            isObject(value)
              ? this.astValue(nodeKey, value, depth + 1)
              : this.literal(nodeKey, null),
          ]),
      );
      return {
        ...join(
          Object.values(fields),
          nodeKey,
          ast.elements.length > valueFlowLimits.fields
            ? "flow_field_limit"
            : undefined,
        ),
        fullObject: true,
        fields,
        fieldsComplete: ast.elements.length <= valueFlowLimits.fields,
      };
    }
    const candidates: AbstractValue[] = [];
    for (const child of Object.values(ast)) {
      if (isObject(child) && typeof child.type === "string")
        candidates.push(this.astValue(nodeKey, child, depth + 1));
      else if (Array.isArray(child))
        for (const entry of child)
          if (isObject(entry) && typeof entry.type === "string")
            candidates.push(this.astValue(nodeKey, entry, depth + 1));
    }
    return this.unknown(
      nodeKey,
      "expression_semantics_unsupported",
      candidates,
    );
  }

  private reference(ast: Record<string, unknown>):
    | {
        kind: "current" | "direct" | "credential";
        name?: string;
        path: string[];
      }
    | undefined {
    const suffix: string[] = [];
    let current = ast;
    while (
      current.type === "MemberExpression" &&
      isObject(current.object) &&
      isObject(current.property)
    ) {
      const key =
        current.computed === true
          ? current.property.type === "Literal"
            ? current.property.value
            : undefined
          : current.property.name;
      if (typeof key !== "string" && typeof key !== "number") return;
      suffix.unshift(String(key));
      current = current.object;
    }
    if (current.type === "Identifier" && current.name === "$json")
      return { kind: "current", path: suffix };
    if (
      current.type === "Identifier" &&
      current.name === "$input" &&
      suffix[0] === "item" &&
      suffix[1] === "json"
    )
      return { kind: "current", path: suffix.slice(2) };
    if (
      current.type === "Identifier" &&
      current.name === "$node" &&
      suffix.length >= 2 &&
      suffix[1] === "json"
    )
      return { kind: "direct", name: suffix[0], path: suffix.slice(2) };
    if (
      current.type === "CallExpression" &&
      isObject(current.callee) &&
      current.callee.name === "$" &&
      Array.isArray(current.arguments) &&
      current.arguments.length === 1 &&
      isObject(current.arguments[0]) &&
      current.arguments[0].type === "Literal" &&
      typeof current.arguments[0].value === "string" &&
      suffix[0] === "item" &&
      suffix[1] === "json"
    )
      return {
        kind: "direct",
        name: current.arguments[0].value,
        path: suffix.slice(2),
      };
    if (
      current.type === "Identifier" &&
      ["$env", "$credentials"].includes(String(current.name))
    )
      return {
        kind: "credential",
        path: [String(current.name).slice(1), ...suffix],
      };
    if (
      current.type === "CallExpression" &&
      isObject(current.callee) &&
      current.callee.type === "MemberExpression" &&
      isObject(current.callee.property) &&
      current.callee.property.name === "first" &&
      isObject(current.callee.object) &&
      Array.isArray(current.arguments) &&
      current.arguments.length === 0 &&
      suffix[0] === "json"
    ) {
      const target = current.callee.object;
      if (target.type === "Identifier" && target.name === "$input")
        return { kind: "current", path: suffix.slice(1) };
      if (
        target.type === "CallExpression" &&
        isObject(target.callee) &&
        target.callee.name === "$" &&
        Array.isArray(target.arguments) &&
        target.arguments.length === 1 &&
        isObject(target.arguments[0]) &&
        target.arguments[0].type === "Literal" &&
        typeof target.arguments[0].value === "string"
      )
        return {
          kind: "direct",
          name: target.arguments[0].value,
          path: suffix.slice(1),
        };
    }
  }

  private connected(from: string, to: string): boolean {
    const pending = [from],
      visited = new Set<string>();
    while (pending.length && visited.size <= 64) {
      const key = pending.shift()!;
      if (key === to) return true;
      if (visited.has(key)) continue;
      visited.add(key);
      pending.push(
        ...this.context.edges
          .filter((edge) => edge.from === key)
          .map((edge) => edge.to),
      );
    }
    return false;
  }

  private input(
    nodeKey: string,
    path: string[],
    depth: number,
    inputIndex?: number,
  ): AbstractValue {
    const edges = this.context.edges.filter(
      (edge) =>
        edge.to === nodeKey &&
        (inputIndex === undefined || edge.input === inputIndex),
    );
    if (
      inputIndex === undefined &&
      this.context.nodeByKey.get(nodeKey)?.type !== prefix + "merge" &&
      edges.some((edge) => edge.input !== 0)
    )
      return this.unknown(nodeKey, "input_port_unsupported");
    return join(
      edges.map((edge) =>
        this.nodeValue(edge.from, path, edge.output, depth + 1),
      ),
      nodeKey,
    );
  }

  private nodeValue(
    nodeKey: string,
    path: string[],
    port: number,
    depth: number,
  ): AbstractValue {
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    if (!safeParts(path))
      return this.unknown(nodeKey, "unsafe_field_reference");
    const cacheKey = JSON.stringify([nodeKey, path, port]);
    const cached = this.cache.get(cacheKey);
    if (cached) return structuredClone(cached);
    if (this.active.has(cacheKey))
      return this.unknown(nodeKey, "cyclic_dataflow");
    const node = this.context.nodeByKey.get(nodeKey);
    if (!node) return this.unknown(nodeKey, "node_missing");
    this.active.add(cacheKey);
    let result: AbstractValue;
    try {
      if (
        node.disabled ||
        node.raw.continueOnFail === true ||
        (node.raw.onError !== undefined &&
          node.raw.onError !== "stopWorkflow") ||
        node.raw.alwaysOutputData === true ||
        node.raw.executeOnce === true
      )
        result = this.unknown(nodeKey, "node_execution_semantics_unresolved");
      else if (
        node.type === prefix + "webhook" &&
        [2, 2.1, 2.2].includes(node.typeVersion)
      ) {
        result = this.source(node, path, "webhook", depth + 1);
        const multiple = node.parameters.multipleMethods;
        const methods =
          node.parameters.httpMethod ??
          (multiple === true ? ["GET", "POST"] : "GET");
        const known = [
          "GET",
          "POST",
          "PUT",
          "PATCH",
          "DELETE",
          "HEAD",
          "OPTIONS",
        ];
        const valid =
          multiple === true
            ? Array.isArray(methods) &&
              methods.length > 0 &&
              methods.every(
                (method) =>
                  typeof method === "string" && known.includes(method),
              ) &&
              new Set(methods).size === methods.length &&
              port < methods.length
            : (multiple === undefined || multiple === false) &&
              typeof methods === "string" &&
              known.includes(methods) &&
              port === 0;
        if (!valid || this.context.edges.some((edge) => edge.to === node.key))
          result = this.unknown(node.key, "webhook_output_unresolved", [
            result,
          ]);
        if (
          isObject(node.parameters.options) &&
          node.parameters.options.rawBody === true &&
          path[0] === "body" &&
          path.length > 1
        )
          result = this.unknown(node.key, "webhook_raw_body_shape_unresolved", [
            result,
          ]);
      } else if (
        node.type === prefix + "executeWorkflowTrigger" &&
        [1, 1.1].includes(node.typeVersion) &&
        port === 0
      ) {
        result = this.unknown(
          node.key,
          "subworkflow_argument_context_unresolved",
          [this.source(node, path, "subworkflow", depth + 1)],
        );
      } else if (
        node.type === prefix + "postgres" &&
        [2.5, 2.6, 2.8].includes(node.typeVersion)
      )
        result = this.source(node, path, "database", depth + 1);
      else if (
        node.type === prefix + "noOp" &&
        node.typeVersion === 1 &&
        port === 0
      )
        result = this.input(nodeKey, path, depth + 1);
      else if (
        node.type === prefix + "set" &&
        [1, 2, 3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion) &&
        port === 0
      )
        result = this.setValue(node, path, depth + 1);
      else if (
        (node.type === prefix + "if" &&
          [2, 2.1, 2.2].includes(node.typeVersion)) ||
        (node.type === prefix + "switch" &&
          [3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion))
      )
        result = this.branchValue(node, path, port, depth + 1);
      else if (
        node.type === prefix + "merge" &&
        [3, 3.1, 3.2].includes(node.typeVersion) &&
        port === 0
      )
        result = this.mergeValue(node, path, depth + 1);
      else if (
        node.type === prefix + "code" &&
        [1, 2].includes(node.typeVersion) &&
        port === 0
      )
        result = this.codeValue(node, path, depth + 1);
      else
        result = this.unknown(nodeKey, "node_transform_unsupported", [
          this.source(node, path, "node_output", depth + 1),
          this.input(nodeKey, [], depth + 1),
        ]);
      if (
        result.status === "unknown" &&
        !result.origins.length &&
        !result.diagnosticCodes.includes("flow_budget_exceeded")
      )
        result = this.unknown(
          nodeKey,
          result.diagnosticCodes[0] ?? "node_transform_unsupported",
          [result, this.input(nodeKey, [], depth + 1)],
        );
      result.paths = result.paths.map((entry) =>
        entry.at(-1) === nodeKey ? entry : [...entry, nodeKey].slice(-64),
      );
      this.cache.set(cacheKey, structuredClone(result));
      return result;
    } finally {
      this.active.delete(cacheKey);
    }
  }

  private setValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    const parameters = node.parameters;
    const options = isObject(parameters.options) ? parameters.options : {};
    if (
      (options.dotNotation !== undefined &&
        typeof options.dotNotation !== "boolean") ||
      (options.ignoreConversionErrors !== undefined &&
        typeof options.ignoreConversionErrors !== "boolean")
    )
      return this.unknown(node.key, "set_options_unresolved");
    let include: unknown = "all";
    if (node.typeVersion < 3) {
      if (
        parameters.keepOnlySet !== undefined &&
        typeof parameters.keepOnlySet !== "boolean"
      )
        return this.unknown(node.key, "set_include_unresolved");
      include = parameters.keepOnlySet === true ? "none" : "all";
    } else if (node.typeVersion < 3.3) include = parameters.include ?? "all";
    else {
      if (
        parameters.includeOtherFields !== undefined &&
        typeof parameters.includeOtherFields !== "boolean"
      )
        return this.unknown(node.key, "set_include_unresolved");
      include =
        parameters.includeOtherFields === true
          ? (parameters.include ?? "all")
          : "none";
    }
    if (!["all", "none", "selected", "except"].includes(String(include)))
      return this.unknown(node.key, "set_include_unresolved");
    const nameParts = (name: string): string[] | undefined => {
      if (name.startsWith("=")) return;
      if (options.dotNotation === false || !/[.\[\]]/.test(name))
        return safeParts([name]) ? [name] : undefined;
      try {
        const ast = parseExpressionAt("$json." + name, 0, {
          ecmaVersion: "latest",
        }) as unknown;
        if (!isObject(ast) || ast.end !== name.length + 6) return;
        return this.reference(ast)?.path;
      } catch {
        return;
      }
    };
    const inherited = (): AbstractValue => {
      if (include === "none")
        return path.length
          ? empty(node.key, undefined, true)
          : this.literal(node.key, {});
      if (include === "all") return this.input(node.key, path, depth + 1);
      const configured =
        include === "selected"
          ? parameters.includeFields
          : parameters.excludeFields;
      if (typeof configured !== "string" || configured.startsWith("="))
        return this.unknown(node.key, "set_include_fields_unresolved");
      const listed = configured
        .split(",")
        .map((name) => nameParts(name.trim()));
      if (listed.some((entry) => !entry))
        return this.unknown(node.key, "set_include_fields_unresolved");
      if (!path.length) {
        if (include === "except")
          return this.unknown(node.key, "set_exclusion_whole_object_partial", [
            this.input(node.key, path, depth + 1),
          ]);
        const fields = Object.fromEntries(
          listed.map((entry) => [
            pointer(entry!),
            this.input(node.key, entry!, depth + 1),
          ]),
        );
        return {
          ...join(Object.values(fields), node.key),
          fullObject: true,
          fields,
        };
      }
      const matched = listed.some(
        (entry) =>
          pointer(path) === pointer(entry!) ||
          pointer(path).startsWith(pointer(entry!) + "/"),
      );
      return (include === "selected" ? matched : !matched)
        ? this.input(node.key, path, depth + 1)
        : empty(node.key, undefined, true);
    };
    if (node.typeVersion >= 3 && parameters.mode === "raw") {
      let value: AbstractValue;
      if (typeof parameters.jsonOutput !== "string")
        return this.unknown(node.key, "set_raw_json_unavailable");
      if (parameters.jsonOutput.startsWith("="))
        value = this.resolveValue(
          node.key,
          parameters.jsonOutput,
          {},
          depth + 1,
        );
      else {
        try {
          value = this.literal(
            node.key,
            JSON.parse(parameters.jsonOutput),
            "",
            depth + 1,
          );
        } catch {
          return this.unknown(node.key, "set_raw_json_unavailable");
        }
      }
      const selected = this.project(value, path, node.key, depth + 1);
      return selected.presence === "absent"
        ? inherited()
        : path.length === 0 && include !== "none"
          ? join([inherited(), selected], node.key, "set_raw_merge_partial")
          : selected;
    }
    if (
      node.typeVersion >= 3 &&
      parameters.mode !== undefined &&
      parameters.mode !== "manual"
    )
      return this.unknown(node.key, "set_mode_unsupported");
    const assignments: { name: unknown; value: unknown; type: unknown }[] = [];
    if (node.typeVersion < 3) {
      const values = isObject(parameters.values) ? parameters.values : {};
      for (const type of ["boolean", "number", "string"]) {
        const entries = values[type] ?? [];
        if (!Array.isArray(entries))
          return this.unknown(node.key, "set_assignments_unresolved");
        for (const entry of entries)
          if (isObject(entry))
            assignments.push({ name: entry.name, value: entry.value, type });
          else return this.unknown(node.key, "set_assignments_unresolved");
      }
    } else if (node.typeVersion < 3.3) {
      const entries = isObject(parameters.fields)
        ? (parameters.fields.values ?? [])
        : [];
      if (!Array.isArray(entries))
        return this.unknown(node.key, "set_assignments_unresolved");
      for (const entry of entries)
        if (isObject(entry) && typeof entry.type === "string")
          assignments.push({
            name: entry.name,
            value: entry[entry.type],
            type: entry.type.replace(/Value$/, ""),
          });
        else return this.unknown(node.key, "set_assignments_unresolved");
    } else {
      const entries = isObject(parameters.assignments)
        ? (parameters.assignments.assignments ?? [])
        : [];
      if (!Array.isArray(entries))
        return this.unknown(node.key, "set_assignments_unresolved");
      for (const entry of entries)
        if (isObject(entry)) {
          if (entry.type !== "binary")
            assignments.push({
              name: entry.name,
              value: entry.value,
              type: entry.type,
            });
        } else return this.unknown(node.key, "set_assignments_unresolved");
    }
    if (assignments.length > valueFlowLimits.fields)
      return {
        ...this.unknown(node.key, "flow_field_limit", [inherited()]),
        presence: "unknown",
      };
    const mapped = new Map<string, AbstractValue>();
    for (const assignment of assignments) {
      const target =
        typeof assignment.name === "string"
          ? nameParts(assignment.name)
          : undefined;
      if (!target || !safeParts(target))
        return this.unknown(node.key, "set_dynamic_field_unresolved", [
          inherited(),
          this.input(node.key, [], depth + 1),
          ...mapped.values(),
        ]);
      if (
        ![
          "string",
          "number",
          "boolean",
          "object",
          "array",
          "dateTime",
        ].includes(String(assignment.type))
      )
        return this.unknown(node.key, "set_assignment_type_unresolved", [
          this.input(node.key, [], depth + 1),
          ...mapped.values(),
        ]);
      let value = this.resolveValue(
        node.key,
        assignment.value,
        { fieldName: target.at(-1) },
        depth + 1,
      );
      if (
        assignment.type === "number" &&
        node.typeVersion >= 3 &&
        options.ignoreConversionErrors !== true
      )
        value = this.transform(node.key, [value], "numeric_conversion");
      const inferred = this.classify(target.at(-1) ?? "");
      if (
        inferred.sensitivity !== "unknown" &&
        !value.sensitivityClasses.includes(inferred.sensitivity) &&
        !value.sensitivityBasis.some((basis) => basis.startsWith("trusted_"))
      )
        value = {
          ...value,
          sensitivity:
            severity(inferred.sensitivity) > severity(value.sensitivity)
              ? inferred.sensitivity
              : value.sensitivity,
          sensitivityClasses: unique([
            ...value.sensitivityClasses,
            inferred.sensitivity,
          ]),
          sensitivityBasis: unique([
            ...value.sensitivityBasis,
            ...inferred.basis,
          ]),
        };
      mapped.set(pointer(target), value);
    }
    if (!path.length) {
      const base = inherited();
      const fields = { ...(base.fields ?? {}), ...Object.fromEntries(mapped) };
      const values =
        include === "none" ? [...mapped.values()] : [base, ...mapped.values()];
      if (!values.length) return this.literal(node.key, {});
      return {
        ...join(values, node.key),
        presence: "present",
        fullObject: true,
        fields,
        fieldsComplete: include === "none",
        valueId: hash([
          "set",
          [...mapped].map(([name, value]) => [name, value.valueId]),
          base.valueId,
        ]),
      };
    }
    const target = pointer(path);
    for (const [name, value] of [...mapped].reverse()) {
      if (name === target || target.startsWith(name + "/"))
        return this.project(
          value,
          path.slice(parts(name).length),
          node.key,
          depth + 1,
        );
    }
    const nested = [...mapped].filter(([name]) =>
      name.startsWith(target + "/"),
    );
    if (nested.length)
      return {
        ...join(
          [
            ...(include === "none" ? [] : [inherited()]),
            ...nested.map(([, value]) => value),
          ],
          node.key,
        ),
        fullObject: true,
        fields: Object.fromEntries(
          nested.map(([name, value]) => [name.slice(target.length), value]),
        ),
      };
    return inherited();
  }

  private branchValue(
    node: NormalizedNode,
    path: string[],
    port: number,
    depth: number,
  ): AbstractValue {
    let filter: unknown;
    let passed = port === 0;
    const options = isObject(node.parameters.options)
      ? node.parameters.options
      : {};
    if (node.type === prefix + "if") {
      if (port > 1) return this.unknown(node.key, "branch_output_unavailable");
      filter = node.parameters.conditions;
    } else {
      if ((node.parameters.mode ?? "rules") !== "rules")
        return this.unknown(node.key, "switch_expression_mode_unresolved", [
          this.input(node.key, path, depth + 1),
        ]);
      const rules = isObject(node.parameters.rules)
        ? node.parameters.rules.values
        : undefined;
      if (!Array.isArray(rules))
        return this.unknown(node.key, "switch_rules_unavailable");
      if (port === rules.length && options.fallbackOutput === "extra")
        return this.input(node.key, path, depth + 1);
      if (port >= rules.length)
        return this.unknown(node.key, "branch_output_unavailable");
      if (
        options.fallbackOutput === port ||
        options.fallbackOutput === String(port)
      )
        return this.unknown(node.key, "switch_fallback_reuses_output", [
          this.input(node.key, path, depth + 1),
        ]);
      filter = isObject(rules[port]) ? rules[port].conditions : undefined;
      passed = true;
    }
    const result = this.input(node.key, path, depth + 1);
    const loose =
      node.type === prefix + "if"
        ? node.parameters.looseTypeValidation
        : options.looseTypeValidation;
    if (loose !== undefined && loose !== false)
      return this.unknown(node.key, "branch_type_validation_unresolved", [
        result,
      ]);
    if (
      !isObject(filter) ||
      !Array.isArray(filter.conditions) ||
      !isObject(filter.options) ||
      filter.options.typeValidation !== "strict" ||
      filter.options.version !== 2
    )
      return this.unknown(node.key, "branch_guard_semantics_unresolved", [
        result,
      ]);
    const conditions = filter.conditions;
    if (
      conditions.length > 1 &&
      !(
        (passed && filter.combinator === "and") ||
        (!passed && filter.combinator === "or")
      )
    )
      return this.unknown(node.key, "branch_guard_disjunction", [result]);
    for (const condition of conditions) {
      if (!isObject(condition) || !isObject(condition.operator)) continue;
      const left = this.resolveValue(
        node.key,
        condition.leftValue,
        {},
        depth + 1,
      );
      if (
        left.status !== "resolved" ||
        left.presence === "absent" ||
        !left.origins.length ||
        left.valueId !== result.valueId
      )
        continue;
      const type = condition.operator.type,
        operation = condition.operator.operation;
      if (typeof operation !== "string") continue;
      if (
        type === "number" &&
        ["equals", "notEquals", "gt", "gte", "lt", "lte"].includes(operation) &&
        typeof condition.rightValue === "number" &&
        Number.isFinite(condition.rightValue)
      )
        result.guards.push({
          nodeKey: node.key,
          outputs: [port],
          kind: "number_type",
          valueId: left.valueId,
          operator: "strict_number",
          origins: left.origins,
        });
      const literal = condition.rightValue;
      const literalAllowed =
        (type === "string" &&
          typeof literal === "string" &&
          !literal.startsWith("=")) ||
        (type === "number" &&
          typeof literal === "number" &&
          Number.isFinite(literal)) ||
        (type === "boolean" && typeof literal === "boolean");
      if (
        literalAllowed &&
        ["number", "string", "boolean"].includes(String(type)) &&
        ["equals", "notEquals"].includes(operation) &&
        (type !== "string" || filter.options.caseSensitive === true)
      ) {
        const equal = (operation === "equals") === passed;
        result.guards.push({
          nodeKey: node.key,
          outputs: [port],
          kind: equal ? "equals_literal" : "not_equals_literal",
          valueId: left.valueId,
          operator: operation,
          literal,
          origins: left.origins,
        });
      }
    }
    return result;
  }

  private mergeValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    const mode = node.parameters.mode ?? "append";
    if (mode === "append") return this.input(node.key, path, depth + 1);
    if (mode === "chooseBranch") {
      if ((node.parameters.chooseBranchMode ?? "waitForAll") !== "waitForAll")
        return this.unknown(node.key, "merge_branch_mode_unsupported");
      if (node.parameters.output === "empty")
        return path.length
          ? empty(node.key, undefined, true)
          : this.literal(node.key, {});
      if ((node.parameters.output ?? "specifiedInput") !== "specifiedInput")
        return this.unknown(node.key, "merge_output_unresolved");
      const selected = node.parameters.useDataOfInput ?? 1;
      if (
        typeof selected !== "number" ||
        !Number.isInteger(selected) ||
        selected < 1 ||
        selected > 64
      )
        return this.unknown(node.key, "merge_input_selection_unresolved");
      return this.input(node.key, path, depth + 1, selected - 1);
    }
    if (
      mode === "combine" &&
      node.parameters.combineBy === "combineByPosition"
    ) {
      const options = isObject(node.parameters.options)
        ? node.parameters.options
        : {};
      const clash =
        isObject(options.clashHandling) &&
        isObject(options.clashHandling.values)
          ? options.clashHandling.values
          : {};
      const value = this.input(
        node.key,
        clash.resolveClash === "addSuffix" ? [] : path,
        depth + 1,
      );
      const result = this.unknown(
        node.key,
        clash.resolveClash === "addSuffix"
          ? "merge_suffix_fields_unresolved"
          : "merge_item_alignment_unverified",
        [value],
      );
      result.guards = [];
      return result;
    }
    return this.unknown(node.key, "merge_mode_unsupported", [
      this.input(node.key, [], depth + 1),
    ]);
  }

  private project(
    value: AbstractValue,
    path: string[],
    nodeKey: string,
    depth: number,
  ): AbstractValue {
    if (!path.length) return value;
    const unresolved = (): AbstractValue => ({
      ...this.unknown(nodeKey, "field_projection_partial", [value]),
      presence: "unknown",
      guards: [],
      valueId: hash(["unresolved_projection", value.valueId, path]),
    });
    if (value.fields) {
      // A bounded prefix does not establish absence, and a later expression
      // property may overwrite an earlier key. Preserve the aggregate's known
      // classifications and limit diagnostics rather than inventing a value.
      if (
        value.fieldsComplete === false &&
        value.diagnosticCodes.includes("flow_field_limit")
      )
        return unresolved();
      const exact = value.fields[pointer(path)];
      if (exact) return exact;
      for (let length = path.length - 1; length > 0; length--) {
        const parent = value.fields[pointer(path.slice(0, length))];
        if (parent)
          return this.project(parent, path.slice(length), nodeKey, depth + 1);
      }
      const nested = Object.entries(value.fields).filter(([name]) =>
        name.startsWith(pointer(path) + "/"),
      );
      if (nested.length)
        return {
          ...join(
            nested.map(([, child]) => child),
            nodeKey,
          ),
          fullObject: true,
          fields: Object.fromEntries(
            nested.map(([name, child]) => [
              name.slice(pointer(path).length),
              child,
            ]),
          ),
        };
      if (value.fieldsComplete === true) return empty(nodeKey, undefined, true);
    }
    if (value.status !== "resolved") return unresolved();
    if (value.transforms.length)
      return this.unknown(nodeKey, "transformed_field_projection_unresolved", [
        value,
      ]);
    const projected = value.origins.map((origin) => {
      const source = this.context.nodeByKey.get(origin.nodeKey);
      return source
        ? this.source(
            source,
            [...parts(origin.fieldPath), ...path],
            origin.kind,
            depth + 1,
          )
        : this.unknown(nodeKey, "node_missing");
    });
    return join(
      projected,
      nodeKey,
      value.status !== "resolved" ? "field_projection_partial" : undefined,
    );
  }

  private codeValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    if (
      (node.typeVersion >= 2 &&
        (node.parameters.language ?? "javaScript") !== "javaScript") ||
      typeof node.parameters.jsCode !== "string"
    )
      return this.unknown(node.key, "code_language_unresolved");
    if ((node.parameters.mode ?? "runOnceForAllItems") !== "runOnceForAllItems")
      return this.unknown(node.key, "code_item_mode_unresolved");
    try {
      const ast = parse(node.parameters.jsCode, {
        ecmaVersion: "latest",
        allowReturnOutsideFunction: true,
      }) as unknown;
      if (
        !isObject(ast) ||
        !Array.isArray(ast.body) ||
        ast.body.length !== 1 ||
        !isObject(ast.body[0]) ||
        ast.body[0].type !== "ReturnStatement" ||
        !isObject(ast.body[0].argument)
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      const returned = ast.body[0].argument;
      if (
        returned.type === "CallExpression" &&
        isObject(returned.callee) &&
        returned.callee.type === "MemberExpression" &&
        isObject(returned.callee.object) &&
        returned.callee.object.name === "$input" &&
        isObject(returned.callee.property) &&
        returned.callee.property.name === "all" &&
        Array.isArray(returned.arguments) &&
        returned.arguments.length === 0
      )
        return this.input(node.key, path, depth + 1);
      if (
        returned.type !== "ArrayExpression" ||
        !Array.isArray(returned.elements) ||
        returned.elements.length !== 1 ||
        !isObject(returned.elements[0])
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      const object = returned.elements[0];
      if (
        object.type !== "ObjectExpression" ||
        !Array.isArray(object.properties) ||
        object.properties.length !== 1 ||
        !isObject(object.properties[0])
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      const property = object.properties[0];
      if (
        property.type !== "Property" ||
        property.computed === true ||
        !isObject(property.key) ||
        (property.key.name ?? property.key.value) !== "json" ||
        !isObject(property.value)
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      return this.project(
        this.astValue(node.key, property.value, depth + 1),
        path,
        node.key,
        depth + 1,
      );
    } catch {
      return this.unknown(node.key, "code_parse_unavailable");
    }
  }
}
