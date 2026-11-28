import { createHash } from "node:crypto";
import { parse, parseExpressionAt } from "acorn";
import {
  analyzeBoundedCode,
  observeInvalidCode,
  type BoundedCodeHost,
} from "./bounded-code.js";
import { aiPromptInputs } from "../rules/ai-flow.js";
import {
  matchCatalogServiceSource,
  matchLocalCatalogEffect,
} from "./node-catalog.js";
import { preserveValueShape } from "./value-shape.js";
import type { NormalizedNode } from "./n8n.js";
import { isObject, stringSelector } from "./static-context.js";
import type { Context } from "./static-context.js";

// Internal analysis structures. Field names and guard literals are untrusted
// input data and MUST NOT be copied into public result evidence.
export type Sensitivity =
  "secret_candidate" | "pii_candidate" | "public_literal" | "unknown";
export type Origin = {
  nodeKey: string;
  fieldPath: string;
  // Candidate subtree retained by collection selection/reindexing. Never an
  // assertion of a descendant's exact output position or presence.
  includesDescendants?: true;
  // Known member selections after unknown collection indices. null means a
  // possible array index, never a wildcard property name or a proven index.
  descendantPath?: (string | null)[];
  // A transform retains its input dependency selector, but its output shape
  // cannot be used to narrow that selector any further.
  projectionUnknown?: true;
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
    | "serialization"
    | "string_processing"
    | "json_parsing"
    | "collection_mapping";
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
  /** Internal scalar literal evidence; never copy to public reports. */
  constant?: string | number | boolean | null;
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
  /** Possible item of a bounded collection; never a stored item at index zero. */
  representativeElement?: AbstractValue;
  /** A selection with uncertain index alignment or optional field presence. */
  representativeSelection?: true;
  /** Alternative values, projected separately before their results are joined. */
  projectionAlternatives?: AbstractValue[];
  /** Control dependencies are retained without treating them as array items. */
  projectionDependencies?: AbstractValue[];
  /** Serialized contents were fully mapped; this does not preserve JSON shape. */
  contentComplete?: true;
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
  /** Internal Code AST text: parsed as one expression, never as an n8n template. */
  resolveExpression(nodeKey: string, expression: string): AbstractValue;
  output(nodeKey: string, fieldPath: string, port?: number): AbstractValue;
  readonly diagnostics: FlowDiagnostic[];
}

/** Wait interval success preserves input items; webhook/form resume does not. */
export function isStaticIntervalWait(node: NormalizedNode): boolean {
  return (
    node.type === "n8n-nodes-base.wait" &&
    [1, 1.1].includes(node.typeVersion) &&
    (node.parameters.resume === undefined ||
      node.parameters.resume === "timeInterval") &&
    (node.parameters.amount === undefined ||
      (typeof node.parameters.amount === "number" &&
        Number.isFinite(node.parameters.amount) &&
        node.parameters.amount >= 0)) &&
    (node.parameters.unit === undefined ||
      (typeof node.parameters.unit === "string" &&
        ["seconds", "minutes", "hours", "days"].includes(node.parameters.unit)))
  );
}

/** Fixed Limit slices the item list without changing any emitted item's JSON. */
export function isStaticItemLimit(node: NormalizedNode): boolean {
  const p = node.parameters;
  const count = p.maxItems === undefined ? 1 : p.maxItems;
  return (
    node.type === "n8n-nodes-base.limit" &&
    node.typeVersion === 1 &&
    Object.keys(p).every((key) =>
      ["maxItems", "keep", "options"].includes(key),
    ) &&
    (p.options === undefined ||
      (isObject(p.options) && Object.keys(p.options).length === 0)) &&
    typeof count === "number" &&
    Number.isSafeInteger(count) &&
    count >= 1 &&
    count <= 1000000 &&
    (p.keep === undefined || p.keep === "firstItems" || p.keep === "lastItems")
  );
}

export const valueFlowLimits = {
  recursion: 64,
  requests: 4096,
  astNodes: 2048,
  expressionCharacters: 65536,
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

/** Match retained candidate subtrees without assigning an exact array index. */
export function originIncludesField(origin: Origin, field: string): boolean {
  if (field === origin.fieldPath) return true;
  if (!origin.includesDescendants || !field.startsWith(origin.fieldPath + "/"))
    return false;
  if (!origin.descendantPath) return true;
  const relative = parts(field).slice(parts(origin.fieldPath).length);
  // A classification of an ancestor of the selected field still applies to
  // that field; an unrelated sibling after a known member selection does not.
  return origin.descendantPath.every((part, index) =>
    index >= relative.length
      ? true
      : part === null
        ? /^(?:0|[1-9]\d*)$/.test(relative[index]!)
        : relative[index] === part,
  );
}
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

function unknownProjection(value: AbstractValue): AbstractValue {
  return {
    ...value,
    origins: value.origins.map((origin) =>
      origin.kind === "literal"
        ? origin
        : { ...origin, projectionUnknown: true },
    ),
    constant: undefined,
    fields: undefined,
    fieldsComplete: false,
    representativeElement: undefined,
    representativeSelection: undefined,
    projectionAlternatives: undefined,
    projectionDependencies: undefined,
    contentComplete: undefined,
    guards: [],
  };
}

function projectionShapeFits(values: AbstractValue[]): boolean {
  const pending = values.map((value) => ({ value, depth: 0 }));
  let count = 0;
  while (pending.length) {
    const { value, depth } = pending.pop()!;
    if (++count > 512 || depth > 32) return false;
    for (const child of [
      ...Object.values(value.fields ?? {}),
      ...(value.representativeElement ? [value.representativeElement] : []),
      ...(value.projectionAlternatives ?? []),
      ...(value.projectionDependencies ?? []),
    ])
      pending.push({ value: child, depth: depth + 1 });
  }
  return true;
}

export function isExternalValue(value: AbstractValue | undefined): boolean {
  return (
    !!value &&
    (value.trust === "external" ||
      value.origins.some(
        (origin) => origin.kind === "webhook" || origin.kind === "subworkflow",
      ))
  );
}

function join(
  values: AbstractValue[],
  nodeKey: string,
  code?: string,
  alternatives = false,
): AbstractValue {
  if (!values.length) return empty(nodeKey, code ?? "input_not_connected");
  if (values.length === 1 && !code && alternatives)
    return structuredClone(values[0]!);
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
  const result: AbstractValue = {
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
    trust: values.some((value) => value.trust === "external")
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
    // Joining mapped alternatives does not preserve a field map. Their
    // origins describe the mapped values, not an object on which new path
    // components can be appended. Keep that structural uncertainty explicit.
    fieldsComplete: values.some(
      (value) => value.fields !== undefined || value.fieldsComplete === false,
    )
      ? false
      : undefined,
    diagnosticCodes: diagnostics,
    valueId: ids.length === 1 ? ids[0]! : hash(ids.sort()),
  };
  // Dependency aggregation (object fields, serialization, call arguments) is
  // different from choosing one possible value. Only value alternatives carry
  // structure into a subsequent projection; never promote a child array into
  // its containing object or a serialized string.
  if (
    alternatives &&
    values.some(
      (value) =>
        value.fields ||
        value.representativeElement ||
        value.projectionAlternatives ||
        value.origins.some(
          (origin) => origin.descendantPath && !origin.projectionUnknown,
        ),
    )
  ) {
    if (
      values.length <= valueFlowLimits.alternatives &&
      projectionShapeFits(values)
    ) {
      result.projectionAlternatives = values;
      result.fieldsComplete = false;
      result.guards = [];
    } else {
      const bounded = unknownProjection(result);
      bounded.status = bounded.origins.length ? "partial" : "unknown";
      bounded.diagnosticCodes = unique([
        ...bounded.diagnosticCodes,
        "code_value_shape_limit",
      ]);
      bounded.sensitivityClasses = unique<Sensitivity>([
        ...bounded.sensitivityClasses,
        "unknown",
      ]).sort((a, b) => severity(b) - severity(a));
      bounded.sensitivity = bounded.sensitivityClasses[0]!;
      return bounded;
    }
  }
  return result;
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
  private readonly codeOutputs = new Map<string, AbstractValue>();
  private readonly resolvedInputs = new Map<string, AbstractValue>();
  private requests = 0;
  private constantCharacters = 0;
  constructor(
    private readonly context: Context,
    private readonly options: ValueFlowOptions,
  ) {}

  resolve(
    nodeKey: string,
    value: unknown,
    options: ResolveOptions = {},
  ): AbstractValue {
    const key = hash([nodeKey, typeof value, value, options]);
    const cached = this.resolvedInputs.get(key);
    if (cached) return structuredClone(cached);
    const result = this.resolveValue(nodeKey, value, options, 0);
    if (this.resolvedInputs.size < valueFlowLimits.requests)
      this.resolvedInputs.set(key, structuredClone(result));
    return result;
  }

  output(nodeKey: string, fieldPath: string, port = 0): AbstractValue {
    return this.nodeValue(nodeKey, parts(fieldPath), port, 0);
  }

  resolveExpression(nodeKey: string, expression: string): AbstractValue {
    if (expression.length > valueFlowLimits.expressionCharacters)
      return this.unknown(nodeKey, "expression_size_limit");
    const key = hash(["code_expression", nodeKey, expression]);
    const cached = this.resolvedInputs.get(key);
    if (cached) return structuredClone(cached);
    if (!this.bounded(nodeKey, 0))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    const result = this.expression(nodeKey, expression, 1);
    if (this.resolvedInputs.size < valueFlowLimits.requests)
      this.resolvedInputs.set(key, structuredClone(result));
    return result;
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
    if (!values.length) return empty(nodeKey, code);
    const result = join(values, nodeKey, code);
    return [
      "field_projection_partial",
      "code_collection_shape_unverified",
      "code_collection_cardinality_unverified",
      "code_collection_index_unverified",
      "code_branch_field_optional",
      "code_array_spread_shape_unverified",
      "collection_cardinality_unverified",
    ].includes(code)
      ? result
      : unknownProjection(result);
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

  private reserveConstant(nodeKey: string, characters: number): boolean {
    if (
      characters > valueFlowLimits.expressionCharacters ||
      this.constantCharacters + characters >
        valueFlowLimits.expressionCharacters
    ) {
      this.note(nodeKey, "constant_inference_size_limit");
      return false;
    }
    this.constantCharacters += characters;
    return true;
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
        constant: undefined,
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
    const constantFits =
      typeof value !== "string" || this.reserveConstant(nodeKey, value.length);
    const result: AbstractValue = {
      status: "resolved",
      ...((value === null ||
        ["string", "number", "boolean"].includes(typeof value)) &&
      constantFits
        ? { constant: value as string | number | boolean | null }
        : {}),
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
    return constantFits
      ? result
      : this.unknown(nodeKey, "constant_inference_size_limit", [result]);
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
    const credential = kind === "credential";
    const result: AbstractValue = {
      status: "resolved",
      presence: "unknown",
      origins: [{ nodeKey: node.key, fieldPath, kind }],
      sensitivity: credential
        ? "secret_candidate"
        : (exact?.sensitivity ?? inferred.sensitivity),
      sensitivityClasses: credential
        ? ["secret_candidate"]
        : exact
          ? unique(exactMatches.map((item) => item.sensitivity))
          : [inferred.sensitivity],
      sensitivityBasis: credential
        ? ["credential_reference"]
        : exact
          ? ["trusted_" + exact.provenance + "_annotation"]
          : inferred.basis,
      trust: credential
        ? "internal"
        : kind === "webhook" || kind === "subworkflow"
          ? "external"
          : "unknown",
      transforms: [],
      guards: [],
      paths: [[node.key]],
      fullObject: path.length === 0,
      diagnosticCodes: [],
      valueId: hash([kind, node.key, fieldPath]),
    };
    if (annotations.length && depth < valueFlowLimits.recursion) {
      // Visit each child path once, rather than re-expanding every descendant
      // both directly and through each of its ancestors.
      const children = unique(
        annotations
          .map((item) => parts(item.fieldPath))
          .filter((entry) => pointer(entry).startsWith(fieldPath + "/"))
          .map((entry) => entry[path.length]!),
      );
      result.fields = Object.fromEntries(
        children
          .slice(0, valueFlowLimits.fields)
          .map((part) => [
            pointer([part]),
            this.source(node, [...path, part], kind, depth + 1),
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
      return /\{\{|\}\}/.test(text)
        ? this.unknown(nodeKey, "expression_syntax_unsupported")
        : this.literal(nodeKey, text, options.fieldName, depth + 1);
    const values = matches.map((match) =>
      this.expression(nodeKey, match[1]!, depth + 1),
    );
    const remainder = text.replace(/\{\{([\s\S]*?)\}\}/g, "");
    if (remainder.includes("{{") || remainder.includes("}}"))
      return this.unknown(nodeKey, "expression_syntax_unsupported", values);
    if (matches.length === 1 && text === matches[0]![0]) return values[0]!;
    const ordered: AbstractValue[] = [];
    let offset = 0;
    for (const [index, match] of matches.entries()) {
      ordered.push(
        this.literal(nodeKey, text.slice(offset, match.index)),
        values[index]!,
      );
      offset = match.index + match[0].length;
    }
    ordered.push(this.literal(nodeKey, text.slice(offset)));
    return this.transform(nodeKey, ordered, "concatenation");
  }

  private expression(
    nodeKey: string,
    text: string,
    depth: number,
  ): AbstractValue {
    const hasCrossNodeToken = /\$\s*\(|\$(?:node|items)\b/.test(text);
    try {
      const ast = parseExpressionAt(text, 0, {
        ecmaVersion: "latest",
        preserveParens: true,
      }) as unknown;
      if (
        !isObject(ast) ||
        typeof ast.end !== "number" ||
        text.slice(ast.end).trim()
      )
        return this.unknown(
          nodeKey,
          "expression_syntax_unsupported",
          hasCrossNodeToken
            ? [this.unknown(nodeKey, "direct_reference_unconnected")]
            : [],
        );
      const stack: unknown[] = [ast];
      let count = 0;
      while (stack.length) {
        const value = stack.pop();
        if (!isObject(value)) continue;
        if (++count > valueFlowLimits.astNodes)
          return this.unknown(
            nodeKey,
            "expression_ast_limit",
            hasCrossNodeToken
              ? [this.unknown(nodeKey, "direct_reference_unconnected")]
              : [],
          );
        for (const child of Object.values(value)) {
          if (Array.isArray(child)) stack.push(...child);
          else if (isObject(child)) stack.push(child);
        }
      }
      return this.astValue(nodeKey, ast, depth + 1);
    } catch {
      return this.unknown(
        nodeKey,
        "expression_parse_unavailable",
        hasCrossNodeToken
          ? [this.unknown(nodeKey, "direct_reference_unconnected")]
          : [],
      );
    }
  }

  private transform(
    nodeKey: string,
    values: AbstractValue[],
    kind: TransformEvidence["kind"],
  ): AbstractValue {
    const merged = unknownProjection(join(values, nodeKey));
    let constant: string | undefined;
    let constantOverflow = false;
    if (
      kind === "concatenation" &&
      values.every((value) => typeof value.constant === "string")
    ) {
      const length = values.reduce(
        (total, value) => total + (value.constant as string).length,
        0,
      );
      if (this.reserveConstant(nodeKey, length))
        constant = values.map((value) => value.constant).join("");
      else constantOverflow = true;
    }
    const result: AbstractValue = {
      ...merged,
      constant,
      fullObject: kind === "serialization" && merged.fullObject,
      contentComplete:
        kind === "serialization" &&
        values.every(
          (value) =>
            value.status === "resolved" &&
            value.fieldsComplete === true &&
            value.fields !== undefined,
        )
          ? true
          : undefined,
      guards: [],
      transforms: [
        ...merged.transforms,
        { nodeKey, kind, inputValueIds: values.map((value) => value.valueId) },
      ].slice(0, valueFlowLimits.alternatives),
      valueId: hash([kind, values.map((value) => value.valueId)]),
    };
    return constantOverflow
      ? this.unknown(nodeKey, "constant_inference_size_limit", [result])
      : result;
  }

  private astValue(
    nodeKey: string,
    ast: Record<string, unknown>,
    depth: number,
  ): AbstractValue {
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
    if (ast.type === "BoundedValue" && isObject(ast.value))
      return structuredClone(ast.value) as unknown as AbstractValue;
    if (ast.type === "ParenthesizedExpression" && isObject(ast.expression))
      return this.astValue(nodeKey, ast.expression, depth + 1);
    if (ast.type === "Literal") {
      if (isObject(ast.regex)) {
        const rawPattern =
          typeof ast.raw === "string"
            ? ast.raw
            : String(ast.regex.pattern ?? "");
        const unescapedDots = rawPattern.replace(/\\\./g, ".");
        const base = join(
          [
            this.literal(nodeKey, rawPattern, "", depth + 1),
            ...(unescapedDots !== rawPattern
              ? [this.literal(nodeKey, unescapedDots, "", depth + 1)]
              : []),
          ],
          nodeKey,
        );
        return {
          ...base,
          constant: undefined,
          fieldsComplete: false,
          valueId: hash(["regex_literal", nodeKey, rawPattern]),
        };
      }
      const value = this.literal(nodeKey, ast.value, "", depth + 1);
      if (ast.boundedClock === true) {
        delete value.constant;
        value.sensitivityBasis = ["runtime_clock"];
        const arguments_ = Array.isArray(ast.boundedClockArguments)
          ? ast.boundedClockArguments
              .filter(isObject)
              .map((argument) => this.astValue(nodeKey, argument, depth + 1))
          : [];
        // Luxon format strings may emit quoted literal text. Formatting a
        // literal must not erase its existing secret/PII candidate classes.
        return {
          ...join([value, ...arguments_], nodeKey),
          fullObject: false,
          fieldsComplete: false,
        };
      }
      return value;
    }
    if (ast.type === "ChainExpression" && isObject(ast.expression)) {
      const value = this.astValue(nodeKey, ast.expression, depth + 1);
      // Optional access may produce undefined. It never establishes a
      // present value or inherits a guard for the non-optional expression.
      return {
        ...value,
        presence: value.presence === "absent" ? "absent" : "unknown",
        guards: [],
        valueId: hash(["optional_access", value.valueId]),
      };
    }
    if (
      ast.type === "LogicalExpression" &&
      ["||", "??", "&&"].includes(String(ast.operator)) &&
      isObject(ast.left) &&
      isObject(ast.right)
    ) {
      // Both alternatives are possible; do not execute truthiness/nullish
      // checks or turn a fallback into sanitization of the original value.
      const values = [
        this.astValue(nodeKey, ast.left, depth + 1),
        this.astValue(nodeKey, ast.right, depth + 1),
      ];
      return {
        ...join(values, nodeKey, undefined, true),
        // A logical selection is not a direct source reference, even when
        // both alternatives are scalar or their object shape is unknown.
        fieldsComplete: false,
        guards: [],
        valueId: hash([
          "logical_selection",
          ast.operator,
          values.map((v) => v.valueId),
        ]),
      };
    }
    if (
      ast.type === "UnaryExpression" &&
      ["!", "+", "-", "typeof", "void"].includes(String(ast.operator)) &&
      isObject(ast.argument)
    ) {
      const argument = this.astValue(nodeKey, ast.argument, depth + 1);
      if (
        (ast.operator === "-" || ast.operator === "+") &&
        argument.status === "resolved" &&
        typeof argument.constant === "number" &&
        Number.isFinite(argument.constant)
      ) {
        return {
          ...argument,
          constant:
            ast.operator === "-" ? -argument.constant : +argument.constant,
          valueId: hash([
            "unary_numeric_literal",
            ast.operator,
            argument.valueId,
          ]),
        };
      }
      return this.transform(
        nodeKey,
        [argument],
        ast.operator === "+" || ast.operator === "-"
          ? "numeric_conversion"
          : "string_processing",
      );
    }
    if (
      ast.type === "Identifier" &&
      (ast.name === "$now" || ast.name === "$today")
    ) {
      return {
        ...this.literal(nodeKey, "", "", depth + 1),
        constant: undefined,
        fieldsComplete: false,
        sensitivityBasis: ["runtime_clock"],
        valueId: hash(["runtime_clock", nodeKey, ast.name]),
      };
    }
    if (
      ast.type === "NewExpression" &&
      isObject(ast.callee) &&
      ast.callee.type === "Identifier" &&
      ast.callee.name === "Date" &&
      Array.isArray(ast.arguments) &&
      ast.arguments.length <= 7 &&
      ast.arguments.every(
        (arg) => isObject(arg) && arg.type !== "SpreadElement",
      )
    ) {
      const clockBase: AbstractValue = {
        ...this.literal(nodeKey, "", "", depth + 1),
        constant: undefined,
        fieldsComplete: false,
        sensitivityBasis: ["runtime_clock"],
      };
      const args = ast.arguments.map((arg) =>
        this.astValue(nodeKey, arg as Record<string, unknown>, depth + 1),
      );
      const transformed = this.transform(
        nodeKey,
        [clockBase, ...args],
        "string_processing",
      );
      return {
        ...transformed,
        constant: undefined,
        fullObject: false,
        fieldsComplete: false,
        guards: [],
        valueId: hash(["new_date", nodeKey, args.map((arg) => arg.valueId)]),
      };
    }
    if (
      ast.type === "Identifier" &&
      (ast.name === "$itemIndex" || ast.name === "$runIndex")
    ) {
      return {
        ...this.literal(nodeKey, 0, "", depth + 1),
        constant: undefined,
        fieldsComplete: false,
        sensitivityBasis: ["runtime_metadata"],
        valueId: hash(["runtime_metadata", nodeKey, ast.name]),
      };
    }
    if (
      ast.type === "MemberExpression" &&
      ast.computed !== true &&
      isObject(ast.object) &&
      ast.object.type === "Identifier" &&
      isObject(ast.property) &&
      ast.property.type === "Identifier" &&
      ((ast.object.name === "$workflow" &&
        ["id", "name", "active"].includes(String(ast.property.name))) ||
        (ast.object.name === "$execution" &&
          ["id", "mode"].includes(String(ast.property.name))))
    ) {
      return {
        ...this.literal(nodeKey, "", "", depth + 1),
        constant: undefined,
        fieldsComplete: false,
        sensitivityBasis: ["runtime_metadata"],
        valueId: hash([
          "runtime_metadata",
          nodeKey,
          ast.object.name,
          ast.property.name,
        ]),
      };
    }
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
      ast.type === "MemberExpression" &&
      isObject(ast.object) &&
      ast.object.type === "Identifier" &&
      ast.object.name === "$node" &&
      isObject(ast.property)
    ) {
      const targetName =
        ast.computed === true
          ? ast.property.type === "Literal"
            ? ast.property.value
            : undefined
          : ast.property.name;
      if (typeof targetName !== "string") {
        const dynamicKey = this.astValue(nodeKey, ast.property, depth + 1);
        return this.unknown(nodeKey, "direct_reference_unconnected", [
          dynamicKey,
        ]);
      }
      const source = this.context.nodeByName.get(targetName);
      if (!source || !this.connected(source.key, nodeKey))
        return this.unknown(nodeKey, "direct_reference_unconnected");
      return this.unknown(nodeKey, "expression_semantics_unsupported", [
        this.nodeValue(source.key, [], 0, depth + 1),
      ]);
    }
    if (
      ast.type === "CallExpression" &&
      isObject(ast.callee) &&
      ast.callee.type === "Identifier" &&
      (ast.callee.name === "$" || ast.callee.name === "$items") &&
      Array.isArray(ast.arguments)
    ) {
      if (ast.arguments.length === 1 && isObject(ast.arguments[0])) {
        const argVal = this.astValue(nodeKey, ast.arguments[0], depth + 1);
        if (
          argVal.status === "resolved" &&
          typeof argVal.constant === "string"
        ) {
          const source = this.context.nodeByName.get(argVal.constant);
          if (!source || !this.connected(source.key, nodeKey))
            return this.unknown(nodeKey, "direct_reference_unconnected");
          return this.unknown(nodeKey, "expression_semantics_unsupported", [
            this.nodeValue(source.key, [], 0, depth + 1),
          ]);
        }
        return this.unknown(nodeKey, "direct_reference_unconnected", [argVal]);
      }
      return this.unknown(nodeKey, "direct_reference_unconnected");
    }
    if (
      ast.type === "MemberExpression" &&
      isObject(ast.object) &&
      isObject(ast.property)
    ) {
      const key =
        ast.computed === true
          ? ast.property.type === "Literal"
            ? ast.property.value
            : undefined
          : ast.property.name;
      if (
        (typeof key === "string" || typeof key === "number") &&
        safeParts([String(key)])
      )
        return this.project(
          this.astValue(nodeKey, ast.object, depth + 1),
          [String(key)],
          nodeKey,
          depth + 1,
        );
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
        name === "encodeURIComponent" ||
        name === "encodeURI" ||
        name === "decodeURIComponent" ||
        name === "decodeURI" ||
        name === "String" ||
        name === "Boolean"
      )
        return this.transform(
          nodeKey,
          [this.astValue(nodeKey, ast.arguments[0], depth + 1)],
          name === "String" ||
            name === "Boolean" ||
            name === "decodeURIComponent" ||
            name === "decodeURI"
            ? "string_processing"
            : name === "encodeURIComponent" || name === "encodeURI"
              ? "url_component_encoding"
              : "numeric_conversion",
        );
      if (
        ast.callee.type === "MemberExpression" &&
        ast.callee.computed !== true &&
        isObject(ast.callee.object) &&
        ast.callee.object.name === "Array" &&
        isObject(ast.callee.property) &&
        ast.callee.property.name === "isArray"
      )
        return this.transform(
          nodeKey,
          [this.astValue(nodeKey, ast.arguments[0], depth + 1)],
          "string_processing",
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
      if (
        ast.callee.type === "MemberExpression" &&
        isObject(ast.callee.object) &&
        ast.callee.object.name === "JSON" &&
        isObject(ast.callee.property) &&
        ast.callee.property.name === "parse"
      ) {
        const input = this.astValue(nodeKey, ast.arguments[0], depth + 1);
        if (
          typeof input.constant === "string" &&
          input.constant.length <= valueFlowLimits.expressionCharacters
        ) {
          try {
            const decoded = this.literal(
              nodeKey,
              JSON.parse(input.constant),
              "",
              depth + 1,
            );
            const value = join([input, decoded], nodeKey);
            return {
              ...value,
              constant: decoded.constant,
              fullObject: decoded.fullObject,
              fieldsComplete: false,
              transforms: [
                ...value.transforms,
                {
                  nodeKey,
                  kind: "json_parsing",
                  inputValueIds: [input.valueId],
                },
              ],
            };
          } catch {
            return this.unknown(nodeKey, "json_parse_content_unresolved", [
              input,
            ]);
          }
        }
        return {
          ...this.unknown(nodeKey, "json_parse_shape_unverified", [input]),
          fullObject: true,
          fieldsComplete: false,
          guards: [],
        };
      }
    }
    if (
      ast.type === "CallExpression" &&
      isObject(ast.callee) &&
      ast.callee.type === "MemberExpression" &&
      isObject(ast.callee.object) &&
      isObject(ast.callee.property) &&
      ast.callee.computed !== true &&
      Array.isArray(ast.arguments) &&
      ast.arguments.every(isObject)
    ) {
      const method = ast.callee.property.name;
      if (
        isObject(ast.callee.object) &&
        ast.callee.object.type === "Identifier" &&
        ast.callee.object.name === "Date" &&
        method === "now" &&
        ast.arguments.length === 0
      ) {
        return {
          ...this.literal(nodeKey, 0, "", depth + 1),
          constant: undefined,
          fieldsComplete: false,
          sensitivityBasis: ["runtime_clock"],
          valueId: hash(["date_now", nodeKey]),
        };
      }
      if (
        isObject(ast.callee.object) &&
        ast.callee.object.type === "Identifier" &&
        ast.callee.object.name === "Math" &&
        [
          "abs",
          "ceil",
          "floor",
          "round",
          "trunc",
          "min",
          "max",
          "pow",
          "sqrt",
          "sign",
          "random",
        ].includes(String(method)) &&
        ast.arguments.every((arg) => arg.type !== "SpreadElement")
      ) {
        if (method === "random" && ast.arguments.length === 0) {
          return {
            ...this.literal(nodeKey, 0, "", depth + 1),
            constant: undefined,
            fieldsComplete: false,
            sensitivityBasis: ["runtime_metadata"],
            valueId: hash(["math_random", nodeKey]),
          };
        }
        if (ast.arguments.length > 0 && ast.arguments.length <= 16) {
          return this.transform(
            nodeKey,
            ast.arguments.map((argument) =>
              this.astValue(nodeKey, argument, depth + 1),
            ),
            "numeric_conversion",
          );
        }
      }
      if (
        [
          "toDateString",
          "toISOString",
          "toUTCString",
          "toJSON",
          "toLocaleDateString",
          "toLocaleString",
          "toLocaleTimeString",
          "getFullYear",
          "getMonth",
          "getDate",
          "getDay",
          "getHours",
          "getMinutes",
          "getSeconds",
          "getMilliseconds",
          "getTime",
          "getUTCFullYear",
          "getUTCMonth",
          "getUTCDate",
          "toFormat",
          "toISO",
          "toISODate",
          "toMillis",
          "toSeconds",
          "minus",
          "plus",
          "startOf",
          "endOf",
          "setZone",
        ].includes(String(method)) &&
        ast.arguments.length <= 4 &&
        ast.arguments.every((arg) => arg.type !== "SpreadElement")
      ) {
        const receiver = this.astValue(nodeKey, ast.callee.object, depth + 1);
        if (receiver.sensitivityBasis.includes("runtime_clock")) {
          const args = ast.arguments.map((argument) =>
            this.astValue(nodeKey, argument, depth + 1),
          );
          const transformed = this.transform(
            nodeKey,
            [receiver, ...args],
            "string_processing",
          );
          return {
            ...transformed,
            constant: undefined,
            fullObject: false,
            fieldsComplete: false,
            guards: [],
            valueId: hash([
              "clock_method",
              String(method),
              receiver.valueId,
              args.map((arg) => arg.valueId),
            ]),
          };
        }
      }
      if (
        [
          "trim",
          "trimStart",
          "trimEnd",
          "toLowerCase",
          "toUpperCase",
          "replace",
          "replaceAll",
          "split",
          "join",
          "slice",
          "substring",
          "concat",
          "includes",
          "startsWith",
          "endsWith",
          "padStart",
          "padEnd",
          "repeat",
          "charAt",
          "at",
          "indexOf",
          "lastIndexOf",
          "search",
          "localeCompare",
          "normalize",
          "toString",
        ].includes(String(method))
      ) {
        const receiver = this.astValue(nodeKey, ast.callee.object, depth + 1);
        const args = ast.arguments.map((argument) =>
          this.astValue(nodeKey, argument, depth + 1),
        );
        const result = this.transform(
          nodeKey,
          [receiver, ...args],
          "string_processing",
        );
        if (method === "split")
          return {
            ...this.unknown(nodeKey, "string_split_cardinality_unverified", [
              result,
            ]),
            fullObject: true,
            fieldsComplete: false,
          };
        return result;
      }
    }
    if (
      ast.type === "ConditionalExpression" &&
      isObject(ast.test) &&
      isObject(ast.consequent) &&
      isObject(ast.alternate)
    ) {
      const condition = this.astValue(nodeKey, ast.test, depth + 1);
      const values = [
        this.astValue(nodeKey, ast.consequent, depth + 1),
        this.astValue(nodeKey, ast.alternate, depth + 1),
      ];
      const selected = join(values, nodeKey, undefined, true);
      if (
        selected.projectionAlternatives &&
        !projectionShapeFits([...selected.projectionAlternatives, condition])
      )
        return this.unknown(nodeKey, "code_value_shape_limit", [
          selected,
          condition,
        ]);
      return {
        ...join([condition, selected], nodeKey),
        projectionAlternatives: selected.projectionAlternatives,
        projectionDependencies: selected.projectionAlternatives
          ? [unknownProjection(condition)]
          : undefined,
        guards: [],
        fieldsComplete: false,
        valueId: hash([
          "conditional_selection",
          condition.valueId,
          values.map((value) => value.valueId),
        ]),
      };
    }
    if (
      ast.type === "BinaryExpression" &&
      isObject(ast.left) &&
      isObject(ast.right)
    ) {
      if (ast.operator === "+")
        return this.transform(
          nodeKey,
          [
            this.astValue(nodeKey, ast.left, depth + 1),
            this.astValue(nodeKey, ast.right, depth + 1),
          ],
          "concatenation",
        );
      if (["-", "*", "/", "%", "**"].includes(String(ast.operator)))
        return this.transform(
          nodeKey,
          [
            this.astValue(nodeKey, ast.left, depth + 1),
            this.astValue(nodeKey, ast.right, depth + 1),
          ],
          "numeric_conversion",
        );
      if (
        ["===", "!==", "==", "!=", "<", "<=", ">", ">=", "in"].includes(
          String(ast.operator),
        )
      )
        return this.transform(
          nodeKey,
          [
            this.astValue(nodeKey, ast.left, depth + 1),
            this.astValue(nodeKey, ast.right, depth + 1),
          ],
          "string_processing",
        );
    }
    if (
      ast.type === "TemplateLiteral" &&
      Array.isArray(ast.expressions) &&
      Array.isArray(ast.quasis)
    ) {
      const ordered: AbstractValue[] = [];
      for (const [index, quasi] of ast.quasis.entries()) {
        ordered.push(
          isObject(quasi) &&
            isObject(quasi.value) &&
            typeof quasi.value.cooked === "string"
            ? this.literal(nodeKey, quasi.value.cooked)
            : this.unknown(nodeKey, "expression_syntax_unsupported"),
        );
        if (index < ast.expressions.length) {
          const value = ast.expressions[index];
          ordered.push(
            isObject(value)
              ? this.astValue(nodeKey, value, depth + 1)
              : this.unknown(nodeKey, "expression_syntax_unsupported"),
          );
        }
      }
      if (ast.quasis.length !== ast.expressions.length + 1)
        return this.unknown(nodeKey, "expression_syntax_unsupported", ordered);
      return this.transform(nodeKey, ordered, "concatenation");
    }
    if (ast.type === "ObjectExpression" && Array.isArray(ast.properties)) {
      if (!ast.properties.length)
        return this.literal(nodeKey, {}, "", depth + 1);
      const fields: Record<string, AbstractValue> = {};
      const properties = ast.properties;
      const withFieldHint = (
        value: AbstractValue,
        name: string,
      ): AbstractValue => {
        const inferred = this.classify(name);
        return inferred.sensitivity === "unknown" ||
          value.sensitivityBasis.some((basis) => basis.startsWith("trusted_"))
          ? value
          : {
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
      };
      const unresolved = (code: string, start: number): AbstractValue => {
        const candidates = Object.values(fields);
        for (const item of properties.slice(start, valueFlowLimits.fields)) {
          if (!isObject(item)) continue;
          if (item.type === "Property" && item.kind !== "init")
            candidates.push(this.input(nodeKey, [], depth + 1));
          if (item.computed === true && isObject(item.key))
            candidates.push(this.astValue(nodeKey, item.key, depth + 1));
          if (isObject(item.value)) {
            const value = this.astValue(nodeKey, item.value, depth + 1);
            const name =
              item.computed !== true && isObject(item.key)
                ? (item.key.name ?? item.key.value)
                : undefined;
            candidates.push(
              typeof name === "string" ? withFieldHint(value, name) : value,
            );
          }
          if (item.type === "SpreadElement" && isObject(item.argument))
            candidates.push(this.astValue(nodeKey, item.argument, depth + 1));
        }
        if (properties.length > valueFlowLimits.fields)
          candidates.push(this.unknown(nodeKey, "flow_field_limit"));
        return this.unknown(nodeKey, code, candidates);
      };
      for (const [index, item] of properties
        .slice(0, valueFlowLimits.fields)
        .entries()) {
        if (
          !isObject(item) ||
          item.type !== "Property" ||
          item.computed === true ||
          item.kind !== "init" ||
          !isObject(item.key) ||
          !isObject(item.value)
        )
          return unresolved("object_expression_unsupported", index);
        const name =
          item.key.type === "Identifier" ? item.key.name : item.key.value;
        if (typeof name !== "string" || !safeParts([name]))
          return unresolved("unsafe_field_reference", index);
        const value = this.astValue(nodeKey, item.value, depth + 1);
        // Object syntax and Code aliases retain the same field-name hints as
        // JSON/Set mappings. A hint adds a class; it never replaces the value's
        // existing secret, personal, public or unknown possibilities.
        fields[pointer([name])] = withFieldHint(value, name);
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
        constant: undefined,
        fullObject: true,
        fields,
        fieldsComplete: ast.properties.length <= valueFlowLimits.fields,
        valueId: hash(
          Object.entries(fields).map(([name, value]) => [name, value.valueId]),
        ),
      };
    }
    if (ast.type === "ArrayExpression" && Array.isArray(ast.elements)) {
      if (!ast.elements.length) return this.literal(nodeKey, [], "", depth + 1);
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
        constant: undefined,
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
    while (true) {
      if (
        current.type === "ParenthesizedExpression" &&
        isObject(current.expression)
      ) {
        current = current.expression;
        continue;
      }
      if (!(
        current.type === "MemberExpression" &&
        isObject(current.object) &&
        isObject(current.property)
      ))
        break;
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
      ["first", "last"].includes(String(current.callee.property.name)) &&
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

  private parameterExpressions(
    nodeKey: string,
    parameters: unknown,
    depth: number,
  ): AbstractValue[] {
    if (depth > 24) return [];
    const results: AbstractValue[] = [];
    const pending: { value: unknown; walkDepth: number }[] = [
      { value: parameters, walkDepth: 0 },
    ];
    let visited = 0;
    while (pending.length > 0 && visited++ < 256 && results.length < 32) {
      const { value, walkDepth } = pending.pop()!;
      if (walkDepth > 16) continue;
      if (
        typeof value === "string" &&
        value.startsWith("=") &&
        value.includes("{{")
      ) {
        results.push(this.resolveValue(nodeKey, value, {}, depth + 1));
      } else if (Array.isArray(value)) {
        for (const item of value.slice(0, 64))
          pending.push({ value: item, walkDepth: walkDepth + 1 });
      } else if (isObject(value)) {
        for (const item of Object.values(value).slice(0, 64))
          pending.push({ value: item, walkDepth: walkDepth + 1 });
      }
    }
    return results;
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
      undefined,
      true,
    );
  }

  private nodeValue(
    nodeKey: string,
    path: string[],
    port: number,
    depth: number,
  ): AbstractValue {
    if (!safeParts(path))
      return this.unknown(nodeKey, "unsafe_field_reference");
    const cacheKey = JSON.stringify([nodeKey, path, port]);
    const cached = this.cache.get(cacheKey);
    if (cached) return structuredClone(cached);
    if (!this.bounded(nodeKey, depth))
      return this.unknown(nodeKey, "flow_budget_exceeded");
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
        node.raw.executeOnce === true ||
        node.raw.rewireOutputLogTo !== undefined
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
        [2.4, 2.5, 2.6, 2.8].includes(node.typeVersion)
      )
        result = this.source(node, path, "database", depth + 1);
      else if (
        node.type === prefix + "noOp" &&
        node.typeVersion === 1 &&
        port === 0
      )
        result = this.input(nodeKey, path, depth + 1);
      else if (isStaticIntervalWait(node) && port === 0)
        result = this.input(nodeKey, path, depth + 1);
      else if (
        isStaticItemLimit(node) &&
        port === 0 &&
        this.context.edges.filter((edge) => edge.to === node.key).length ===
          1 &&
        this.context.edges.every(
          (edge) =>
            (edge.to !== node.key || edge.input === 0) &&
            (edge.from !== node.key || edge.output === 0),
        ) &&
        !this.context.unsupportedEdges.some(
          (edge) => edge.to === node.key || edge.from === node.key,
        )
      )
        result = this.input(nodeKey, path, depth + 1);
      else if (
        node.type === prefix + "aggregate" &&
        node.typeVersion === 1 &&
        port === 0
      )
        result = this.aggregateValue(node, path, depth + 1);
      else if (
        node.type === prefix + "set" &&
        [1, 2, 3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion) &&
        port === 0
      )
        result = this.setValue(node, path, depth + 1);
      else if (
        (node.type === prefix + "if" &&
          [2, 2.1, 2.2, 2.3].includes(node.typeVersion)) ||
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
        matchLocalCatalogEffect(node) !== undefined &&
        port === 0 &&
        !this.context.unsupportedEdges.some(
          (edge) => edge.to === node.key || edge.from === node.key,
        )
      ) {
        const localCatalog = matchLocalCatalogEffect(node)!;
        const incoming = this.context.edges.filter(
          (edge) => edge.to === node.key,
        );
        const outgoing = this.context.edges.filter(
          (edge) => edge.from === node.key,
        );
        const paramValues = this.parameterExpressions(
          nodeKey,
          node.parameters,
          depth + 1,
        );
        if (
          localCatalog.kind === "passthrough" &&
          incoming.length === 1 &&
          incoming.every((edge) => edge.input === 0) &&
          outgoing.every((edge) => edge.output === 0)
        ) {
          result = this.input(nodeKey, path, depth + 1);
          if (
            paramValues.some((val) =>
              val.diagnosticCodes.includes("direct_reference_unconnected"),
            )
          ) {
            result = this.unknown(nodeKey, "direct_reference_unconnected", [
              result,
              ...paramValues,
            ]);
          }
        } else if (
          localCatalog.kind === "append_merge" &&
          incoming.every((edge) => edge.input < localCatalog.inputs) &&
          outgoing.every((edge) => edge.output === 0)
        ) {
          result = this.mergeValue(node, path, depth + 1);
        } else {
          result = this.unknown(nodeKey, "node_transform_unsupported", [
            this.source(node, path, "node_output", depth + 1),
            this.input(nodeKey, [], depth + 1),
            ...paramValues,
          ]);
        }
      } else if (
        node.type === prefix + "code" &&
        [1, 2].includes(node.typeVersion) &&
        port === 0
      )
        result = this.codeValue(node, path, depth + 1);
      else if (port !== 0)
        result = this.unknown(nodeKey, "service_output_port_unresolved", [
          this.source(node, path, "node_output", depth + 1),
          this.input(nodeKey, [], depth + 1),
        ]);
      else {
        const ai = aiPromptInputs(node, this.context);
        const service = ai
          ? undefined
          : this.serviceValue(node, path, depth + 1);
        if (ai) {
          for (const code of ai.diagnostics) this.note(node.key, code);
          result = this.unknown(node.key, "ai_generation_output_unverified", [
            this.source(node, path, "node_output", depth + 1),
            ...ai.inputs.map((input) =>
              input.value === undefined
                ? this.unknown(node.key, "ai_prompt_value_unresolved")
                : this.resolveValue(
                    input.nodeKey ?? node.key,
                    input.value,
                    {},
                    depth + 1,
                  ),
            ),
          ]);
          result.guards = [];
          result.fullObject = path.length === 0;
          result.fieldsComplete = false;
        } else if (service) result = service;
        else
          result = this.unknown(nodeKey, "node_transform_unsupported", [
            this.source(node, path, "node_output", depth + 1),
            this.input(nodeKey, [], depth + 1),
            ...this.parameterExpressions(nodeKey, node.parameters, depth + 1),
          ]);
      }
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
      if (result.fullObject) delete result.constant;
      this.cache.set(cacheKey, structuredClone(result));
      return result;
    } finally {
      this.active.delete(cacheKey);
    }
  }

  private serviceValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue | undefined {
    if (node.type === prefix + "manualTrigger" && node.typeVersion === 1)
      return this.project(
        this.literal(node.key, {}),
        path,
        node.key,
        depth + 1,
      );
    const emailTrigger =
      (node.type === prefix + "gmailTrigger" &&
        [1, 1.1, 1.2, 1.3, 1.4].includes(node.typeVersion)) ||
      (node.type === prefix + "emailReadImap" &&
        [1, 2, 2.1, 2.2].includes(node.typeVersion));
    const externalTrigger =
      emailTrigger ||
      (node.type === prefix + "telegramTrigger" &&
        [1, 1.1, 1.2, 1.3, 1.4, 1.5].includes(node.typeVersion)) ||
      (node.type === prefix + "formTrigger" &&
        [2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6].includes(node.typeVersion));
    if (externalTrigger) {
      const source = this.source(node, path, "node_output", depth + 1);
      source.trust = "external";
      if (
        emailTrigger &&
        (!path.length ||
          path.some((part) =>
            /^(?:from|to|cc|bcc|sender|replyTo|text|html|snippet)$/i.test(part),
          )) &&
        !source.sensitivityBasis.some((basis) => basis.startsWith("trusted_"))
      ) {
        source.sensitivityClasses = unique([
          ...source.sensitivityClasses,
          "pii_candidate",
        ]);
        source.sensitivity =
          source.sensitivity === "secret_candidate"
            ? "secret_candidate"
            : "pii_candidate";
        source.sensitivityBasis.push("service_email_schema_candidate");
      }
      return {
        ...this.unknown(
          node.key,
          this.context.edges.some((edge) => edge.to === node.key)
            ? "trigger_input_connection_unresolved"
            : "trigger_payload_schema_unverified",
          [source],
        ),
        guards: [],
        fullObject: path.length === 0,
        fieldsComplete: false,
      };
    }
    const operation = node.parameters.operation;
    const gmail =
      node.type === prefix + "gmail" &&
      [2.1, 2.2].includes(node.typeVersion) &&
      (node.parameters.resource ?? "message") === "message" &&
      ["get", "getAll"].includes(stringSelector(operation));
    const airtable =
      node.type === prefix + "airtable" &&
      [2, 2.1, 2.2].includes(node.typeVersion) &&
      (node.parameters.resource ?? "record") === "record" &&
      ["get", "search", "create", "update", "upsert", "deleteRecord"].includes(
        stringSelector(operation ?? "get"),
      );
    const sheets =
      node.type === prefix + "googleSheets" &&
      [3, 4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7].includes(node.typeVersion) &&
      (node.parameters.resource ?? "sheet") === "sheet" &&
      (operation ?? "read") === "read";
    const http =
      node.type === prefix + "httpRequest" &&
      [3, 4, 4.1, 4.2, 4.3].includes(node.typeVersion);
    const notion =
      node.type === prefix + "notion" &&
      [2, 2.1, 2.2].includes(node.typeVersion) &&
      ((node.parameters.resource === "databasePage" &&
        ["get", "getAll"].includes(stringSelector(operation))) ||
        (node.parameters.resource === "database" && operation === "get"));
    const docs =
      node.type === prefix + "googleDocs" &&
      [1, 2].includes(node.typeVersion) &&
      (node.parameters.resource ?? "document") === "document" &&
      operation === "get";
    const trigger =
      node.type === prefix + "errorTrigger" && node.typeVersion === 1;
    if (gmail || airtable || sheets || http || trigger || notion || docs) {
      const source = this.source(node, path, "node_output", depth + 1);
      source.trust = "external";
      if (
        gmail &&
        (!path.length ||
          path.some((part) =>
            /^(?:from|to|cc|bcc|sender|replyTo|text|html|snippet)$/i.test(part),
          )) &&
        !source.sensitivityBasis.some((basis) => basis.startsWith("trusted_"))
      ) {
        source.sensitivityClasses = unique([
          ...source.sensitivityClasses,
          "pii_candidate",
        ]);
        source.sensitivity =
          source.sensitivity === "secret_candidate"
            ? "secret_candidate"
            : "pii_candidate";
        source.sensitivityBasis = unique([
          ...source.sensitivityBasis,
          "service_email_schema_candidate",
        ]);
      }
      return {
        ...this.unknown(
          node.key,
          trigger
            ? "trigger_runtime_data_unverified"
            : "service_response_shape_unverified",
          [source],
        ),
        guards: [],
        fullObject: path.length === 0,
        fieldsComplete: false,
      };
    }
    if (
      node.type === prefix + "googleSheets" &&
      [3, 4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7].includes(node.typeVersion) &&
      (node.parameters.resource ?? "sheet") === "sheet" &&
      operation === "append"
    )
      return {
        ...this.unknown(node.key, "sheets_append_output_mode_unverified", [
          this.source(node, path, "node_output", depth + 1),
          this.input(node.key, [], depth + 1),
        ]),
        guards: [],
        fieldsComplete: false,
      };
    const catalogService = matchCatalogServiceSource(node);
    if (catalogService) {
      if (catalogService.kind === "html_extract") {
        const extractedInput = this.input(
          node.key,
          [catalogService.sourceProperty],
          depth + 1,
        );
        const wholeInput = this.input(node.key, [], depth + 1);
        const nodeSource = this.source(node, path, "node_output", depth + 1);
        nodeSource.trust = extractedInput.trust;
        const paramValues = this.parameterExpressions(
          node.key,
          node.parameters,
          depth + 1,
        );
        const merged = this.unknown(node.key, "field_projection_partial", [
          nodeSource,
          extractedInput,
          wholeInput,
          ...paramValues,
        ]);
        return {
          ...merged,
          trust:
            extractedInput.trust === "external" ||
            wholeInput.trust === "external"
              ? "external"
              : merged.trust,
          guards: [],
          fullObject: path.length === 0,
          fieldsComplete: false,
        };
      }
      const source = this.source(node, path, "node_output", depth + 1);
      source.trust = "external";
      if (
        catalogService.piiFieldPattern &&
        catalogService.piiBasis &&
        (!path.length ||
          path.some((part) => catalogService.piiFieldPattern!.test(part))) &&
        !source.sensitivityBasis.some((basis) => basis.startsWith("trusted_"))
      ) {
        source.sensitivityClasses = unique([
          ...source.sensitivityClasses,
          "pii_candidate",
        ]);
        source.sensitivity =
          source.sensitivity === "secret_candidate"
            ? "secret_candidate"
            : "pii_candidate";
        source.sensitivityBasis = unique([
          ...source.sensitivityBasis,
          catalogService.piiBasis,
        ]);
      }
      return {
        ...this.unknown(
          node.key,
          catalogService.kind === "external_trigger"
            ? this.context.edges.some((edge) => edge.to === node.key)
              ? "trigger_input_connection_unresolved"
              : "trigger_payload_schema_unverified"
            : "service_response_shape_unverified",
          [source],
        ),
        guards: [],
        fullObject: path.length === 0,
        fieldsComplete: false,
      };
    }
    return;
  }

  private aggregateValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    const parameters = node.parameters;
    const options = isObject(parameters.options) ? parameters.options : {};
    const unresolved = (code: string): AbstractValue =>
      this.unknown(node.key, code, [this.input(node.key, [], depth + 1)]);
    if (
      (parameters.options !== undefined && !isObject(parameters.options)) ||
      Object.entries(options).some(
        ([key, value]) =>
          ![
            "disableDotNotation",
            "mergeLists",
            "keepMissing",
            "includeBinaries",
            "keepOnlyUnique",
          ].includes(key) || typeof value !== "boolean",
      )
    )
      return unresolved("aggregate_options_unresolved");
    const candidateSubtree = (value: AbstractValue): AbstractValue => ({
      ...value,
      origins: value.origins.map((origin) =>
        origin.kind === "literal"
          ? origin
          : { ...origin, includesDescendants: true },
      ),
    });
    // A representative element carries every possible input's classification.
    // Its index, presence, cardinality and branch guards are not established.
    const collection = (value: AbstractValue): AbstractValue => ({
      ...this.unknown(node.key, "collection_cardinality_unverified", [value]),
      constant: undefined,
      guards: [],
      presence: "unknown",
      fullObject: true,
      fields: undefined,
      fieldsComplete: false,
      valueId: hash(["aggregate_collection", node.key, value.valueId]),
    });
    const keys = (value: unknown): string[] | undefined => {
      const entries =
        typeof value === "string"
          ? value
              .split(",")
              .map((entry) => entry.trim())
              .filter(Boolean)
          : Array.isArray(value)
            ? value
            : undefined;
      if (
        !entries ||
        entries.length > valueFlowLimits.fields ||
        entries.some(
          (entry) =>
            typeof entry !== "string" ||
            entry.startsWith("=") ||
            !safeParts([entry]),
        )
      )
        return;
      return entries as string[];
    };
    const mode =
      parameters.aggregate === undefined
        ? "aggregateIndividualFields"
        : parameters.aggregate;
    if (mode === "aggregateAllItemData") {
      const destination =
        parameters.destinationFieldName === undefined
          ? "data"
          : parameters.destinationFieldName;
      const include = keys(
        parameters.fieldsToInclude === undefined
          ? ""
          : parameters.fieldsToInclude,
      );
      const exclude = keys(
        parameters.fieldsToExclude === undefined
          ? ""
          : parameters.fieldsToExclude,
      );
      if (
        typeof destination !== "string" ||
        destination.startsWith("=") ||
        !safeParts([destination]) ||
        !include ||
        !exclude
      )
        return unresolved("aggregate_fields_unresolved");
      const accepts = (key: string): boolean =>
        (!include.length || include.includes(key)) && !exclude.includes(key);
      const item = (field: string[]): AbstractValue => {
        if (field.length)
          return accepts(field[0]!)
            ? this.input(node.key, field, depth + 1)
            : empty(node.key, undefined, true);
        if (include.length) {
          const selected = include
            .filter(accepts)
            .map((key) => this.input(node.key, [key], depth + 1));
          return selected.length
            ? join(selected, node.key)
            : this.literal(node.key, {});
        }
        const value = this.input(node.key, [], depth + 1);
        return exclude.length
          ? this.unknown(node.key, "aggregate_excluded_unknown_fields", [value])
          : value;
      };
      if (path.length && path[0] !== destination)
        return empty(node.key, undefined, true);
      if (path.length > 1 && /^(?:0|[1-9]\d*)$/.test(path[1]!)) {
        const value = item(path.slice(2));
        const selected =
          path.length > 2 || include.length || !exclude.length
            ? candidateSubtree(value)
            : value;
        return { ...collection(selected), fullObject: value.fullObject };
      }
      const whole = item([]);
      // With exclude-only on an unknown input shape, the remaining root fields
      // are not known. Do not widen that root to include removed descendants.
      const value = collection(
        include.length || !exclude.length ? candidateSubtree(whole) : whole,
      );
      return path.length
        ? value
        : {
            ...value,
            fields: { [pointer([destination])]: value },
            fieldsComplete: true,
          };
    }
    if (mode !== "aggregateIndividualFields")
      return unresolved("aggregate_mode_unresolved");
    const configured = isObject(parameters.fieldsToAggregate)
      ? parameters.fieldsToAggregate.fieldToAggregate
      : undefined;
    if (
      !Array.isArray(configured) ||
      !configured.length ||
      configured.length > valueFlowLimits.fields
    )
      return unresolved("aggregate_fields_unresolved");
    const mappings: {
      output: string[];
      input: string[];
      literalInput: string;
    }[] = [];
    const runtimeKeys = new Set<string | undefined>();
    for (const field of configured) {
      if (
        !isObject(field) ||
        typeof field.fieldToAggregate !== "string" ||
        !field.fieldToAggregate ||
        field.fieldToAggregate.startsWith("=") ||
        (field.renameField !== undefined &&
          typeof field.renameField !== "boolean") ||
        (field.outputFieldName !== undefined &&
          typeof field.outputFieldName !== "string")
      )
        return unresolved("aggregate_fields_unresolved");
      const runtimeKey =
        field.renameField === true
          ? field.outputFieldName
          : field.fieldToAggregate;
      if (runtimeKeys.has(runtimeKey))
        return unresolved("aggregate_duplicate_field_unresolved");
      runtimeKeys.add(runtimeKey);
      const input =
        options.disableDotNotation === true
          ? [field.fieldToAggregate]
          : field.fieldToAggregate.split(".");
      const outputName = field.outputFieldName || input.at(-1)!;
      if (typeof outputName !== "string" || outputName.startsWith("="))
        return unresolved("aggregate_fields_unresolved");
      const output =
        options.disableDotNotation === true
          ? [outputName]
          : outputName.split(".");
      if (
        !safeParts(input) ||
        !safeParts(output) ||
        [...input, ...output].some((part) => /[\[\]]/.test(part)) ||
        mappings.some(
          (entry) =>
            pointer(entry.output) === pointer(output) ||
            pointer(entry.output).startsWith(pointer(output) + "/") ||
            pointer(output).startsWith(pointer(entry.output) + "/"),
        )
      )
        return unresolved("aggregate_fields_unresolved");
      mappings.push({ input, output, literalInput: field.fieldToAggregate });
    }
    const fields: Record<string, AbstractValue> = Object.create(null);
    for (const entry of mappings) {
      const read = (tail: string[]): AbstractValue => {
        const nested = this.input(
          node.key,
          [...entry.input, ...tail],
          depth + 1,
        );
        // lodash.get prefers an existing literal dotted key before treating
        // the name as a nested path. Unknown item shapes can contain either.
        return entry.input.length > 1
          ? this.unknown(
              node.key,
              "aggregate_dotted_key_resolution_unverified",
              [
                nested,
                this.input(node.key, [entry.literalInput, ...tail], depth + 1),
              ],
            )
          : nested;
      };
      const value = read([]);
      const descendants = candidateSubtree(value);
      fields[pointer(entry.output)] = collection(descendants);
      if (pointer(path).startsWith(pointer(entry.output) + "/")) {
        const tail = path.slice(entry.output.length);
        if (!/^(?:0|[1-9]\d*)$/.test(tail[0]!))
          return unresolved("aggregate_array_property_unresolved");
        const element =
          options.mergeLists === true
            ? this.unknown(node.key, "aggregate_flatten_shape_unverified", [
                descendants,
                read(tail.slice(1)),
                read(["0", ...tail.slice(1)]),
              ])
            : options.keepMissing !== true &&
                tail.length > 1 &&
                /^(?:0|[1-9]\d*)$/.test(tail[1]!)
              ? this.unknown(
                  node.key,
                  "aggregate_null_filter_alignment_unverified",
                  [descendants, read(tail.slice(1))],
                )
              : read(tail.slice(1));
        return {
          ...collection(candidateSubtree(element)),
          fullObject: element.fullObject,
        };
      }
    }
    const value = {
      ...join(Object.values(fields), node.key),
      constant: undefined,
      fullObject: true,
      fields,
      fieldsComplete: true,
      guards: [],
    };
    return this.project(value, path, node.key, depth + 1);
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
    if (
      typeof include !== "string" ||
      !["all", "none", "selected", "except"].includes(include)
    )
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
      const names = configured
        .split(",")
        .map((name) => name.trim())
        .filter(Boolean);
      const listed = names.map(nameParts);
      if (listed.some((entry) => !entry))
        return this.unknown(node.key, "set_include_fields_unresolved");
      if (include === "selected") {
        const fields = new Map<string, AbstractValue>();
        for (const [index, entry] of listed.entries()) {
          const name = names[index]!;
          const output =
            options.dotNotation !== false && name.includes(".")
              ? nameParts(name.split(".").at(-1)!)!
              : entry!;
          fields.set(pointer(output), this.input(node.key, entry!, depth + 1));
        }
        const value = {
          ...join([...fields.values()], node.key),
          constant: undefined,
          fullObject: true,
          fields: Object.fromEntries(fields),
          fieldsComplete: true,
        };
        return this.project(value, path, node.key, depth + 1);
      }
      if (!path.length)
        return this.unknown(node.key, "set_exclusion_whole_object_partial", [
          this.input(node.key, path, depth + 1),
        ]);
      const matched = listed.some(
        (entry) =>
          pointer(path) === pointer(entry!) ||
          pointer(path).startsWith(pointer(entry!) + "/"),
      );
      return !matched
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
          "binary",
        ].includes(typeof assignment.type === "string" ? assignment.type : "")
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
      if (assignment.type === "binary")
        value = this.unknown(
          node.key,
          "set_binary_json_assignment_unverified",
          [value, this.input(node.key, [], depth + 1)],
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
        constant: undefined,
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
        constant: undefined,
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
      const unresolvedRoute = (code: string): AbstractValue => ({
        ...this.unknown(node.key, code, [
          this.input(node.key, path, depth + 1),
        ]),
        guards: [],
      });
      if (
        node.parameters.options !== undefined &&
        !isObject(node.parameters.options)
      )
        return unresolvedRoute("switch_options_unresolved");
      if ((node.parameters.mode ?? "rules") !== "rules")
        return this.unknown(node.key, "switch_expression_mode_unresolved", [
          this.input(node.key, path, depth + 1),
        ]);
      const rules = isObject(node.parameters.rules)
        ? node.parameters.rules.values
        : undefined;
      if (!Array.isArray(rules))
        return this.unknown(node.key, "switch_rules_unavailable");
      const fallback = options.fallbackOutput;
      const fallbackIndex =
        typeof fallback === "number"
          ? fallback
          : typeof fallback === "string" && /^(?:0|[1-9]\d*)$/.test(fallback)
            ? Number(fallback)
            : undefined;
      const staticOutput =
        fallbackIndex !== undefined &&
        Number.isSafeInteger(fallbackIndex) &&
        fallbackIndex >= 0 &&
        fallbackIndex < rules.length;
      if (
        fallback !== undefined &&
        fallback !== "none" &&
        fallback !== "extra" &&
        !staticOutput
      )
        return unresolvedRoute("switch_fallback_selector_unresolved");
      if (port === rules.length && fallback === "extra")
        return this.input(node.key, path, depth + 1);
      if (port >= rules.length)
        return this.unknown(node.key, "branch_output_unavailable");
      if (fallbackIndex === port)
        return unresolvedRoute("switch_fallback_reuses_output");
      filter = isObject(rules[port]) ? rules[port].conditions : undefined;
      passed = true;
    }
    const result = this.input(node.key, path, depth + 1);
    const loose =
      node.typeVersion >= (node.type === prefix + "if" ? 2.1 : 3.1)
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
      ![1, 2, 3].includes(Number(filter.options.version ?? 1)) ||
      (filter.options.version !== undefined &&
        typeof filter.options.version !== "number")
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
      // Every filter version accepts null/undefined before strict type
      // validation; v3 additionally normalizes empty strings/arrays to null.
      // Only finite-number equality excludes all these non-number inputs.
      const finiteNumberProof =
        (operation === "equals" && passed) ||
        (operation === "notEquals" && !passed);
      if (
        type === "number" &&
        ["equals", "notEquals", "gt", "gte", "lt", "lte"].includes(operation) &&
        typeof condition.rightValue === "number" &&
        Number.isFinite(condition.rightValue) &&
        finiteNumberProof
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
    const alternatives =
      value.projectionAlternatives ??
      (value.projectionDependencies?.length
        ? [{ ...value, projectionDependencies: undefined }]
        : undefined);
    if (alternatives) {
      if (!this.bounded(nodeKey, depth))
        return this.unknown(nodeKey, "flow_budget_exceeded", [value]);
      const projected = join(
        alternatives.map((alternative) =>
          alternative.fields ||
          alternative.representativeElement ||
          alternative.projectionAlternatives ||
          alternative.origins.some(
            (origin) => origin.descendantPath && !origin.projectionUnknown,
          )
            ? this.project(alternative, path, nodeKey, depth + 1)
            : unknownProjection(
                this.unknown(nodeKey, "field_projection_partial", [
                  alternative,
                ]),
              ),
        ),
        nodeKey,
        "field_projection_partial",
        true,
      );
      const dependencies = value.projectionDependencies ?? [];
      if (!dependencies.length) return projected;
      if (!projectionShapeFits([projected, ...dependencies]))
        return this.unknown(nodeKey, "code_value_shape_limit", [
          projected,
          ...dependencies,
        ]);
      return {
        ...join([projected, ...dependencies], nodeKey),
        projectionAlternatives: projected.projectionAlternatives,
        projectionDependencies: projected.projectionAlternatives
          ? dependencies
          : undefined,
        fieldsComplete: false,
        guards: [],
      };
    }
    const selectedElement = (
      selected: AbstractValue,
      identity: unknown,
    ): AbstractValue => {
      const origins = selected.origins.map((origin) =>
        origin.kind === "literal"
          ? origin
          : {
              ...origin,
              includesDescendants: true as const,
              descendantPath: origin.descendantPath ?? [],
            },
      );
      return {
        ...preserveValueShape(
          this.unknown(nodeKey, "code_collection_index_unverified", [selected]),
          selected,
        ),
        origins,
        constant: undefined,
        guards: [],
        presence: "unknown",
        representativeSelection: true,
        valueId: hash([
          "code_collection_selection",
          selected.valueId,
          origins,
          identity,
        ]),
      };
    };
    if (value.representativeElement && /^(?:0|[1-9]\d*)$/.test(path[0]!)) {
      // The source wildcard is already part of the representative. Consume the
      // requested output index without appending it to the source path again.
      return selectedElement(
        this.project(
          value.representativeElement,
          path.slice(1),
          nodeKey,
          depth + 1,
        ),
        [value.valueId, path],
      );
    }
    if (value.representativeSelection) {
      const unmarked = { ...value };
      delete unmarked.representativeSelection;
      return selectedElement(this.project(unmarked, path, nodeKey, depth + 1), [
        value.valueId,
        path,
      ]);
    }
    const unresolved = (): AbstractValue => {
      const result: AbstractValue = {
        ...this.unknown(nodeKey, "field_projection_partial", [value]),
        presence: "unknown",
        guards: [],
        valueId: hash(["unresolved_projection", value.valueId, path]),
      };
      result.origins = result.origins.map((origin) =>
        origin.includesDescendants &&
        origin.descendantPath &&
        !origin.projectionUnknown
          ? { ...origin, descendantPath: [...origin.descendantPath, ...path] }
          : origin,
      );
      const candidates = result.origins.filter(
        (origin) => origin.kind !== "literal",
      );
      if (
        candidates.length &&
        candidates.every(
          (origin) => origin.includesDescendants && origin.descendantPath,
        ) &&
        value.sensitivityBasis.some((basis) => basis.startsWith("trusted_")) &&
        value.sensitivityBasis.every(
          (basis) =>
            basis.startsWith("trusted_") || basis === "literal_definition",
        )
      ) {
        // Source annotations are initially aggregated into a whole collection.
        // Re-select them after a known member read so a secret sibling does not
        // contaminate a selected ordinary field. Non-annotation candidates are
        // never removed here, and unresolved contents remain explicitly unknown.
        const annotations = (this.options.sourceAnnotations ?? [])
          .slice(0, valueFlowLimits.annotations)
          .filter((annotation) =>
            candidates.some(
              (origin) =>
                annotation.nodeKey === origin.nodeKey &&
                safeParts(parts(annotation.fieldPath)) &&
                originIncludesField(
                  origin,
                  pointer(parts(annotation.fieldPath)),
                ),
            ),
          );
        result.sensitivityClasses = unique<Sensitivity>([
          "unknown",
          ...value.sensitivityClasses.filter(
            (kind) => kind === "public_literal",
          ),
          ...annotations.map((annotation) => annotation.sensitivity),
        ]).sort((a, b) => severity(b) - severity(a));
        result.sensitivity = result.sensitivityClasses[0]!;
        result.sensitivityBasis = unique([
          ...value.sensitivityBasis.filter(
            (basis) => basis === "literal_definition",
          ),
          ...annotations.map(
            (annotation) => "trusted_" + annotation.provenance + "_annotation",
          ),
        ]);
      }
      return result;
    };
    if (value.fieldsComplete === false && !value.fields) return unresolved();
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
          constant: undefined,
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
      true,
    );
  }

  private codeValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    const cached = this.codeOutputs.get(node.key);
    if (cached)
      return this.project(structuredClone(cached), path, node.key, depth + 1);
    const source = node.parameters.jsCode;
    if (
      (node.typeVersion >= 2 &&
        (node.parameters.language ?? "javaScript") !== "javaScript") ||
      typeof source !== "string"
    )
      return this.simpleCodeValue(node, path, depth);
    const host: BoundedCodeHost = {
      evaluate: (value) => this.astValue(node.key, value, depth + 1),
      literal: (value) => this.literal(node.key, value, "", depth + 1),
      union: (values) => join(values, node.key, undefined, true),
      project: (value, selected) =>
        safeParts(selected)
          ? this.project(value, selected, node.key, depth + 1)
          : this.unknown(node.key, "unsafe_field_reference", [value]),
      unknown: (code, values) => this.unknown(node.key, code, values),
      input: () => this.input(node.key, [], depth + 1),
      bounded: () => this.bounded(node.key, depth + 1),
    };
    const finish = (output: AbstractValue): AbstractValue => {
      this.codeOutputs.set(node.key, structuredClone(output));
      return this.project(output, path, node.key, depth + 1);
    };
    if ((node.parameters.mode ?? "runOnceForAllItems") !== "runOnceForAllItems")
      return finish(
        observeInvalidCode(
          source,
          host,
          source.length > valueFlowLimits.expressionCharacters
            ? "code_source_size_limit"
            : "code_item_mode_unresolved",
        ),
      );
    if (source.length > valueFlowLimits.expressionCharacters)
      return finish(observeInvalidCode(source, host, "code_source_size_limit"));
    const simple = this.simpleCodeValue(node, path, depth);
    if (
      typeof source === "string" &&
      simple.diagnosticCodes.includes("code_parse_unavailable")
    )
      return finish(
        observeInvalidCode(source, host, "code_parse_unavailable", [simple]),
      );
    if (!simple.diagnosticCodes.includes("code_mapping_unsupported"))
      return simple;
    try {
      if (
        typeof source !== "string" ||
        source.length > valueFlowLimits.expressionCharacters
      )
        return this.unknown(node.key, "code_source_size_limit", [simple]);
      const ast = parse(source, {
        ecmaVersion: "latest",
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      }) as unknown;
      if (!isObject(ast)) return simple;
      const output = analyzeBoundedCode(ast, host);
      // The fallback reports its actual bounded transfer limitations instead
      // of retaining the fast profile's generic mapping rejection.
      for (let index = this.diagnostics.length - 1; index >= 0; index--)
        if (
          this.diagnostics[index]!.nodeKey === node.key &&
          this.diagnostics[index]!.code === "code_mapping_unsupported"
        )
          this.diagnostics.splice(index, 1);
      return finish(output);
    } catch {
      return typeof source === "string"
        ? finish(
            observeInvalidCode(source, host, "code_parse_unavailable", [
              simple,
            ]),
          )
        : this.unknown(node.key, "code_parse_unavailable", [simple]);
    }
  }

  private simpleCodeValue(
    node: NormalizedNode,
    path: string[],
    depth: number,
  ): AbstractValue {
    const cached = this.codeOutputs.get(node.key);
    if (cached)
      return this.project(structuredClone(cached), path, node.key, depth + 1);
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
        allowAwaitOutsideFunction: true,
      }) as unknown;
      if (
        !isObject(ast) ||
        !Array.isArray(ast.body) ||
        ast.body.length === 0 ||
        ast.body.length > valueFlowLimits.fields
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      // Interpret only immutable local declarations followed by a single
      // return. Calls, mutation, branches, loops and declarations outside this
      // grammar remain opaque; no submitted JavaScript is evaluated.
      const locals = new Map<string, Record<string, unknown>>();
      const roots = new Set([
        "$json",
        "$input",
        "$node",
        "$env",
        "$credentials",
        "$",
        "JSON",
        "Number",
        "parseInt",
        "parseFloat",
        "encodeURIComponent",
        "$now",
        "$today",
        "Date",
        "undefined",
      ]);
      const literalOptions = (item: unknown): boolean => {
        if (!isObject(item)) return false;
        if (item.type === "Literal")
          return !isObject(item.value) && !item.regex;
        if (item.type === "Identifier") return item.name === "undefined";
        if (
          item.type === "ObjectExpression" &&
          Array.isArray(item.properties) &&
          item.properties.length <= 16
        )
          return item.properties.every(
            (property) =>
              isObject(property) &&
              property.type === "Property" &&
              property.kind === "init" &&
              property.computed !== true &&
              isObject(property.value) &&
              property.value.type === "Literal" &&
              !isObject(property.value.value),
          );
        return false;
      };
      const expand = (
        item: Record<string, unknown>,
        level: number,
      ): Record<string, unknown> | undefined => {
        if (!this.bounded(node.key, level)) return;
        if (item.type === "Literal") return item;
        if (item.type === "ChainExpression" && isObject(item.expression)) {
          const expression = expand(item.expression, level + 1);
          return expression ? { ...item, expression } : undefined;
        }
        if (
          item.type === "LogicalExpression" &&
          ["||", "??"].includes(String(item.operator)) &&
          isObject(item.left) &&
          isObject(item.right)
        ) {
          const left = expand(item.left, level + 1);
          const right = expand(item.right, level + 1);
          return left && right ? { ...item, left, right } : undefined;
        }
        if (item.type === "Identifier") {
          if (typeof item.name !== "string") return;
          return (
            locals.get(item.name) ?? (roots.has(item.name) ? item : undefined)
          );
        }
        if (
          item.type === "CallExpression" &&
          isObject(item.callee) &&
          item.callee.type === "MemberExpression" &&
          item.callee.computed !== true &&
          isObject(item.callee.property) &&
          isObject(item.callee.object) &&
          Array.isArray(item.arguments)
        ) {
          const receiver = item.callee.object;
          const method = item.callee.property.name;
          const nativeClock =
            receiver.type === "NewExpression" &&
            isObject(receiver.callee) &&
            receiver.callee.type === "Identifier" &&
            receiver.callee.name === "Date" &&
            Array.isArray(receiver.arguments) &&
            receiver.arguments.length === 0 &&
            typeof method === "string" &&
            [
              "toDateString",
              "toISOString",
              "toUTCString",
              "toJSON",
              "toLocaleDateString",
              "toLocaleString",
              "toLocaleTimeString",
            ].includes(method);
          const n8nClock =
            receiver.type === "Identifier" &&
            ["$now", "$today"].includes(String(receiver.name)) &&
            typeof method === "string" &&
            ["toFormat", "toISO", "toISODate", "toLocaleString"].includes(
              method,
            );
          if ((nativeClock || n8nClock) && item.arguments.every(literalOptions))
            return {
              type: "Literal",
              value: "clock_" + hash([node.key, item]),
              boundedClock: true,
              boundedClockArguments: item.arguments.filter(
                (argument) =>
                  !(
                    isObject(argument) &&
                    argument.type === "Identifier" &&
                    argument.name === "undefined"
                  ),
              ),
            };
        }
        if (
          item.type === "ObjectExpression" &&
          Array.isArray(item.properties)
        ) {
          const properties = [];
          for (const property of item.properties.slice(
            0,
            valueFlowLimits.fields + 1,
          )) {
            if (
              !isObject(property) ||
              property.type !== "Property" ||
              property.kind !== "init" ||
              property.computed === true ||
              !isObject(property.value)
            )
              return;
            const value = expand(property.value, level + 1);
            if (!value) return;
            properties.push({ ...property, value });
          }
          return { ...item, properties };
        }
        if (item.type === "ArrayExpression" && Array.isArray(item.elements)) {
          const elements = [];
          for (const element of item.elements.slice(
            0,
            valueFlowLimits.fields + 1,
          )) {
            if (element === null) {
              elements.push(null);
              continue;
            }
            if (!isObject(element)) return;
            const value = expand(element, level + 1);
            if (!value) return;
            elements.push(value);
          }
          return { ...item, elements };
        }
        if (
          item.type === "TemplateLiteral" &&
          Array.isArray(item.expressions)
        ) {
          const expressions = item.expressions.map((child) =>
            isObject(child) ? expand(child, level + 1) : undefined,
          );
          return expressions.every(Boolean)
            ? { ...item, expressions }
            : undefined;
        }
        if (
          item.type === "BinaryExpression" &&
          item.operator === "+" &&
          isObject(item.left) &&
          isObject(item.right)
        ) {
          const left = expand(item.left, level + 1),
            right = expand(item.right, level + 1);
          return left && right ? { ...item, left, right } : undefined;
        }
        if (
          item.type === "MemberExpression" &&
          isObject(item.object) &&
          isObject(item.property)
        ) {
          const object = expand(item.object, level + 1);
          const property =
            item.computed === true
              ? expand(item.property, level + 1)
              : item.property;
          return object && property ? { ...item, object, property } : undefined;
        }
        if (
          item.type === "CallExpression" &&
          isObject(item.callee) &&
          Array.isArray(item.arguments)
        ) {
          const callee = item.callee;
          const simple =
            callee.type === "Identifier" &&
            [
              "Number",
              "parseInt",
              "parseFloat",
              "encodeURIComponent",
              "$",
            ].includes(String(callee.name)) &&
            item.arguments.length === 1;
          const stringify =
            callee.type === "MemberExpression" &&
            callee.computed !== true &&
            isObject(callee.object) &&
            callee.object.type === "Identifier" &&
            callee.object.name === "JSON" &&
            isObject(callee.property) &&
            callee.property.name === "stringify" &&
            item.arguments.length === 1;
          const selection =
            callee.type === "MemberExpression" &&
            callee.computed !== true &&
            isObject(callee.property) &&
            ["first", "last", "all"].includes(String(callee.property.name)) &&
            isObject(callee.object) &&
            ((callee.object.type === "Identifier" &&
              callee.object.name === "$input") ||
              (callee.object.type === "CallExpression" &&
                isObject(callee.object.callee) &&
                callee.object.callee.name === "$")) &&
            item.arguments.length === 0;
          if (!simple && !stringify && !selection) return;
          const expandedCallee = expand(callee, level + 1);
          const args = item.arguments.map((child) =>
            isObject(child) ? expand(child, level + 1) : undefined,
          );
          return expandedCallee && args.every(Boolean)
            ? { ...item, callee: expandedCallee, arguments: args }
            : undefined;
        }
        return;
      };
      for (const statement of ast.body.slice(0, -1)) {
        if (
          !isObject(statement) ||
          statement.type !== "VariableDeclaration" ||
          statement.kind !== "const" ||
          !Array.isArray(statement.declarations)
        )
          return this.unknown(node.key, "code_mapping_unsupported");
        for (const declaration of statement.declarations) {
          if (
            !isObject(declaration) ||
            !isObject(declaration.id) ||
            declaration.id.type !== "Identifier" ||
            typeof declaration.id.name !== "string" ||
            roots.has(declaration.id.name) ||
            locals.has(declaration.id.name) ||
            !isObject(declaration.init) ||
            locals.size >= valueFlowLimits.fields
          )
            return this.unknown(node.key, "code_mapping_unsupported");
          const value = expand(declaration.init, depth + 1);
          if (!value) return this.unknown(node.key, "code_mapping_unsupported");
          locals.set(declaration.id.name, value);
        }
      }
      const final = ast.body.at(-1);
      if (
        !isObject(final) ||
        final.type !== "ReturnStatement" ||
        !isObject(final.argument)
      )
        return this.unknown(node.key, "code_mapping_unsupported");
      const returned = expand(final.argument, depth + 1);
      if (!returned) return this.unknown(node.key, "code_mapping_unsupported");
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
      const object =
        returned.type === "ObjectExpression"
          ? returned
          : returned.type === "ArrayExpression" &&
              Array.isArray(returned.elements) &&
              returned.elements.length === 1 &&
              isObject(returned.elements[0])
            ? returned.elements[0]
            : undefined;
      if (
        !object ||
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
      const output = this.astValue(node.key, property.value, depth + 1);
      this.codeOutputs.set(node.key, structuredClone(output));
      return this.project(output, path, node.key, depth + 1);
    } catch {
      return this.unknown(node.key, "code_parse_unavailable");
    }
  }
}
