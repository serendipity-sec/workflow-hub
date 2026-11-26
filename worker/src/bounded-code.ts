import type { AbstractValue } from "./value-flow.js";
import { preserveValueShape } from "./value-shape.js";
import { createHash } from "node:crypto";
import { tokenizer, type Token } from "acorn";

type Ast = Record<string, unknown>;
const object = (value: unknown): value is Ast =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const marker = (value: AbstractValue): Ast => ({ type: "BoundedValue", value });
const keyOf = (value: Ast): string | undefined => {
  if (!object(value.property)) return;
  const key =
    value.computed === true
      ? value.property.type === "Literal"
        ? value.property.value
        : undefined
      : value.property.name;
  return typeof key === "string" || typeof key === "number"
    ? String(key)
    : undefined;
};
const roots = new Set([
  "$json",
  "$input",
  "$node",
  "$env",
  "$credentials",
  "$",
  "JSON",
  "String",
  "Number",
  "Boolean",
  "parseInt",
  "parseFloat",
  "encodeURIComponent",
  "$now",
  "$today",
  "Date",
  "undefined",
]);
const stringMethods = new Set([
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
  "toString",
]);
const specialKeys = new Set(["__proto__", "prototype", "constructor"]);
interface Binding {
  value: AbstractValue;
  mutable: boolean;
  owned: boolean;
  objectId?: number;
}
interface State {
  env: Map<string, Binding>;
  returns: AbstractValue[];
  stopped: boolean;
  stopReason?: "return" | "break" | "continue";
  writes: Set<string>;
}
export interface BoundedCodeHost {
  evaluate(ast: Ast): AbstractValue;
  literal(value: unknown): AbstractValue;
  union(values: AbstractValue[]): AbstractValue;
  project(value: AbstractValue, path: string[]): AbstractValue;
  unknown(code: string, values: AbstractValue[]): AbstractValue;
  input(): AbstractValue;
  bounded(): boolean;
}

const sourceRoots = new Set([
  "$json",
  "$input",
  "$node",
  "$env",
  "$credentials",
  "$",
]);
const classifiedName =
  /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|email|phone|mobile|ssn|birth|address|full[_-]?name)/i;
const namedFact = (name: string, value: Ast): Ast => ({
  type: "ObjectExpression",
  properties: [
    {
      type: "Property",
      kind: "init",
      computed: false,
      key: { type: "Literal", value: name },
      value,
    },
  ],
});

function sourceScopeBindings(node: Ast): Set<string> {
  const names = new Set<string>();
  const bind = (pattern: unknown): void => {
    if (!object(pattern)) return;
    if (pattern.type === "Identifier" && sourceRoots.has(String(pattern.name)))
      names.add(String(pattern.name));
    else if (
      pattern.type === "ObjectPattern" &&
      Array.isArray(pattern.properties)
    ) {
      for (const item of pattern.properties)
        if (object(item))
          bind(item.type === "RestElement" ? item.argument : item.value);
    } else if (
      pattern.type === "ArrayPattern" &&
      Array.isArray(pattern.elements)
    ) {
      for (const item of pattern.elements) bind(item);
    } else if (pattern.type === "AssignmentPattern") bind(pattern.left);
    else if (pattern.type === "RestElement") bind(pattern.argument);
  };
  const declaration = (item: unknown): void => {
    if (!object(item)) return;
    if (
      item.type === "VariableDeclaration" &&
      Array.isArray(item.declarations)
    ) {
      for (const value of item.declarations) if (object(value)) bind(value.id);
    } else if (
      ["FunctionDeclaration", "ClassDeclaration"].includes(String(item.type))
    )
      bind(item.id);
  };
  if (
    ["Program", "BlockStatement"].includes(String(node.type)) &&
    Array.isArray(node.body)
  ) {
    for (const item of node.body) declaration(item);
  }
  if (
    [
      "FunctionDeclaration",
      "FunctionExpression",
      "ArrowFunctionExpression",
    ].includes(String(node.type))
  ) {
    if (Array.isArray(node.params))
      for (const param of node.params) bind(param);
    bind(node.id);
  }
  if (["ClassDeclaration", "ClassExpression"].includes(String(node.type)))
    bind(node.id);
  if (
    [
      "Program",
      "FunctionDeclaration",
      "FunctionExpression",
      "ArrowFunctionExpression",
    ].includes(String(node.type))
  ) {
    // var is function-scoped even inside a nested block. Nested functions and
    // classes introduce separate scopes and must not hide this scope's roots.
    const pending: unknown[] = Array.isArray(node.body)
      ? [...node.body]
      : [node.body];
    let visits = 0;
    while (pending.length && visits++ < 2048) {
      const item = pending.pop();
      if (!object(item)) continue;
      if (
        [
          "FunctionDeclaration",
          "FunctionExpression",
          "ArrowFunctionExpression",
          "ClassDeclaration",
          "ClassExpression",
        ].includes(String(item.type))
      )
        continue;
      if (item.type === "VariableDeclaration" && item.kind === "var")
        declaration(item);
      for (const child of Object.values(item)) {
        if (Array.isArray(child)) pending.push(...child);
        else if (object(child)) pending.push(child);
      }
    }
  }
  if (node.type === "CatchClause") bind(node.param);
  if (node.type === "ForStatement") declaration(node.init);
  if (["ForInStatement", "ForOfStatement"].includes(String(node.type)))
    declaration(node.left);
  return names;
}

/** These are observations, never a binding, execution, shape or guard proof. */
export function opaqueCodeObservation(
  host: BoundedCodeHost,
  code: string,
  values: AbstractValue[],
): AbstractValue {
  return {
    ...host.unknown(code, values),
    constant: undefined,
    fields: undefined,
    fieldsComplete: false,
    fullObject: true,
    guards: [],
    presence: "unknown",
    trust: "unknown",
  };
}

/** Tokenization recovers only literal fields and direct references before a
 * syntax/length/token limit. Comments and ordinary string contents are not code. */
export function observeInvalidCode(
  source: string,
  host: BoundedCodeHost,
  code: string,
  prior: AbstractValue[] = [],
): AbstractValue {
  const values = [...prior];
  const tokens: (Token & { value?: unknown })[] = [];
  let limited = source.length > 65536;
  try {
    const stream = tokenizer(source.slice(0, 65536), { ecmaVersion: "latest" });
    for (let index = 0; index < 4096; index++) {
      const token = stream.getToken();
      if (token.type.label === "eof") break;
      tokens.push(token);
      if (index === 4095) limited = true;
    }
  } catch {
    values.push(host.unknown("code_token_observation_incomplete", []));
  }
  let facts = 0;
  const uncertainBindings = new Set<string>();
  const tokenLabel = (index: number): string | undefined =>
    tokens[index]?.type.label === "name" && tokens[index]?.value === "let"
      ? "let"
      : tokens[index]?.type.label;
  for (const [index, token] of tokens.entries()) {
    if (token.type.label !== "name" || !sourceRoots.has(String(token.value)))
      continue;
    const before = tokenLabel(index - 1);
    const after = tokens[index + 1]?.type.label;
    if (
      ["const", "let", "var", "function", "class"].includes(before ?? "") ||
      (["(", ","].includes(before ?? "") &&
        [")", ",", "="].includes(after ?? "")) ||
      (((before === "{" && after === "}") ||
        (before === "[" && after === "]")) &&
        ["const", "let", "var"].includes(tokenLabel(index - 2) ?? "")) ||
      (before === ":" && ["}", ",", "="].includes(after ?? ""))
    )
      uncertainBindings.add(String(token.value));
  }
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (facts >= 256) {
      limited = true;
      break;
    }
    if (
      token.type.label === "name" &&
      sourceRoots.has(String(token.value)) &&
      !uncertainBindings.has(String(token.value)) &&
      tokens[index + 1]?.type.label !== ":" &&
      ![".", "?."].includes(tokens[index - 1]?.type.label ?? "") &&
      ([".", "["].includes(tokens[index + 1]?.type.label ?? "") ||
        ["=", "return", "=>"].includes(tokens[index - 1]?.type.label ?? ""))
    ) {
      let ast: Ast = { type: "Identifier", name: token.value };
      let cursor = index + 1;
      for (let depth = 0; depth < 32; depth++) {
        if (
          tokens[cursor]?.type.label === "." &&
          tokens[cursor + 1]?.type.label === "name"
        ) {
          ast = {
            type: "MemberExpression",
            computed: false,
            object: ast,
            property: { type: "Identifier", name: tokens[cursor + 1]!.value },
          };
          cursor += 2;
        } else if (
          tokens[cursor]?.type.label === "[" &&
          ["string", "num"].includes(tokens[cursor + 1]?.type.label ?? "") &&
          tokens[cursor + 2]?.type.label === "]"
        ) {
          ast = {
            type: "MemberExpression",
            computed: true,
            object: ast,
            property: { type: "Literal", value: tokens[cursor + 1]!.value },
          };
          cursor += 3;
        } else break;
      }
      values.push(host.evaluate(ast));
      facts++;
    }
    if (
      ["name", "string"].includes(token.type.label) &&
      classifiedName.test(String(token.value)) &&
      tokens[index + 1]?.type.label === ":" &&
      ["string", "num"].includes(tokens[index + 2]?.type.label ?? "")
    ) {
      values.push(
        host.evaluate(
          namedFact(String(token.value), {
            type: "Literal",
            value: tokens[index + 2]!.value,
          }),
        ),
      );
      facts++;
    } else if (
      ["string", "template"].includes(token.type.label) &&
      typeof token.value === "string" &&
      token.value.includes("@")
    ) {
      values.push(host.literal(token.value));
      facts++;
    }
  }
  if (limited) values.push(host.unknown("code_source_observation_limit", []));
  if (uncertainBindings.size)
    values.push(host.unknown("code_source_binding_unresolved", []));
  values.push(host.input(), host.unknown("code_source_observations_only", []));
  return opaqueCodeObservation(host, code, values);
}

/** A bounded abstract transfer interpreter. No submitted function is invoked. */
export function analyzeBoundedCode(
  program: Ast,
  host: BoundedCodeHost,
): AbstractValue {
  const pending: {
    value: unknown;
    parent?: Ast;
    field?: string;
    binding?: boolean;
    shadowed?: Set<string>;
  }[] = [{ value: program }];
  const sourceFacts: Ast[] = [];
  let syntaxNodes = 0;
  let unsupported = false;
  let observationLimited = false;
  let astLimited = false;
  let bindingUnresolved = false;
  const fact = (value: Ast): void => {
    if (sourceFacts.length < 256) sourceFacts.push(value);
    else observationLimited = true;
  };
  while (pending.length) {
    const frame = pending.pop()!;
    const value = frame.value;
    if (!object(value)) continue;
    const shadowed = new Set([
      ...(frame.shadowed ?? []),
      ...sourceScopeBindings(value),
    ]);
    if (typeof value.type === "string" && ++syntaxNodes > 2048) {
      astLimited = true;
      break;
    }
    if (value.type === "MemberExpression") {
      let root = value;
      while (object(root.object) || object(root.callee))
        root = (object(root.object) ? root.object : root.callee) as Ast;
      if (
        root.type === "Identifier" &&
        ["$json", "$input", "$node", "$env", "$credentials", "$"].includes(
          String(root.name),
        )
      ) {
        if (shadowed.has(String(root.name))) bindingUnresolved = true;
        else fact(value);
      }
    } else if (
      value.type === "Literal" &&
      typeof value.value === "string" &&
      /@/.test(value.value)
    )
      fact(value);
    if (
      value.type === "TemplateElement" &&
      object(value.value) &&
      typeof value.value.cooked === "string" &&
      value.value.cooked.includes("@")
    )
      fact({ type: "Literal", value: value.value.cooked });
    if (
      value.type === "Identifier" &&
      ["$env", "$credentials"].includes(String(value.name)) &&
      !shadowed.has(String(value.name)) &&
      !frame.binding &&
      !(frame.field === "key" && frame.parent?.computed !== true) &&
      !(frame.field === "property" && frame.parent?.computed !== true)
    )
      fact(value);
    if (
      value.type === "Property" &&
      value.computed !== true &&
      object(value.key) &&
      object(value.value)
    ) {
      const name = value.key.name ?? value.key.value;
      if (typeof name === "string" && classifiedName.test(name))
        fact(
          namedFact(
            name,
            value.value.type === "Literal"
              ? value.value
              : { type: "Literal", value: null },
          ),
        );
    }
    if (
      ([
        "FunctionDeclaration",
        "FunctionExpression",
        "ArrowFunctionExpression",
      ].includes(String(value.type)) &&
        value.async === true) ||
      [
        "ForStatement",
        "ForInStatement",
        "WhileStatement",
        "DoWhileStatement",
        "SwitchStatement",
        "YieldExpression",
        "ClassDeclaration",
        "WithStatement",
        "ImportExpression",
      ].includes(String(value.type))
    )
      unsupported = true;
    for (const [field, child] of Object.entries(value).reverse()) {
      const binding =
        frame.binding ||
        field === "params" ||
        (field === "id" &&
          [
            "VariableDeclarator",
            "FunctionDeclaration",
            "FunctionExpression",
            "ClassDeclaration",
          ].includes(String(value.type))) ||
        (field === "param" && value.type === "CatchClause");
      if (Array.isArray(child))
        pending.push(
          ...child
            .slice()
            .reverse()
            .map((item) => ({
              value: item,
              parent: value,
              field,
              binding,
              shadowed,
            })),
        );
      else if (object(child))
        pending.push({ value: child, parent: value, field, binding, shadowed });
    }
  }
  // Observe before transfer work can consume the shared request budget.
  const observedSources = sourceFacts.map((ast) => host.evaluate(ast));
  if (observationLimited)
    observedSources.push(host.unknown("code_source_observation_limit", []));
  if (bindingUnresolved)
    observedSources.push(host.unknown("code_source_binding_unresolved", []));
  if (unsupported || astLimited) {
    if (unsupported && astLimited)
      observedSources.push(
        host.unknown("code_statement_profile_unresolved", []),
      );
    return opaqueCodeObservation(
      host,
      astLimited
        ? "code_ast_profile_limit"
        : "code_statement_profile_unresolved",
      [
        ...observedSources,
        host.input(),
        host.unknown("code_source_observations_only", []),
      ],
    );
  }
  let opaque = false;
  let objectMutation = false;
  let exceptionFlow = false;
  let steps = 0;
  let nextObjectId = 0;
  let shapeWork = 0;
  const functions = new Map<string, Ast>();
  const functionConstants = new WeakMap<Ast, Map<string, Binding>>();
  const captureConstants = (fn: Ast, state: State): void => {
    const selfName =
      fn.type === "FunctionExpression" && object(fn.id)
        ? fn.id.name
        : undefined;
    const captured = [...state.env].filter(
      ([name, binding]) =>
        name !== selfName &&
        !binding.mutable &&
        !binding.owned &&
        !binding.value.fullObject &&
        !binding.value.fields &&
        binding.value.status === "resolved" &&
        binding.value.constant !== undefined,
    );
    // Only lexical immutable primitive values are supported. Mutable bindings
    // and object captures retain the opaque profile; caller parameters cannot
    // substitute for a function's defining environment.
    if (captured.length <= 128)
      functionConstants.set(
        fn,
        new Map(
          captured.map(([name, binding]) => [name, structuredClone(binding)]),
        ),
      );
  };
  const embeddedObjects = new Set<number>();
  const loopExitStack: State[][] = [];
  const diagnosticValues: AbstractValue[] = [];
  const observedValues: AbstractValue[] = [];
  const unknown = (
    code: string,
    values: AbstractValue[] = [],
  ): AbstractValue => {
    const value = host.unknown(code, values);
    diagnosticValues.push(value);
    return value;
  };
  const limit = (): boolean => {
    if (++steps <= 2048 && host.bounded()) return true;
    opaque = true;
    unknown("code_transfer_budget_exceeded");
    return false;
  };
  const clone = (state: State): State => {
    const fits = shapeFits(
      [...state.env.values()].map((binding) => binding.value),
    );
    if (!fits) opaque = true;
    return {
      env: new Map(
        [...state.env].map(([name, binding]) => [
          name,
          fits
            ? structuredClone(binding)
            : {
                ...binding,
                value: unknown("code_value_shape_limit", [binding.value]),
                owned: false,
                objectId: undefined,
              },
        ]),
      ),
      returns: [...state.returns],
      stopped: state.stopped,
      stopReason: state.stopReason,
      writes: new Set(state.writes),
    };
  };
  // Count repeated paths, not just unique references: later serialization and
  // structuredClone would otherwise expand a small shared graph exponentially.
  const shapeFits = (values: AbstractValue[]): boolean => {
    const pending = values.map((value) => ({ value, depth: 0 }));
    let nodes = 0;
    while (pending.length) {
      const { value, depth } = pending.pop()!;
      if (++nodes > 512 || ++shapeWork > 16384 || depth > 32) return false;
      if (value.fields)
        pending.push(
          ...Object.values(value.fields).map((child) => ({
            value: child,
            depth: depth + 1,
          })),
        );
      if (value.representativeElement)
        pending.push({ value: value.representativeElement, depth: depth + 1 });
      for (const alternative of [
        ...(value.projectionAlternatives ?? []),
        ...(value.projectionDependencies ?? []),
      ])
        pending.push({ value: alternative, depth: depth + 1 });
    }
    return true;
  };
  const madeObject = (fields: Record<string, AbstractValue>): AbstractValue => {
    const values = Object.values(fields);
    if (!shapeFits(values)) {
      opaque = true;
      return unknown("code_value_shape_limit", values);
    }
    return host.evaluate({
      type: "ObjectExpression",
      properties: Object.entries(fields).map(([name, value]) => ({
        type: "Property",
        kind: "init",
        computed: false,
        key: { type: "Literal", value: name },
        value: marker(value),
      })),
    });
  };
  const array = (items: AbstractValue[]): AbstractValue => {
    if (items.length > 128) return unknown("flow_field_limit", items);
    if (!shapeFits(items)) {
      opaque = true;
      return unknown("code_value_shape_limit", items);
    }
    return host.evaluate({
      type: "ArrayExpression",
      elements: items.map(marker),
    });
  };
  const candidate = (value: AbstractValue, index = false): AbstractValue => {
    const origins = value.origins.map((origin) =>
      origin.kind === "literal"
        ? origin
        : {
            ...origin,
            includesDescendants: true as const,
            descendantPath: origin.projectionUnknown
              ? origin.descendantPath
              : [...(origin.descendantPath ?? []), ...(index ? [null] : [])],
          },
    );
    return {
      ...value,
      origins,
      valueId: createHash("sha256")
        .update(
          JSON.stringify(["code_collection_candidate", value.valueId, origins]),
        )
        .digest("hex"),
    };
  };
  const collection = (
    item: AbstractValue,
    code = "code_collection_cardinality_unverified",
  ): AbstractValue => {
    if (!shapeFits([item])) {
      opaque = true;
      return unknown("code_value_shape_limit", [item]);
    }
    const representative = candidate(item);
    return {
      ...unknown(code, [representative]),
      representativeElement: representative,
      constant: undefined,
      fields: undefined,
      fieldsComplete: false,
      fullObject: true,
      guards: [],
      valueId: createHash("sha256")
        .update(
          JSON.stringify(["code_collection_summary", representative.valueId]),
        )
        .digest("hex"),
    };
  };
  const builtinResult = (values: AbstractValue[]): AbstractValue => ({
    ...unknown("code_builtin_result_unverified", values),
    constant: undefined,
    fields: undefined,
    fieldsComplete: false,
    fullObject: false,
    presence: "unknown",
    guards: [],
  });
  const knownCollection = (value: AbstractValue): boolean =>
    Boolean(value.representativeElement) ||
    (value.fullObject &&
      value.fieldsComplete === true &&
      Boolean(value.fields) &&
      Object.keys(value.fields!).every((key) =>
        /^\/(?:0|[1-9]\d*)$/.test(key),
      )) ||
    (value.fullObject &&
      value.diagnosticCodes.includes("string_split_cardinality_unverified")) ||
    Boolean(value.projectionAlternatives?.every(knownCollection));
  const projectField = (value: AbstractValue, key: string): AbstractValue => {
    const projected = host.project(value, [key]);
    if (
      specialKeys.has(key) ||
      projected.status === "resolved" ||
      !value.diagnosticCodes.includes("code_collection_shape_unverified")
    )
      return projected;
    // An unknown representative has no proven array index or object shape.
    // A subsequent named read can still be a sensitive field candidate. Reuse
    // the existing field-name classifier without inventing an exact source
    // index: origins remain the known collection prefix and status stays partial.
    const classified = host.project(madeObject({ [key]: projected }), [key]);
    return {
      ...classified,
      constant: undefined,
      fields: undefined,
      fieldsComplete: false,
      presence: "unknown",
      guards: [],
    };
  };
  const embedReferences = (ast: Ast, state: State): void => {
    const pending: unknown[] = [ast];
    while (pending.length) {
      const node = pending.pop();
      if (!object(node)) continue;
      if (node.type === "Identifier") {
        const id = state.env.get(String(node.name))?.objectId;
        if (id !== undefined) embeddedObjects.add(id);
      }
      for (const child of Object.values(node)) {
        if (Array.isArray(child)) pending.push(...child);
        else if (object(child)) pending.push(child);
      }
    }
  };
  const choice = (values: AbstractValue[], depth = 0): AbstractValue => {
    if (!values.length) return host.literal(undefined);
    if (!shapeFits(values)) {
      opaque = true;
      return unknown("code_value_shape_limit", values);
    }
    if (values.length === 1) return structuredClone(values[0]!);
    if (
      depth < 8 &&
      values.every((value) => value.fields && value.fieldsComplete === true)
    ) {
      const keys = [
        ...new Set(values.flatMap((value) => Object.keys(value.fields!))),
      ];
      if (keys.length <= 128) {
        const fields: Record<string, AbstractValue> = Object.create(null);
        for (const key of keys) {
          const entries = values.map((value) => value.fields![key]);
          fields[key.slice(1).replace(/~1/g, "/").replace(/~0/g, "~")] =
            entries.every(Boolean)
              ? choice(entries as AbstractValue[], depth + 1)
              : (() => {
                  const possible = choice(
                    entries.filter(Boolean) as AbstractValue[],
                    depth + 1,
                  );
                  return {
                    ...preserveValueShape(
                      unknown("code_branch_field_optional", [possible]),
                      possible,
                    ),
                    presence: "unknown" as const,
                    representativeSelection: true,
                    constant: undefined,
                    guards: [],
                  };
                })();
        }
        return madeObject(fields);
      }
    }
    const value = host.union(values);
    value.guards = [];
    if (
      values.every(
        (item) =>
          Object.hasOwn(item, "constant") &&
          Object.is(item.constant, values[0]!.constant),
      )
    )
      value.constant = values[0]!.constant;
    return value;
  };
  const element = (value: AbstractValue): AbstractValue => {
    if (value.projectionAlternatives) {
      const possible = choice(value.projectionAlternatives.map(element));
      const dependencies = value.projectionDependencies ?? [];
      return dependencies.length
        ? {
            ...preserveValueShape(
              unknown("code_collection_shape_unverified", [
                possible,
                ...dependencies,
              ]),
              possible,
            ),
            projectionDependencies: [
              ...(possible.projectionDependencies ?? []),
              ...dependencies,
            ],
          }
        : possible;
    }
    if (value.representativeElement)
      return structuredClone(value.representativeElement);
    const candidateSubtree = {
      ...candidate(value, true),
      constant: undefined,
      guards: [],
      fieldsComplete: false,
    };
    if (value.fields && value.fieldsComplete === true) {
      const entries = Object.entries(value.fields).filter(([key]) =>
        /^\/\d+$/.test(key),
      );
      if (entries.length && !value.diagnosticCodes.includes("flow_field_limit"))
        return choice(entries.map(([, item]) => candidate(item)));
      if (!Object.keys(value.fields).length)
        return unknown("code_collection_empty_or_unavailable", [
          candidateSubtree,
        ]);
    }
    // Unknown reindexing may select any descendant. Preserve the same bounded
    // candidate-subtree marker used by Aggregate so explicit source policy
    // classifications survive later scalar projections without asserting /0.
    return unknown("code_collection_shape_unverified", [candidateSubtree]);
  };
  const mergeState = (base: State, branches: State[]): void => {
    for (const branch of branches)
      for (const name of branch.writes) base.writes.add(name);
    const continuing = branches.filter((state) => !state.stopped);
    for (const [name, binding] of base.env) {
      const candidates = continuing.map(
        (state) => state.env.get(name)?.value ?? binding.value,
      );
      if (candidates.length) {
        binding.value = choice(candidates);
        if (
          !continuing.every((state) => {
            const branchBinding = state.env.get(name);
            return (
              branchBinding?.owned === true &&
              branchBinding.objectId !== undefined &&
              branchBinding.objectId === binding.objectId
            );
          })
        ) {
          binding.owned = false;
          binding.objectId = undefined;
        }
      }
    }
    base.returns = [
      ...new Map(
        branches
          .flatMap((state) => state.returns)
          .map((value) => [value.valueId, value]),
      ).values(),
    ];
    base.stopped = continuing.length === 0;
    base.stopReason =
      base.stopped &&
      branches.length > 0 &&
      branches.every((state) => state.stopReason === branches[0]!.stopReason)
        ? branches[0]!.stopReason
        : undefined;
  };
  const callFunction = (
    fn: Ast,
    args: AbstractValue[],
    state: State,
    depth: number,
  ): AbstractValue => {
    if (
      depth > 6 ||
      !Array.isArray(fn.params) ||
      fn.params.length > 4 ||
      !object(fn.body)
    ) {
      opaque = true;
      return unknown("code_function_profile_unresolved", args);
    }
    const parameters = new Set(
      fn.params.filter(object).map((param) => param.name),
    );
    const selfName =
      fn.type === "FunctionExpression" && object(fn.id)
        ? fn.id.name
        : undefined;
    const lexicalConstants =
      functionConstants.get(fn) ?? new Map<string, Binding>();
    let selfReferenced = false;
    const pending: unknown[] = [fn.body];
    while (pending.length) {
      const part = pending.pop();
      if (!object(part)) continue;
      if (
        part.type === "Identifier" &&
        typeof selfName === "string" &&
        part.name === selfName &&
        !parameters.has(selfName)
      ) {
        selfReferenced = true;
        continue;
      }
      if (
        part.type === "Identifier" &&
        typeof part.name === "string" &&
        state.env.has(part.name) &&
        !parameters.has(part.name) &&
        !lexicalConstants.has(part.name)
      ) {
        opaque = true;
        return unknown("code_closure_capture_unresolved", [
          ...args,
          ...[...state.env.values()].map((binding) => binding.value),
          ...observedValues,
        ]);
      }
      for (const [key, child] of Object.entries(part)) {
        if (
          (part.type === "MemberExpression" &&
            key === "property" &&
            part.computed !== true) ||
          (part.type === "Property" && key === "key" && part.computed !== true)
        )
          continue;
        if (Array.isArray(child)) pending.push(...child);
        else if (object(child)) pending.push(child);
      }
    }
    const child = clone(state);
    for (const [name, binding] of lexicalConstants)
      child.env.set(name, structuredClone(binding));
    if (selfReferenced && typeof selfName === "string") {
      // The named function's own binding is not the caller's same-named
      // primitive. Keep it unknown while still observing the bounded body,
      // including sensitive properties read through callback arguments.
      child.env.set(selfName, {
        value: unknown("code_function_self_binding_unresolved"),
        mutable: false,
        owned: false,
      });
    }
    child.returns = [];
    child.stopped = false;
    for (const [index, param] of fn.params.entries()) {
      if (
        !object(param) ||
        param.type !== "Identifier" ||
        typeof param.name !== "string" ||
        roots.has(param.name)
      ) {
        opaque = true;
        return unknown("code_parameter_binding_unresolved", args);
      }
      child.env.set(param.name, {
        value: args[index] ?? host.literal(undefined),
        mutable: true,
        owned: false,
      });
    }
    const closureBefore = new Map(
      [...child.env].map(([name, binding]) => [name, binding.value.valueId]),
    );
    if (fn.body.type === "BlockStatement" && Array.isArray(fn.body.body))
      execute(fn.body.body, child, depth + 1);
    else child.returns.push(expression(fn.body, child, depth + 1));
    // Writes through a closure are outside the pure helper profile.
    for (const [name, before] of closureBefore) {
      if (
        !fn.params.some((param) => object(param) && param.name === name) &&
        child.env.get(name)?.value.valueId !== before
      ) {
        opaque = true;
        return unknown("code_closure_mutation_unresolved", [
          ...(state.env.get(name) ? [state.env.get(name)!.value] : []),
          ...child.returns,
          ...[...child.env.values()].map((binding) => binding.value),
        ]);
      }
    }
    if (selfReferenced) opaque = true;
    return choice(child.returns);
  };
  const expression = (ast: Ast, state: State, depth = 0): AbstractValue => {
    if (!limit() || depth > 48) return unknown("code_transfer_budget_exceeded");
    if (ast.type === "Identifier") {
      if (typeof ast.name !== "string")
        return unknown("code_identifier_unresolved");
      const local = state.env.get(ast.name);
      if (local) {
        if (!shapeFits([local.value])) {
          opaque = true;
          return unknown("code_value_shape_limit", [local.value]);
        }
        return structuredClone(local.value);
      }
      if (ast.name === "undefined") return host.literal(undefined);
      if (roots.has(ast.name)) return host.evaluate(ast);
      opaque = true;
      return unknown("code_identifier_unresolved");
    }
    if (ast.type === "Literal") return host.evaluate(ast);
    if (
      ast.type === "NewExpression" &&
      object(ast.callee) &&
      ast.callee.type === "Identifier" &&
      ast.callee.name === "Date" &&
      !state.env.has("Date") &&
      !functions.has("Date") &&
      Array.isArray(ast.arguments) &&
      ast.arguments.length <= 1 &&
      ast.arguments.every(
        (argument) => object(argument) && argument.type !== "SpreadElement",
      )
    )
      return builtinResult(
        ast.arguments.length
          ? ast.arguments.map((argument) =>
              expression(argument as Ast, state, depth + 1),
            )
          : [host.literal(undefined)],
      );
    if (ast.type === "AwaitExpression" && object(ast.argument)) {
      const input = expression(ast.argument, state, depth + 1);
      const value = unknown("code_await_result_unverified", [input]);
      // Thenable resolution, rejection and scheduling remain unknown. Merely
      // parsing n8n's async wrapper does not run the operation or prove success.
      return {
        ...value,
        constant: undefined,
        fields: undefined,
        fieldsComplete: false,
        fullObject: true,
        presence: "unknown",
        trust: "unknown",
        guards: [],
      };
    }
    if (
      ast.type === "ChainExpression" ||
      ast.type === "ParenthesizedExpression"
    ) {
      if (!object(ast.expression)) return unknown("code_expression_unresolved");
      const value = expression(ast.expression, state, depth + 1);
      if (ast.type === "ChainExpression") {
        value.presence = "unknown";
        value.guards = [];
      }
      return value;
    }
    if (ast.type === "ObjectExpression" && Array.isArray(ast.properties)) {
      embedReferences(ast, state);
      let fields: Record<string, AbstractValue> = Object.create(null);
      const uncertain: AbstractValue[] = [];
      for (const property of ast.properties) {
        if (!object(property)) {
          opaque = true;
          continue;
        }
        if (property.type === "SpreadElement" && object(property.argument)) {
          const spread = expression(property.argument, state, depth + 1);
          if (spread.fields && spread.fieldsComplete === true) {
            for (const [key, value] of Object.entries(spread.fields))
              fields[key.slice(1).replace(/~1/g, "/").replace(/~0/g, "~")] =
                value;
          } else {
            uncertain.push(spread);
            fields = Object.create(null);
          }
          continue;
        }
        if (
          property.type !== "Property" ||
          property.kind !== "init" ||
          property.method === true ||
          !object(property.key) ||
          !object(property.value)
        ) {
          opaque = true;
          continue;
        }
        const name =
          property.computed === true
            ? property.key.type === "Literal"
              ? property.key.value
              : undefined
            : (property.key.name ?? property.key.value);
        if (typeof name !== "string" && typeof name !== "number") {
          opaque = true;
          unknown("code_object_key_unresolved", [
            expression(property.key, state, depth + 1),
            expression(property.value, state, depth + 1),
          ]);
          continue;
        }
        if (specialKeys.has(String(name))) {
          opaque = true;
          unknown("code_prototype_semantics_unresolved", [
            expression(property.value, state, depth + 1),
          ]);
          continue;
        }
        fields[String(name)] = expression(property.value, state, depth + 1);
      }
      const value = madeObject(fields);
      if (ast.properties.length > 128)
        return unknown("flow_field_limit", [value, ...Object.values(fields)]);
      if (uncertain.length) {
        const result = unknown("code_spread_shape_unverified", [
          value,
          ...uncertain,
        ]);
        return {
          ...result,
          fields: value.fields,
          fieldsComplete: false,
          fullObject: true,
        };
      }
      return value;
    }
    if (ast.type === "ArrayExpression" && Array.isArray(ast.elements)) {
      embedReferences(ast, state);
      const values: AbstractValue[] = [];
      let spread = false;
      for (const item of ast.elements) {
        if (
          object(item) &&
          item.type === "SpreadElement" &&
          object(item.argument)
        ) {
          spread = true;
          values.push(element(expression(item.argument, state, depth + 1)));
        } else
          values.push(
            object(item)
              ? expression(item, state, depth + 1)
              : host.literal(null),
          );
      }
      return spread
        ? collection(choice(values), "code_array_spread_shape_unverified")
        : array(values);
    }
    if (ast.type === "MemberExpression" && object(ast.object)) {
      // Let the existing reference parser retain exact n8n source paths.
      let root = ast.object;
      while (root.type === "MemberExpression" && object(root.object))
        root = root.object;
      if (
        (root.type === "Identifier" &&
          roots.has(String(root.name)) &&
          !state.env.has(String(root.name))) ||
        root.type === "CallExpression"
      ) {
        const name =
          root.type === "CallExpression" &&
          object(root.callee) &&
          object(root.callee.object)
            ? root.callee.object.name
            : undefined;
        if (
          root.type === "Identifier" ||
          name === "$input" ||
          (object(root.callee) &&
            ["first", "last", "all"].includes(keyOf(root.callee) ?? "") &&
            object(root.callee.object) &&
            object(root.callee.object.callee) &&
            root.callee.object.callee.name === "$") ||
          (object(root.callee) && root.callee.name === "$")
        )
          return host.evaluate(ast);
      }
      const receiver = expression(ast.object, state, depth + 1);
      const key = keyOf(ast);
      if (key !== undefined) return projectField(receiver, key);
      const index = object(ast.property)
        ? expression(ast.property, state, depth + 1)
        : host.literal(undefined);
      if (
        index.status === "resolved" &&
        (typeof index.constant === "string" ||
          typeof index.constant === "number")
      )
        return projectField(receiver, String(index.constant));
      return unknown("code_dynamic_index_unresolved", [receiver, index]);
    }
    if (
      ast.type === "CallExpression" &&
      object(ast.callee) &&
      Array.isArray(ast.arguments)
    ) {
      const callee = ast.callee;
      const method = keyOf(callee);
      if (
        callee.type === "MemberExpression" &&
        callee.computed !== true &&
        object(callee.object) &&
        callee.object.type === "Identifier" &&
        typeof callee.object.name === "string" &&
        !state.env.has(callee.object.name) &&
        !functions.has(callee.object.name) &&
        ast.arguments.every(
          (argument) => object(argument) && argument.type !== "SpreadElement",
        )
      ) {
        const owner = callee.object.name;
        const count = ast.arguments.length;
        const accepted =
          (owner === "Math" &&
            ((["floor", "ceil", "round", "trunc", "abs"].includes(
              method ?? "",
            ) &&
              count === 1) ||
              (["min", "max"].includes(method ?? "") &&
                count > 0 &&
                count <= 16))) ||
          (owner === "Date" &&
            ((method === "parse" && count === 1) ||
              (method === "now" && count === 0))) ||
          (owner === "Number" &&
            ["isFinite", "isInteger", "isNaN", "isSafeInteger"].includes(
              method ?? "",
            ) &&
            count === 1);
        if (accepted)
          return builtinResult(
            count
              ? ast.arguments.map((argument) =>
                  expression(argument as Ast, state, depth + 1),
                )
              : [host.literal(undefined)],
          );
      }
      if (
        callee.type === "MemberExpression" &&
        callee.computed !== true &&
        object(callee.object) &&
        ["join", "slice", "pop", "match"].includes(method ?? "") &&
        ast.arguments.every(
          (argument) => object(argument) && argument.type !== "SpreadElement",
        )
      ) {
        const receiver = expression(callee.object, state, depth + 1);
        const args = ast.arguments.map((argument) =>
          expression(argument as Ast, state, depth + 1),
        );
        if (method === "join" && args.length <= 1 && knownCollection(receiver))
          return builtinResult([receiver, ...args]);
        if (
          method === "slice" &&
          args.length <= 2 &&
          knownCollection(receiver)
        ) {
          const selected = collection(element(receiver));
          if (!args.length) return selected;
          const dependency = builtinResult(args);
          return {
            ...preserveValueShape(
              unknown("code_collection_cardinality_unverified", [
                selected,
                dependency,
              ]),
              selected,
            ),
            projectionDependencies: [dependency],
          };
        }
        // pop mutates its receiver. Only a fresh, unaliased split result is
        // accepted; general array aliases keep the existing opaque profile.
        if (
          method === "pop" &&
          !args.length &&
          callee.object.type === "CallExpression" &&
          object(callee.object.callee) &&
          callee.object.callee.type === "MemberExpression" &&
          callee.object.callee.computed !== true &&
          keyOf(callee.object.callee) === "split" &&
          knownCollection(receiver)
        )
          return builtinResult([receiver]);
        if (
          method === "match" &&
          args.length === 1 &&
          object(ast.arguments[0]) &&
          ast.arguments[0].type === "Literal" &&
          object(ast.arguments[0].regex)
        )
          return collection(builtinResult([receiver, ...args]));
        if (method === "slice" && args.length <= 2)
          return host.evaluate({
            ...ast,
            callee: { ...callee, object: marker(receiver) },
            arguments: args.map(marker),
          });
        opaque = true;
        return unknown("code_call_effect_unresolved", [receiver, ...args]);
      }
      if (
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        callee.object.type === "Identifier" &&
        callee.object.name === "$input" &&
        method === "all" &&
        !ast.arguments.length
      ) {
        return collection(madeObject({ json: host.input() }));
      }
      if (
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        callee.object.type === "Identifier" &&
        callee.object.name === "$input" &&
        ["first", "last"].includes(method ?? "") &&
        !ast.arguments.length
      )
        return madeObject({ json: host.input() });
      if (
        callee.type === "Identifier" &&
        typeof callee.name === "string" &&
        functions.has(callee.name) &&
        !state.env.has(callee.name)
      ) {
        for (const arg of ast.arguments)
          if (object(arg)) embedReferences(arg, state);
        const args = ast.arguments.map((arg) =>
          object(arg)
            ? expression(arg, state, depth + 1)
            : host.literal(undefined),
        );
        return callFunction(
          functions.get(callee.name)!,
          args,
          state,
          depth + 1,
        );
      }
      if (
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        method === "filter" &&
        ast.arguments.length === 1 &&
        object(ast.arguments[0]) &&
        ast.arguments[0].type === "Identifier" &&
        ast.arguments[0].name === "Boolean" &&
        !state.env.has("Boolean") &&
        !functions.has("Boolean")
      ) {
        // Truthiness does not validate, sanitize or establish any field. Keep
        // one representative of all possible survivors; filtering shifts the
        // indices, so the original array's exact fields cannot be retained.
        const receiver = expression(callee.object, state, depth + 1);
        return collection(element(receiver));
      }
      if (
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        ["map", "filter", "forEach", "some", "every", "flatMap"].includes(
          method ?? "",
        ) &&
        ast.arguments.length === 1 &&
        object(ast.arguments[0]) &&
        (["ArrowFunctionExpression", "FunctionExpression"].includes(
          String(ast.arguments[0].type),
        ) ||
          (ast.arguments[0].type === "Identifier" &&
            typeof ast.arguments[0].name === "string" &&
            functions.has(ast.arguments[0].name) &&
            !state.env.has(ast.arguments[0].name)))
      ) {
        const callback =
          ast.arguments[0].type === "Identifier"
            ? functions.get(String(ast.arguments[0].name))!
            : ast.arguments[0];
        const receiver = expression(callee.object, state, depth + 1);
        const item = element(receiver);
        const args = [item];
        if (Array.isArray(callback.params) && callback.params.length > 1)
          args.push(unknown("code_collection_index_unverified"));
        if (Array.isArray(callback.params) && callback.params.length > 2)
          args.push(receiver);
        // Named helpers retain their defining environment. Re-capturing here
        // would incorrectly turn the caller's shadowed variable into a closure.
        if (ast.arguments[0].type !== "Identifier")
          captureConstants(callback, state);
        const mapped = callFunction(callback, args, state, depth + 1);
        if (method === "filter") {
          return collection(item);
        }
        if (method === "some" || method === "every")
          return {
            ...host.union([receiver, mapped]),
            constant: undefined,
            fields: undefined,
            fieldsComplete: false,
            fullObject: false,
            guards: [],
          };
        if (method === "forEach") {
          opaque = true;
          return unknown("code_callback_mutation_unresolved", [
            receiver,
            mapped,
          ]);
        }
        // flatMap may return an array or a scalar. Preserve both the returned
        // value and a possible element until the runtime shape is known; this
        // cannot be used to prove a particular index or remove sensitivity.
        const mappedItem =
          method === "flatMap"
            ? unknown("code_flatmap_shape_unverified", [
                mapped,
                element(mapped),
              ])
            : mapped;
        return collection(mappedItem);
      }
      const simple =
        callee.type === "Identifier" &&
        [
          "String",
          "Number",
          "Boolean",
          "parseInt",
          "parseFloat",
          "encodeURIComponent",
          "$",
        ].includes(String(callee.name)) &&
        !state.env.has(String(callee.name));
      const standard =
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        callee.object.type === "Identifier" &&
        ["JSON", "$input"].includes(String(callee.object.name)) &&
        !state.env.has(String(callee.object.name)) &&
        ["parse", "stringify", "first", "last"].includes(method ?? "");
      if (
        simple ||
        standard ||
        (callee.type === "MemberExpression" &&
          object(callee.object) &&
          stringMethods.has(method ?? ""))
      ) {
        const args = ast.arguments.map((arg) =>
          object(arg)
            ? marker(expression(arg, state, depth + 1))
            : { type: "Literal", value: null },
        );
        const rewritten =
          simple || standard
            ? callee
            : {
                ...callee,
                object: marker(
                  expression(callee.object as Ast, state, depth + 1),
                ),
              };
        return host.evaluate({ ...ast, callee: rewritten, arguments: args });
      }
      // Date/clock formatting must observe the bounded local environment too.
      // Passing the original AST to the expression-only host loses local
      // constructor and formatting arguments (including captured parameters).
      if (
        callee.type === "MemberExpression" &&
        object(callee.object) &&
        (callee.object.type === "NewExpression" ||
          ["$now", "$today"].includes(String(callee.object.name)))
      ) {
        const receiver = expression(callee.object, state, depth + 1);
        const args = ast.arguments
          .filter(object)
          .map((argument) =>
            expression(
              argument.type === "SpreadElement" && object(argument.argument)
                ? argument.argument
                : argument,
              state,
              depth + 1,
            ),
          );
        const nativeDate =
          callee.object.type === "NewExpression" &&
          object(callee.object.callee) &&
          callee.object.callee.type === "Identifier" &&
          callee.object.callee.name === "Date" &&
          !state.env.has("Date") &&
          !functions.has("Date") &&
          Array.isArray(callee.object.arguments) &&
          callee.object.arguments.length <= 1 &&
          callee.object.arguments.every(
            (argument) => object(argument) && argument.type !== "SpreadElement",
          ) &&
          [
            "toDateString",
            "toISOString",
            "toUTCString",
            "toJSON",
            "toLocaleDateString",
            "toLocaleString",
            "toLocaleTimeString",
          ].includes(method ?? "");
        const n8nClock =
          callee.object.type === "Identifier" &&
          ["$now", "$today"].includes(String(callee.object.name)) &&
          !state.env.has(String(callee.object.name)) &&
          ["toFormat", "toISO", "toISODate", "toLocaleString"].includes(
            method ?? "",
          );
        if (
          callee.computed !== true &&
          (nativeDate || n8nClock) &&
          ast.arguments.length <= 2 &&
          ast.arguments.every(
            (argument) => object(argument) && argument.type !== "SpreadElement",
          )
        )
          return builtinResult([receiver, ...args]);
        opaque = true;
        return unknown("code_call_effect_unresolved", [receiver, ...args]);
      }
      opaque = true;
      return unknown(
        "code_call_effect_unresolved",
        ast.arguments
          .filter(object)
          .map((arg) => expression(arg, state, depth + 1)),
      );
    }
    if (ast.type === "NewExpression") {
      opaque = true;
      return unknown("code_expression_profile_unresolved", [
        ...(object(ast.callee)
          ? [expression(ast.callee, state, depth + 1)]
          : []),
        ...(Array.isArray(ast.arguments)
          ? ast.arguments
              .filter(object)
              .map((argument) =>
                expression(
                  argument.type === "SpreadElement" && object(argument.argument)
                    ? argument.argument
                    : argument,
                  state,
                  depth + 1,
                ),
              )
          : []),
      ]);
    }
    if (
      [
        "BinaryExpression",
        "LogicalExpression",
        "ConditionalExpression",
        "UnaryExpression",
        "TemplateLiteral",
      ].includes(String(ast.type))
    ) {
      const rewritten = { ...ast };
      for (const name of [
        "left",
        "right",
        "test",
        "consequent",
        "alternate",
        "argument",
      ])
        if (object(ast[name]))
          rewritten[name] = marker(
            expression(ast[name] as Ast, state, depth + 1),
          );
      if (Array.isArray(ast.expressions))
        rewritten.expressions = ast.expressions
          .filter(object)
          .map((item) => marker(expression(item, state, depth + 1)));
      return host.evaluate(rewritten);
    }
    if (
      ast.type === "UpdateExpression" &&
      (ast.operator === "++" || ast.operator === "--") &&
      object(ast.argument) &&
      ast.argument.type === "Identifier" &&
      typeof ast.argument.name === "string"
    ) {
      const prior = expression(ast.argument, state, depth + 1);
      const next = host.evaluate({
        type: "BinaryExpression",
        operator: ast.operator === "++" ? "+" : "-",
        left: marker(prior),
        right: marker(host.literal(1)),
      });
      assign(ast.argument, next, state);
      return ast.prefix === true ? next : prior;
    }
    opaque = true;
    return unknown("code_expression_profile_unresolved");
  };
  const assign = (target: Ast, value: AbstractValue, state: State): void => {
    observedValues.push(value);
    if (target.type === "Identifier" && typeof target.name === "string") {
      const old = state.env.get(target.name);
      if (!old?.mutable) {
        opaque = true;
        unknown("code_assignment_target_unresolved", [value]);
        return;
      }
      state.env.set(target.name, {
        ...old,
        value,
        owned: false,
        objectId: undefined,
      });
      state.writes.add(target.name);
      return;
    }
    objectMutation = true;
    if (
      target.type === "MemberExpression" &&
      object(target.object) &&
      target.object.type === "Identifier" &&
      typeof target.object.name === "string"
    ) {
      const binding = state.env.get(target.object.name),
        key = keyOf(target);
      if (key !== undefined && specialKeys.has(key)) {
        opaque = true;
        unknown("code_prototype_semantics_unresolved", [value]);
        return;
      }
      if (
        binding?.objectId !== undefined &&
        embeddedObjects.has(binding.objectId)
      ) {
        opaque = true;
        unknown("code_nested_alias_mutation_unresolved", [
          binding.value,
          value,
        ]);
        return;
      }
      if (
        binding?.owned &&
        binding.value.fields &&
        binding.value.fieldsComplete === true &&
        key !== undefined
      ) {
        const fields: Record<string, AbstractValue> = Object.create(null);
        for (const [path, child] of Object.entries(binding.value.fields))
          fields[path.slice(1).replace(/~1/g, "/").replace(/~0/g, "~")] = child;
        fields[key] = value;
        const replacement = madeObject(fields);
        const oldId = binding.objectId;
        for (const [name, alias] of state.env)
          if (oldId !== undefined && alias.objectId === oldId) {
            alias.value = replacement;
            state.writes.add(name);
          }
        return;
      }
    }
    opaque = true;
    unknown("code_assignment_target_unresolved", [value]);
  };
  const isolatedJsonParseTry = (item: Ast, state: State): boolean => {
    if (
      item.finalizer != null ||
      !object(item.block) ||
      !Array.isArray(item.block.body) ||
      item.block.body.length !== 1 ||
      !object(item.block.body[0]) ||
      !object(item.handler) ||
      !object(item.handler.body) ||
      !Array.isArray(item.handler.body.body) ||
      state.env.has("JSON") ||
      functions.has("JSON")
    )
      return false;
    const statement = item.block.body[0];
    let call: unknown;
    if (statement.type === "ReturnStatement") call = statement.argument;
    else if (
      statement.type === "ExpressionStatement" &&
      object(statement.expression) &&
      statement.expression.type === "AssignmentExpression" &&
      statement.expression.operator === "=" &&
      object(statement.expression.left) &&
      statement.expression.left.type === "Identifier" &&
      state.env.get(String(statement.expression.left.name))?.mutable === true
    )
      call = statement.expression.right;
    if (
      !object(call) ||
      call.type !== "CallExpression" ||
      !object(call.callee) ||
      call.callee.type !== "MemberExpression" ||
      call.callee.computed === true ||
      !object(call.callee.object) ||
      call.callee.object.type !== "Identifier" ||
      call.callee.object.name !== "JSON" ||
      keyOf(call.callee) !== "parse" ||
      !Array.isArray(call.arguments) ||
      call.arguments.length !== 1 ||
      !object(call.arguments[0]) ||
      !["Identifier", "Literal"].includes(String(call.arguments[0].type))
    )
      return false;
    if (item.handler.param == null) return true;
    if (
      !object(item.handler.param) ||
      item.handler.param.type !== "Identifier" ||
      typeof item.handler.param.name !== "string"
    )
      return false;
    const caughtName = item.handler.param.name;
    const pending: unknown[] = [...item.handler.body.body];
    while (pending.length) {
      const node = pending.pop();
      if (!object(node)) continue;
      // Any use or rebinding remains in the general exception profile. The
      // exception object is not known, and must not be confused with an outer
      // same-named binding or treated as a public literal.
      if (node.type === "Identifier" && node.name === caughtName) return false;
      for (const child of Object.values(node)) {
        if (Array.isArray(child)) pending.push(...child);
        else if (object(child)) pending.push(child);
      }
    }
    return true;
  };
  const execute = (
    body: unknown[],
    state: State,
    depth = 0,
    loopDepth = 0,
  ): void => {
    if (depth > 12) {
      opaque = true;
      unknown("code_statement_depth_limit");
      return;
    }
    for (const item of body) {
      if (state.stopped || opaque || !limit()) return;
      if (!object(item)) {
        opaque = true;
        continue;
      }
      if (item.type === "BlockStatement" && Array.isArray(item.body)) {
        const scoped = clone(state);
        execute(item.body, scoped, depth + 1, loopDepth);
        mergeState(state, [scoped]);
        continue;
      }
      if (item.type === "ContinueStatement" && !item.label && loopDepth > 0) {
        loopExitStack
          .at(-1)
          ?.push({ ...clone(state), stopped: false, stopReason: undefined });
        state.stopped = true;
        state.stopReason = "continue";
        continue;
      }
      if (item.type === "BreakStatement" && !item.label && loopDepth > 0) {
        loopExitStack
          .at(-1)
          ?.push({ ...clone(state), stopped: false, stopReason: undefined });
        state.stopped = true;
        state.stopReason = "break";
        continue;
      }
      if (
        item.type === "FunctionDeclaration" &&
        object(item.id) &&
        typeof item.id.name === "string" &&
        !roots.has(item.id.name) &&
        depth === 0 &&
        !functions.has(item.id.name) &&
        !state.env.has(item.id.name)
      ) {
        functions.set(item.id.name, item);
        captureConstants(item, state);
        continue;
      }
      if (
        item.type === "VariableDeclaration" &&
        ["const", "let"].includes(String(item.kind)) &&
        Array.isArray(item.declarations)
      ) {
        for (const declaration of item.declarations) {
          if (
            !object(declaration) ||
            !object(declaration.id) ||
            declaration.id.type !== "Identifier" ||
            typeof declaration.id.name !== "string" ||
            roots.has(declaration.id.name) ||
            state.env.has(declaration.id.name)
          ) {
            opaque = true;
            continue;
          }
          if (
            object(declaration.init) &&
            ["ArrowFunctionExpression", "FunctionExpression"].includes(
              String(declaration.init.type),
            )
          ) {
            if (functions.has(declaration.id.name) || depth !== 0) {
              opaque = true;
              continue;
            }
            functions.set(declaration.id.name, declaration.init);
            captureConstants(declaration.init, state);
            continue;
          }
          const value = object(declaration.init)
            ? expression(declaration.init, state)
            : host.literal(undefined);
          observedValues.push(value);
          if (
            object(declaration.init) &&
            declaration.init.type !== "Identifier"
          )
            embedReferences(declaration.init, state);
          const owned =
            object(declaration.init) &&
            (["ObjectExpression", "ArrayExpression"].includes(
              String(declaration.init.type),
            ) ||
              (declaration.init.type === "Identifier" &&
                state.env.get(String(declaration.init.name))?.owned === true));
          state.env.set(declaration.id.name, {
            value,
            mutable: item.kind === "let",
            owned,
            objectId: owned
              ? object(declaration.init) &&
                declaration.init.type === "Identifier"
                ? state.env.get(String(declaration.init.name))?.objectId
                : ++nextObjectId
              : undefined,
          });
        }
        continue;
      }
      if (item.type === "ReturnStatement") {
        if (object(item.argument)) embedReferences(item.argument, state);
        state.returns.push(
          object(item.argument)
            ? expression(item.argument, state)
            : host.literal(undefined),
        );
        state.stopped = true;
        state.stopReason = "return";
        continue;
      }
      if (
        item.type === "IfStatement" &&
        object(item.test) &&
        object(item.consequent)
      ) {
        expression(item.test, state);
        const yes = clone(state),
          no = clone(state);
        execute(
          item.consequent.type === "BlockStatement" &&
            Array.isArray(item.consequent.body)
            ? item.consequent.body
            : [item.consequent],
          yes,
          depth + 1,
          loopDepth,
        );
        if (object(item.alternate))
          execute(
            item.alternate.type === "BlockStatement" &&
              Array.isArray(item.alternate.body)
              ? item.alternate.body
              : [item.alternate],
            no,
            depth + 1,
            loopDepth,
          );
        mergeState(state, [yes, no]);
        continue;
      }
      if (
        item.type === "TryStatement" &&
        object(item.block) &&
        Array.isArray(item.block.body)
      ) {
        // One JSON.parse call commits its sole identifier assignment only
        // after it succeeds. Its catch therefore starts from the pre-call
        // state. Multi-statement try blocks may have partial writes and retain
        // the general opaque exception profile.
        const isolatedParse = isolatedJsonParseTry(item, state);
        if (!isolatedParse) exceptionFlow = true;
        const normal = clone(state),
          failed = clone(state);
        execute(item.block.body, normal, depth + 1, loopDepth);
        if (
          object(item.handler) &&
          object(item.handler.body) &&
          Array.isArray(item.handler.body.body)
        ) {
          if (
            !isolatedParse &&
            object(item.handler.param) &&
            item.handler.param.type === "Identifier" &&
            typeof item.handler.param.name === "string"
          )
            failed.env.set(item.handler.param.name, {
              value: unknown("code_exception_value_unverified"),
              mutable: false,
              owned: false,
            });
          execute(item.handler.body.body, failed, depth + 1, loopDepth);
        }
        mergeState(state, [normal, failed]);
        if (object(item.finalizer) && Array.isArray(item.finalizer.body)) {
          opaque = true;
          unknown("code_finally_semantics_unresolved");
        }
        continue;
      }
      if (
        item.type === "ForOfStatement" &&
        object(item.left) &&
        item.left.type === "VariableDeclaration" &&
        Array.isArray(item.left.declarations) &&
        item.left.declarations.length === 1 &&
        object(item.left.declarations[0]) &&
        object(item.left.declarations[0].id) &&
        item.left.declarations[0].id.type === "Identifier" &&
        typeof item.left.declarations[0].id.name === "string" &&
        object(item.right) &&
        object(item.body)
      ) {
        const list = expression(item.right, state),
          before = clone(state),
          once = clone(state),
          loopExits: State[] = [];
        once.writes.clear();
        once.env.set(item.left.declarations[0].id.name, {
          value: element(list),
          mutable: true,
          owned: false,
        });
        loopExitStack.push(loopExits);
        try {
          execute(
            item.body.type === "BlockStatement" && Array.isArray(item.body.body)
              ? item.body.body
              : [item.body],
            once,
            depth + 1,
            loopDepth + 1,
          );
        } finally {
          loopExitStack.pop();
        }
        mergeState(state, [before, once, ...loopExits]);
        const carried = [
          list,
          ...[once, ...loopExits].flatMap((branch) =>
            [...branch.env.values()].map((binding) => binding.value),
          ),
        ];
        const loopWrites = new Set([
          ...once.writes,
          ...loopExits.flatMap((branch) => [...branch.writes]),
        ]);
        for (const name of loopWrites) {
          const binding = state.env.get(name);
          if (binding) {
            binding.value = unknown("code_loop_carried_state_unverified", [
              binding.value,
              ...carried,
            ]);
            binding.owned = false;
            binding.objectId = undefined;
          }
        }
        const hadLoopReturn =
          once.returns.length > before.returns.length ||
          loopExits.some(
            (branch) => branch.returns.length > before.returns.length,
          );
        if (hadLoopReturn)
          state.returns = state.returns.map((value) =>
            unknown("code_loop_carried_state_unverified", [value, ...carried]),
          );
        unknown("code_loop_summary_partial", [list]);
        continue;
      }
      if (item.type === "ExpressionStatement" && object(item.expression)) {
        const expr = item.expression;
        if (
          expr.type === "AssignmentExpression" &&
          object(expr.left) &&
          object(expr.right) &&
          ["=", "+="].includes(String(expr.operator))
        ) {
          embedReferences(expr.right, state);
          const right = expression(expr.right, state);
          assign(
            expr.left,
            expr.operator === "="
              ? right
              : host.evaluate({
                  type: "BinaryExpression",
                  operator: "+",
                  left: marker(expression(expr.left, state)),
                  right: marker(right),
                }),
            state,
          );
          continue;
        }
        if (
          expr.type === "CallExpression" &&
          object(expr.callee) &&
          expr.callee.type === "MemberExpression" &&
          keyOf(expr.callee) === "push" &&
          object(expr.callee.object) &&
          expr.callee.object.type === "Identifier" &&
          Array.isArray(expr.arguments)
        ) {
          objectMutation = true;
          const binding = state.env.get(String(expr.callee.object.name));
          if (binding?.owned) {
            const existing = binding.value.fields
              ? Object.values(binding.value.fields)
              : [binding.value];
            const values = [
              ...existing,
              ...expr.arguments
                .filter(object)
                .map((arg) => expression(arg, state)),
            ];
            if (
              binding.objectId !== undefined &&
              embeddedObjects.has(binding.objectId)
            ) {
              opaque = true;
              unknown("code_nested_alias_mutation_unresolved", values);
              continue;
            }
            const replacement = array(values);
            const oldId = binding.objectId;
            for (const [name, alias] of state.env)
              if (oldId !== undefined && alias.objectId === oldId) {
                alias.value = replacement;
                state.writes.add(name);
              }
            continue;
          }
        }
        expression(expr, state);
        continue;
      }
      if (item.type === "EmptyStatement") continue;
      opaque = true;
      unknown("code_statement_profile_unresolved");
    }
  };
  const initial: State = {
    env: new Map(),
    returns: [],
    stopped: false,
    writes: new Set(),
  };
  if (!Array.isArray(program.body))
    return opaqueCodeObservation(host, "code_program_unavailable", [
      ...observedSources,
      host.input(),
    ]);
  execute(program.body, initial);
  const returned = choice(initial.returns);
  if (objectMutation) unknown("code_object_mutation_unresolved");
  if (exceptionFlow) unknown("code_try_state_unresolved");
  if (opaque || objectMutation || exceptionFlow || !initial.returns.length)
    return opaqueCodeObservation(host, "code_effects_partially_analyzed", [
      host.input(),
      returned,
      ...observedSources,
      ...diagnosticValues,
      ...observedValues,
      ...[...initial.env.values()].map((binding) => binding.value),
    ]);
  let output: AbstractValue;
  if (returned.fields?.["/json"]) output = returned.fields["/json"];
  else if (returned.representativeElement?.fields?.["/json"])
    output = returned.representativeElement.fields["/json"];
  else if (
    returned.fields &&
    Object.keys(returned.fields).length &&
    Object.keys(returned.fields).every((key) => /^\/\d+$/.test(key)) &&
    Object.values(returned.fields).every((value) => value.fields?.["/json"])
  )
    output = choice(
      Object.values(returned.fields).map((value) => value.fields!["/json"]!),
    );
  else
    return opaqueCodeObservation(host, "code_return_shape_unresolved", [
      returned,
      ...observedSources,
      host.input(),
    ]);
  const partial = unknown("code_bounded_flow_partial", [output]);
  return preserveValueShape(partial, output);
}
