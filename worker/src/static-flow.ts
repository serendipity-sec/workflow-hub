import { parseExpressionAt } from "acorn";
import type { MainEdge, NormalizedNode } from "./n8n.js";
import type { Context } from "./static-context.js";
import { isObject } from "./static-context.js";
import type {
  Category,
  Finding,
  RuleResult,
  StaticLocation,
} from "./static-contract.js";
import { locationFor, stableId } from "./static-contract.js";
import { inspectJavaScript } from "./static-settings.js";
import { isStructuredPostgres } from "./definition-risks.js";
import {
  buildValueFlow,
  isStaticIntervalWait,
  isStaticItemLimit,
} from "./value-flow.js";

const prefix = "n8n-nodes-base.";
const http = prefix + "httpRequest";
const pg = prefix + "postgres";
const webhook = prefix + "webhook";
const respond = prefix + "respondToWebhook";
const conditional = prefix + "if";
const noop = prefix + "noOp";
const codeNode = prefix + "code";
const stopAndError = prefix + "stopAndError";
const httpVersions = new Set([3, 4, 4.1, 4.2, 4.3, 4.4, 4.5]);
const pgVersions = new Set([2.4, 2.5, 2.6, 2.8]);
const webhookVersions = new Set([2, 2.1, 2.2]);
const responseVersions = new Set([1, 1.1, 1.2, 1.3, 1.4, 1.5]);
const ifVersions = new Set([2, 2.1, 2.2, 2.3]);
const scheduleVersions = new Set([1, 1.1, 1.2, 1.3, 1.4]);
// These types have explicit sink/source profile checks below. This set does
// not declare their outputs to preserve the current input item.
const inspectedTypes = new Set([webhook, http, pg, respond]);
const rootLocation: StaticLocation = { nodeKey: null, pointer: "/nodes" };

type Ref = { kind: "current" | "direct"; path: string; name?: string };
type Trace = { source: NormalizedNode; path: NormalizedNode[]; reference: Ref };
type LocalEffect = { inputs: number; outputs: number; preservesInput: boolean };
type FlowContext = Context & { localEffects: ReadonlyMap<string, LocalEffect> };

/** A deliberately small Acorn profile for data-only parameter expressions.
 * Calls, callbacks, mutation and dynamic property keys outside the n8n read
 * accessors stay opaque. Parsing never invokes workflow expressions. */
function readOnlyParameters(parameters: unknown): boolean {
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
        (value.type === "Literal" && value.value === null)
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
        value.arguments.length
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
      const parts = expressions(value);
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

function localDataEffects(context: Context): ReadonlyMap<string, LocalEffect> {
  const profiles = new Map<string, LocalEffect>();
  const flow = buildValueFlow(context);
  for (const node of context.nodes) {
    const collection = collectionEffect(context, node);
    if (collection) {
      profiles.set(node.key, collection);
      continue;
    }
    const set =
      node.type === prefix + "set" &&
      [3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion);
    const branch =
      node.type === prefix + "switch" &&
      [3, 3.1, 3.2, 3.3, 3.4, 3.5].includes(node.typeVersion);
    const aggregate =
      node.type === prefix + "aggregate" && node.typeVersion === 1;
    if (
      (!set && !branch && !aggregate) ||
      !safeExecution(node) ||
      !readOnlyParameters(node.parameters)
    )
      continue;
    if (
      context.unsupportedEdges.some(
        (edge) => edge.from === node.key || edge.to === node.key,
      ) ||
      context.edges.some((edge) => edge.to === node.key && edge.input !== 0)
    )
      continue;
    const p = node.parameters;
    if (p.options !== undefined && !isObject(p.options)) continue;
    const options = isObject(p.options) ? p.options : {};
    let outputs = 1;
    if (set) {
      if (p.mode !== undefined && p.mode !== "manual" && p.mode !== "raw")
        continue;
      if (p.mode === "raw") {
        if (typeof p.jsonOutput !== "string") continue;
        if (!p.jsonOutput.startsWith("=")) {
          try {
            if (!isObject(JSON.parse(p.jsonOutput))) continue;
          } catch {
            continue;
          }
        }
      } else {
        const container = node.typeVersion < 3.3 ? p.fields : p.assignments;
        if (container !== undefined && !isObject(container)) continue;
        const entries = isObject(container)
          ? container[node.typeVersion < 3.3 ? "values" : "assignments"]
          : undefined;
        if (entries !== undefined && !Array.isArray(entries)) continue;
      }
      if (p.duplicateItem !== undefined && p.duplicateItem !== false) continue;
      if (
        p.includeOtherFields !== undefined &&
        typeof p.includeOtherFields !== "boolean"
      )
        continue;
      if (
        Object.entries(options).some(
          ([key, value]) =>
            ![
              "dotNotation",
              "ignoreConversionErrors",
              "includeBinary",
              "stripBinary",
            ].includes(key) || typeof value !== "boolean",
        )
      )
        continue;
    }
    if (branch) {
      if (p.mode !== undefined && p.mode !== "rules") continue;
      const rules = isObject(p.rules) ? p.rules.values : undefined;
      if (!Array.isArray(rules) || !rules.length || rules.length > 128)
        continue;
      if (
        rules.some(
          (rule) =>
            !isObject(rule) ||
            !isObject(rule.conditions) ||
            !Array.isArray(rule.conditions.conditions) ||
            !rule.conditions.conditions.length ||
            rule.conditions.conditions.some(
              (condition) =>
                !isObject(condition) ||
                !isObject(condition.operator) ||
                typeof condition.operator.type !== "string" ||
                typeof condition.operator.operation !== "string" ||
                ![
                  "string",
                  "number",
                  "boolean",
                  "dateTime",
                  "array",
                  "object",
                ].includes(String(condition.operator.type)) ||
                ![
                  "equals",
                  "notEquals",
                  "contains",
                  "notContains",
                  "lt",
                  "lte",
                  "gt",
                  "gte",
                  "exists",
                  "notExists",
                  "empty",
                  "notEmpty",
                  "true",
                  "false",
                ].includes(String(condition.operator.operation)),
            ),
        )
      )
        continue;
      const fallback = options.fallbackOutput;
      const index =
        typeof fallback === "string" && /^(?:0|[1-9]\d*)$/.test(fallback)
          ? Number(fallback)
          : fallback;
      if (
        fallback !== undefined &&
        fallback !== "none" &&
        fallback !== "extra" &&
        !(
          typeof index === "number" &&
          Number.isSafeInteger(index) &&
          index >= 0 &&
          index < rules.length
        )
      )
        continue;
      if (
        options.allMatchingOutputs !== undefined &&
        typeof options.allMatchingOutputs !== "boolean"
      )
        continue;
      outputs = rules.length + (fallback === "extra" ? 1 : 0);
    } else {
      // Reuse the bounded field decoder to reject malformed Set/Aggregate
      // declarations. Upstream value uncertainty is retained by that analyzer;
      // it is not itself evidence of a network, SQL or response side effect.
      flow.output(node.key, "");
      const allowed = new Set([
        "set_exclusion_whole_object_partial",
        "set_raw_merge_partial",
        "aggregate_dotted_key_resolution_unverified",
        "aggregate_excluded_unknown_fields",
      ]);
      if (
        flow.diagnostics.some(
          (item) =>
            item.nodeKey === node.key &&
            !allowed.has(item.code) &&
            (/^(set_|aggregate_|flow_)/.test(item.code) ||
              item.code === "unsafe_field_reference"),
        )
      )
        continue;
    }
    if (
      context.edges.some(
        (edge) => edge.from === node.key && edge.output >= outputs,
      )
    )
      continue;
    profiles.set(node.key, { inputs: 1, outputs, preservesInput: branch });
  }
  return profiles;
}

/** Fixed local operations only. Item selection is not a proof of which item
 * executes, and transforming collections never preserves current JSON paths. */
function collectionEffect(
  context: Context,
  node: NormalizedNode,
): LocalEffect | undefined {
  if (!safeExecution(node) || !readOnlyParameters(node.parameters)) return;
  const p = node.parameters;
  const known = (keys: string[]): boolean =>
    Object.keys(p).every((key) => keys.includes(key));
  const emptyOptions = (): boolean =>
    p.options === undefined ||
    (isObject(p.options) && Object.keys(p.options).length === 0);
  let profile: LocalEffect | undefined;
  if (node.type === prefix + "limit" && node.typeVersion === 1) {
    if (!isStaticItemLimit(node)) return;
    profile = { inputs: 1, outputs: 1, preservesInput: true };
  } else if (
    node.type === prefix + "merge" &&
    [3, 3.1, 3.2].includes(node.typeVersion)
  ) {
    const count = p.numberInputs === undefined ? 2 : p.numberInputs;
    if (
      !known(["mode", "numberInputs", "options"]) ||
      (p.mode !== undefined && p.mode !== "append") ||
      !emptyOptions() ||
      typeof count !== "number" ||
      !Number.isSafeInteger(count) ||
      count < 2 ||
      count > 10
    )
      return;
    profile = { inputs: count, outputs: 1, preservesInput: false };
  } else if (
    node.type === prefix + "splitOut" &&
    [1, 1.1].includes(node.typeVersion)
  ) {
    if (
      !known(["fieldToSplitOut", "include", "fieldsToInclude", "options"]) ||
      (p.options !== undefined && !isObject(p.options))
    )
      return;
    const options = isObject(p.options) ? p.options : {};
    if (
      Object.entries(options).some(([key, value]) =>
        key === "destinationFieldName"
          ? typeof value !== "string"
          : key === "disableDotNotation"
            ? typeof value !== "boolean"
            : key !== "includeBinary" || value !== false,
      )
    )
      return;
    // Keep lodash bracket syntax, prototype paths and binary splitting outside
    // this narrow JSON-only effect profile.
    const fields = (value: unknown): string[] | undefined => {
      if (typeof value !== "string" || value.length > 4096) return;
      const selected = value
        .split(",")
        .map((field) => field.trim().replace(/^\$json\./, ""));
      if (
        !selected.length ||
        selected.length > 128 ||
        selected.some(
          (field) =>
            !/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(
              field,
            ) ||
            field
              .split(".")
              .some((part) =>
                ["__proto__", "prototype", "constructor"].includes(part),
              ),
        )
      )
        return;
      return selected;
    };
    const split = fields(p.fieldToSplitOut);
    const include = p.include === undefined ? "noOtherFields" : p.include;
    if (
      !split ||
      !["noOtherFields", "allOtherFields", "selectedOtherFields"].includes(
        include as string,
      ) ||
      (include === "selectedOtherFields" && !fields(p.fieldsToInclude))
    )
      return;
    if (
      options.destinationFieldName !== undefined &&
      options.destinationFieldName !== ""
    ) {
      const destination = fields(options.destinationFieldName);
      if (
        !destination ||
        destination.length !== split.length ||
        new Set(destination).size !== destination.length
      )
        return;
    }
    profile = { inputs: 1, outputs: 1, preservesInput: false };
  } else if (node.type === prefix + "errorTrigger" && node.typeVersion === 1) {
    if (!known(["notice"])) return;
    profile = { inputs: 0, outputs: 1, preservesInput: false };
  } else if (node.type === stopAndError && node.typeVersion === 1) {
    const mode = p.errorType === undefined ? "errorMessage" : p.errorType;
    if (
      !known(["errorType", "errorMessage", "errorObject"]) ||
      (mode !== "errorMessage" && mode !== "errorObject") ||
      typeof p[mode] !== "string"
    )
      return;
    if (mode === "errorObject" && !(p[mode] as string).startsWith("=")) {
      try {
        if (!isObject(JSON.parse(p[mode] as string))) return;
      } catch {
        return;
      }
    }
    profile = { inputs: 1, outputs: 0, preservesInput: false };
  }
  if (
    !profile ||
    context.unsupportedEdges.some(
      (edge) => edge.from === node.key || edge.to === node.key,
    ) ||
    context.edges.some(
      (edge) =>
        (edge.to === node.key && edge.input >= profile.inputs) ||
        (edge.from === node.key && edge.output >= profile.outputs),
    )
  )
    return;
  return profile;
}

function sourceOutputCount(node: NormalizedNode): number | undefined {
  const methods = new Set([
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
  ]);
  const multiple = node.parameters.multipleMethods;
  if (multiple !== undefined && typeof multiple !== "boolean") return;
  const value = node.parameters.httpMethod;
  if (multiple === true) {
    const selected = value === undefined ? ["GET", "POST"] : value;
    if (
      !Array.isArray(selected) ||
      selected.length === 0 ||
      selected.some(
        (method) => typeof method !== "string" || !methods.has(method),
      ) ||
      new Set(selected).size !== selected.length
    )
      return;
    return selected.length;
  }
  return value === undefined ||
    (typeof value === "string" && methods.has(value))
    ? 1
    : undefined;
}

function controlEdge(context: FlowContext, edge: MainEdge): boolean {
  const node = context.nodeByKey.get(edge.from);
  const targetInputs = context.localEffects.get(edge.to)?.inputs ?? 1;
  if (!node || !safeExecution(node) || edge.input >= targetInputs) return false;
  if (node.type === webhook) {
    const count = sourceOutputCount(node);
    return (
      webhookVersions.has(node.typeVersion) &&
      count !== undefined &&
      edge.output < count &&
      !context.edges.some((item) => item.to === node.key)
    );
  }
  if (node.type === conditional)
    return ifVersions.has(node.typeVersion) && edge.output < 2;
  if (node.type === noop) return node.typeVersion === 1 && edge.output === 0;
  if (isStaticIntervalWait(node)) return edge.output === 0;
  const local = context.localEffects.get(node.key);
  if (local) return edge.output < local.outputs;
  if (node.type === http)
    return httpVersions.has(node.typeVersion) && edge.output === 0;
  if (node.type === pg)
    return pgVersions.has(node.typeVersion) && edge.output === 0;
  if (node.type === respond)
    return responseVersions.has(node.typeVersion) && edge.output === 0;
  return false;
}

function safeExecution(node: NormalizedNode): boolean {
  return (
    !node.disabled &&
    node.raw.continueOnFail !== true &&
    (node.raw.onError === undefined || node.raw.onError === "stopWorkflow") &&
    node.raw.alwaysOutputData !== true &&
    node.raw.executeOnce !== true &&
    node.raw.rewireOutputLogTo === undefined
  );
}

function expressions(value: string): string[] | undefined {
  const matches = [...value.matchAll(/\{\{([^{}]*)\}\}/g)];
  const removed = value.replace(/\{\{([^{}]*)\}\}/g, "");
  if (removed.includes("{{") || removed.includes("}}")) return undefined;
  if (value.trimStart().startsWith("=") && matches.length === 0)
    return undefined;
  return matches.map((match) => match[1]!.trim());
}

function reference(text: string): Ref | undefined {
  const current = /^\$json((?:\.[A-Za-z_][A-Za-z0-9_]*)*)$/.exec(text);
  if (current) return { kind: "current", path: current[1]!.slice(1) };
  const direct =
    /^\$\((['"])([^'"\\]+)\1\)\.first\(\)\.json((?:\.[A-Za-z_][A-Za-z0-9_]*)*)$/.exec(
      text,
    );
  if (direct)
    return { kind: "direct", name: direct[2], path: direct[3]!.slice(1) };
}

function pathBetween(
  context: FlowContext,
  from: NormalizedNode,
  to: NormalizedNode,
): NormalizedNode[] | undefined {
  const pending: NormalizedNode[][] = [[from]];
  const visited = new Set<string>();
  while (pending.length) {
    const path = pending.shift()!;
    const last = path.at(-1)!;
    if (last.key === to.key) return path;
    if (visited.has(last.key) || path.length > context.nodes.length) continue;
    visited.add(last.key);
    for (const edge of context.edges.filter((item) => item.from === last.key)) {
      const node = context.nodeByKey.get(edge.to);
      if (node && !node.disabled && controlEdge(context, edge))
        pending.push([...path, node]);
    }
  }
}

function trace(
  context: FlowContext,
  sink: NormalizedNode,
  ref: Ref,
): Trace | undefined {
  if (
    ref.path
      .split(".")
      .some((part) => ["__proto__", "prototype", "constructor"].includes(part))
  )
    return;
  if (ref.kind === "direct") {
    const source = context.nodeByName.get(ref.name!);
    if (
      !source ||
      source.type !== webhook ||
      !webhookVersions.has(source.typeVersion) ||
      !safeExecution(source)
    )
      return;
    const path = pathBetween(context, source, sink);
    return path ? { source, path, reference: ref } : undefined;
  }
  const backwards: NormalizedNode[] = [sink];
  const visited = new Set([sink.key]);
  let current = sink;
  while (backwards.length <= context.nodes.length) {
    const incoming = context.edges.filter((edge) => edge.to === current.key);
    if (incoming.length !== 1 || incoming[0]!.input !== 0) return;
    const edge = incoming[0]!;
    if (!controlEdge(context, edge)) return;
    const previous = context.nodeByKey.get(edge.from);
    if (!previous || visited.has(previous.key) || !safeExecution(previous))
      return;
    visited.add(previous.key);
    backwards.push(previous);
    if (
      previous.type === webhook &&
      webhookVersions.has(previous.typeVersion)
    ) {
      return { source: previous, path: backwards.reverse(), reference: ref };
    }
    if (
      !(
        previous.type === conditional &&
        ifVersions.has(previous.typeVersion) &&
        edge.output <= 1
      ) &&
      !(
        previous.type === noop &&
        previous.typeVersion === 1 &&
        edge.output === 0
      ) &&
      !(isStaticIntervalWait(previous) && edge.output === 0) &&
      !context.localEffects.get(previous.key)?.preservesInput
    )
      return;
    current = previous;
  }
}

function narrowNumericGuard(
  context: FlowContext,
  sink: NormalizedNode,
  value: string,
  ref: Ref,
): boolean {
  // Only the previously validated, unquoted single-value SELECT profile can
  // classify a numeric IF as a guard. Generic expression presence never does.
  if (
    !/^=?\s*SELECT\s+[A-Za-z_][A-Za-z0-9_]*\s+FROM\s+[A-Za-z_][A-Za-z0-9_]*\s+WHERE\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{\{[^{}]+\}\}\s*$/i.test(
      value,
    )
  )
    return false;
  const incoming = context.edges.filter((edge) => edge.to === sink.key);
  if (incoming.length !== 1 || incoming[0]!.output !== 0) return false;
  const guard = context.nodeByKey.get(incoming[0]!.from);
  if (
    !guard ||
    guard.type !== conditional ||
    guard.typeVersion !== 2.2 ||
    !safeExecution(guard)
  )
    return false;
  if (
    (guard.parameters.looseTypeValidation !== undefined &&
      guard.parameters.looseTypeValidation !== false) ||
    !isObject(guard.parameters.conditions)
  )
    return false;
  const filter = guard.parameters.conditions;
  if (
    filter.combinator !== "and" ||
    !Array.isArray(filter.conditions) ||
    filter.conditions.length !== 1 ||
    !isObject(filter.options)
  )
    return false;
  if (
    filter.options.typeValidation !== "strict" ||
    filter.options.version !== 2 ||
    filter.options.caseSensitive !== true ||
    filter.options.leftValue !== ""
  )
    return false;
  const condition = filter.conditions[0];
  if (
    !isObject(condition) ||
    !isObject(condition.operator) ||
    condition.operator.type !== "number" ||
    condition.operator.operation !== "equals" ||
    !Number.isSafeInteger(condition.rightValue) ||
    typeof condition.leftValue !== "string"
  )
    return false;
  const left = /^=\{\{([^{}]+)\}\}$/.exec(condition.leftValue)?.[1];
  const guardedRef = left ? reference(left.trim()) : undefined;
  if (!guardedRef || guardedRef.path !== ref.path) return false;
  const target = trace(context, sink, ref);
  const guardTarget = trace(context, guard, guardedRef);
  return (
    target !== undefined &&
    guardTarget !== undefined &&
    target.source.key === guardTarget.source.key
  );
}

function rule(ruleId: string, category: Category): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.5.0",
    findings: [],
    diagnostics: [],
    coverage: [],
  };
}

function evaluate(
  result: RuleResult,
  node: NormalizedNode,
  suffix: string,
  checks: () => void,
): void {
  const previousFindings = new Set(result.findings.map((item) => item.id));
  const previousDiagnostics = new Set(
    result.diagnostics.map((item) => item.id),
  );
  checks();
  const location = locationFor(node, suffix);
  const findings = result.findings.filter(
    (item) => !previousFindings.has(item.id),
  );
  const diagnostics = result.diagnostics.filter(
    (item) => !previousDiagnostics.has(item.id),
  );
  result.coverage.push({
    location,
    status: diagnostics.length
      ? findings.length
        ? "partial"
        : "unsupported"
      : "checked",
    findingIds: findings.map((item) => item.id),
    diagnosticIds: diagnostics.map((item) => item.id),
  });
}

function diagnostic(
  result: RuleResult,
  location: StaticLocation,
  code: string,
): void {
  const id = stableId(result.ruleId, location, code);
  if (!result.diagnostics.some((item) => item.id === id))
    result.diagnostics.push({ id, code, location });
}

function finding(
  result: RuleResult,
  location: StaticLocation,
  code: string,
  evidence: Finding["evidence"],
  claim: Finding["claim"] = "configuration",
  severity: Finding["severity"] = "medium",
): Finding | undefined {
  const id = stableId(result.ruleId, location, code);
  const existing = result.findings.find((item) => item.id === id);
  if (existing) return existing;
  if (result.findings.length >= 256) {
    const rank = { info: 0, low: 1, medium: 2, high: 3 };
    const replace = result.findings.findIndex(
      (item) => rank[item.severity] < rank[severity],
    );
    if (replace < 0) {
      diagnostic(result, location, "definition_finding_limit");
      return;
    }
    // Keep a later high-severity candidate rather than silently losing it to
    // earlier informational findings. The displaced location remains explicit
    // partial coverage, and all coverage references stay schema-consistent.
    const omitted = result.findings.splice(replace, 1)[0]!;
    diagnostic(result, omitted.location, "definition_finding_limit");
    const limitId = stableId(
      result.ruleId,
      omitted.location,
      "definition_finding_limit",
    );
    for (const scope of result.coverage) {
      if (!scope.findingIds.includes(omitted.id)) continue;
      scope.findingIds = scope.findingIds.filter((item) => item !== omitted.id);
      if (!scope.diagnosticIds.includes(limitId))
        scope.diagnosticIds.push(limitId);
      scope.status = scope.findingIds.length ? "partial" : "unsupported";
    }
  }
  const added: Finding = {
    id,
    ruleId: result.ruleId,
    category: result.category,
    severity,
    claim,
    location,
    evidence: [{ code, location }, ...evidence],
    assumptions: ["static_definition_only", "runtime_permissions_unverified"],
    remediation: {
      code: "review_actual_value_and_destination",
      checks: [
        "preserve_expected_function",
        "rescan_same_profile",
        "verify_runtime_conditions",
      ],
    },
  };
  result.findings.push(added);
  return added;
}

function traceEvidence(found: Trace | undefined): Finding["evidence"] {
  return found
    ? found.path.map((node, index) => ({
        code: index === 0 ? "webhook_input_source" : "declared_main_path",
        location: locationFor(node),
      }))
    : [];
}

function dynamicEvidence(
  context: FlowContext,
  result: RuleResult,
  node: NormalizedNode,
  value: string,
  suffix: string,
): { refs: Ref[]; traces: Trace[]; complete: boolean } {
  const location = locationFor(node, suffix);
  const parts = expressions(value);
  if (!parts) {
    diagnostic(result, location, "unsupported_expression");
    return { refs: [], traces: [], complete: false };
  }
  const refs = parts.map(reference);
  const traces = refs.map((ref) =>
    ref ? trace(context, node, ref) : undefined,
  );
  const complete = refs.every(Boolean) && traces.every(Boolean);
  if (!complete) diagnostic(result, location, "input_provenance_unresolved");
  return {
    refs: refs.filter((ref): ref is Ref => ref !== undefined),
    traces: traces.filter((item): item is Trace => item !== undefined),
    complete,
  };
}

function isDynamic(value: string): boolean {
  return (
    value.trimStart().startsWith("=") ||
    value.includes("{{") ||
    value.includes("}}")
  );
}

function fixedDestination(value: string): URL | undefined {
  // Only a literal, valid authority followed by a literal slash is enough.
  // A variable appended to a hostname is still an authority change.
  const text = value.startsWith("=") ? value.slice(1) : value;
  const open = text.indexOf("{{");
  if (open < 0) return URL.canParse(text) ? new URL(text) : undefined;
  const literal = text.slice(0, open);
  const match = /^(https?:\/\/[^/?#]+)[/?#]/i.exec(literal);
  return match && URL.canParse(match[1]!) ? new URL(match[1]!) : undefined;
}

function nonpublicLiteral(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const v4 = (parts: number[]): boolean => {
    const [a, b] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b! >= 64 && b! <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b! >= 16 && b! <= 31) ||
      (a === 192 && b === 168)
    );
  };
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return v4(host.split(".").map(Number));
  if (host === "[::]" || host === "[::1]") return true;
  if (/^\[f[cd][0-9a-f]{2}:/.test(host) || /^\[fe[89ab][0-9a-f]:/.test(host))
    return true;
  const mapped = /^\[::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})\]$/.exec(host);
  if (mapped) {
    const high = parseInt(mapped[1]!, 16),
      low = parseInt(mapped[2]!, 16);
    return v4([high >>> 8, high & 255, low >>> 8, low & 255]);
  }
  return false;
}

function outboundBody(result: RuleResult, node: NormalizedNode): void {
  const parameters = node.parameters;
  if (
    parameters.sendBody !== undefined &&
    typeof parameters.sendBody !== "boolean"
  ) {
    diagnostic(
      result,
      locationFor(node, "/parameters/sendBody"),
      "request_body_toggle_unresolved",
    );
    return;
  }
  if (parameters.sendBody !== true) return;
  // HEAD/OPTIONS/TRACE and unreviewed WebDAV methods have different body
  // handling. Preserve uncertainty instead of declaring a saved field sent.
  const method = parameters.method === undefined ? "GET" : parameters.method;
  if (
    typeof method !== "string" ||
    !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)
  ) {
    diagnostic(
      result,
      locationFor(node, "/parameters/method"),
      "request_body_method_unresolved",
    );
    return;
  }
  const contentType =
    parameters.contentType === undefined ? "json" : parameters.contentType;
  const mode =
    parameters.specifyBody === undefined ? "keypair" : parameters.specifyBody;
  let field: "jsonBody" | "body" | "bodyParameters" | "inputDataFieldName";
  if (contentType === "json" && mode === "json") field = "jsonBody";
  else if (
    (contentType === "json" || contentType === "form-urlencoded") &&
    mode === "keypair"
  )
    field = "bodyParameters";
  else if (contentType === "form-urlencoded" && mode === "string")
    field = "body";
  else if (contentType === "multipart-form-data") field = "bodyParameters";
  else if (contentType === "raw") field = "body";
  else if (contentType === "binaryData") field = "inputDataFieldName";
  else {
    diagnostic(
      result,
      locationFor(node, "/parameters"),
      "request_body_mode_unresolved",
    );
    return;
  }
  const value = parameters[field];
  const location = locationFor(node, "/parameters/" + field);
  // Never fall back to a different saved field: it may be inactive in n8n.
  if (value === undefined) {
    if (field === "inputDataFieldName")
      diagnostic(result, location, "request_body_field_unavailable");
    return;
  }
  if (
    (field === "bodyParameters" &&
      (!isObject(value) ||
        (value.parameters !== undefined &&
          !Array.isArray(value.parameters)))) ||
    ((field === "body" || field === "inputDataFieldName") &&
      typeof value !== "string") ||
    (field === "jsonBody" &&
      typeof value !== "string" &&
      value !== null &&
      !isObject(value) &&
      !Array.isArray(value))
  ) {
    diagnostic(result, location, "request_body_shape_unresolved");
    return;
  }
  finding(
    result,
    location,
    "configured_outbound_body",
    [],
    "configuration",
    "info",
  );
  if (field === "inputDataFieldName")
    diagnostic(result, location, "binary_body_content_unverified");
}

function httpRules(
  context: FlowContext,
  egress: RuleResult,
  ssrf: RuleResult,
): void {
  for (const node of context.nodes.filter((item) => item.type === http)) {
    for (const result of [egress, ssrf]) {
      evaluate(
        result,
        node,
        result === egress ? "/parameters" : "/parameters/url",
        () => {
          const location = locationFor(node, "/parameters/url");
          if (node.disabled) {
            diagnostic(result, location, "disabled_node_not_executed");
            return;
          }
          if (!httpVersions.has(node.typeVersion)) {
            diagnostic(result, location, "unsupported_node_version");
            return;
          }
          const value = node.parameters.url;
          if (typeof value !== "string" || !value.trim()) {
            diagnostic(result, location, "request_url_unavailable");
            return;
          }
          // HTTP Request uses n8n's ordinary parameter evaluation. Unlike the
          // Postgres query parser, bare {{...}} is not expression mode.
          const dynamic = value.startsWith("=");
          const declaredScheme = /^=?([a-z][a-z0-9+.-]*):/i
            .exec(value)?.[1]
            ?.toLowerCase();
          if (declaredScheme && !["http", "https"].includes(declaredScheme)) {
            diagnostic(result, location, "unsupported_request_scheme");
            return;
          }
          const traced = dynamic
            ? dynamicEvidence(context, result, node, value, "/parameters/url")
            : undefined;
          if (!dynamic && !URL.canParse(value)) {
            diagnostic(result, location, "request_url_invalid");
            return;
          }
          const literalUrl = dynamic ? fixedDestination(value) : new URL(value);
          if (
            literalUrl &&
            !["http:", "https:"].includes(literalUrl.protocol)
          ) {
            diagnostic(result, location, "unsupported_request_scheme");
            return;
          }
          if (result === egress) {
            finding(
              result,
              location,
              dynamic
                ? "dynamic_request_destination"
                : "configured_request_destination",
              traceEvidence(traced?.traces[0]),
              traced?.complete ? "supported_path" : "configuration",
              "info",
            );
            outboundBody(result, node);
          } else if (
            (dynamic && !literalUrl) ||
            (literalUrl && nonpublicLiteral(literalUrl.hostname))
          ) {
            const added = finding(
              result,
              location,
              dynamic && !literalUrl
                ? "dynamic_request_authority"
                : "configured_nonpublic_destination",
              traceEvidence(!literalUrl ? traced?.traces[0] : undefined),
              dynamic && !literalUrl
                ? traced?.complete
                  ? "supported_path"
                  : "candidate"
                : "configuration",
              dynamic && !literalUrl ? "high" : "medium",
            );
            added?.assumptions.push("dns_redirects_and_network_unverified");
          }
          if (!safeExecution(node))
            diagnostic(result, location, "nonstandard_execution_semantics");
        },
      );
    }
  }
}

function sqlRule(context: FlowContext, result: RuleResult): void {
  for (const node of context.nodes.filter((item) => item.type === pg)) {
    evaluate(result, node, "/parameters/query", () => {
      const location = locationFor(node, "/parameters/query");
      if (node.disabled) {
        diagnostic(result, location, "disabled_node_not_executed");
        return;
      }
      if (!pgVersions.has(node.typeVersion)) {
        diagnostic(result, location, "unsupported_node_version");
        return;
      }
      if (
        (node.parameters.resource === undefined
          ? "database"
          : node.parameters.resource) !== "database" ||
        (node.parameters.operation === undefined
          ? "insert"
          : node.parameters.operation) !== "executeQuery"
      ) {
        diagnostic(
          result,
          location,
          isStructuredPostgres(node)
            ? "database_runtime_schema_and_permissions_unverified"
            : "unsupported_database_operation",
        );
        return;
      }
      const value = node.parameters.query;
      if (typeof value !== "string") {
        diagnostic(result, location, "query_unavailable");
        return;
      }
      if (!isDynamic(value)) return;
      const traced = dynamicEvidence(
        context,
        result,
        node,
        value,
        "/parameters/query",
      );
      const guarded =
        traced.complete &&
        traced.refs.length === 1 &&
        narrowNumericGuard(context, node, value, traced.refs[0]!);
      if (!guarded) {
        const last = finding(
          result,
          location,
          "dynamic_sql_text",
          traceEvidence(traced.traces[0]),
          traced.complete ? "supported_path" : "candidate",
          "high",
        );
        if (last)
          last.remediation = {
            code: "use_fixed_sql_and_value_parameters",
            checks: [
              "value_positions_only",
              "check_node_version_binding_semantics",
              "preserve_expected_rows",
              "rescan_same_profile",
            ],
          };
      }
      if (!safeExecution(node))
        diagnostic(result, location, "nonstandard_execution_semantics");
    });
  }
}

function outputRule(context: FlowContext, result: RuleResult): void {
  errorOutputRule(context, result);
  for (const node of context.nodes.filter(
    (item) =>
      item.type === respond ||
      (item.type === webhook && item.parameters.responseMode === "lastNode"),
  )) {
    evaluate(result, node, "/parameters", () => {
      const location = locationFor(node, "/parameters");
      if (node.disabled) {
        diagnostic(result, location, "disabled_node_not_executed");
        return;
      }
      if (node.type === webhook) {
        if (!webhookVersions.has(node.typeVersion)) {
          diagnostic(result, location, "unsupported_node_version");
          return;
        }
        if (node.parameters.responseData === "noData") return;
        const options = node.parameters.options;
        if (
          isObject(options) &&
          options.noResponseBody === true &&
          node.parameters.responseData === undefined
        )
          return;
        finding(
          result,
          location,
          "last_node_response_review",
          [],
          "configuration",
          "medium",
        );
        diagnostic(result, location, "response_data_sensitivity_unverified");
        return;
      }
      if (!responseVersions.has(node.typeVersion)) {
        diagnostic(result, location, "unsupported_node_version");
        return;
      }
      const mode = node.parameters.respondWith ?? "firstIncomingItem";
      if (mode === "firstIncomingItem" || mode === "allIncomingItems") {
        // responseKey wraps the full input under a key; it does not select a field.
        const traced = trace(context, node, { kind: "current", path: "" });
        finding(
          result,
          location,
          "whole_input_response",
          traceEvidence(traced),
          traced ? "supported_path" : "configuration",
          "medium",
        );
        diagnostic(result, location, "response_data_sensitivity_unverified");
      } else if (mode === "json" || mode === "text") {
        const body = node.parameters.responseBody;
        if (body !== undefined && typeof body !== "string")
          diagnostic(result, location, "unsupported_response_body_shape");
        if (typeof body === "string" && body.startsWith("=")) {
          const traced = dynamicEvidence(
            context,
            result,
            node,
            body,
            "/parameters/responseBody",
          );
          if (
            traced.refs.some((ref) => ref.path === "" || ref.path === "body")
          ) {
            finding(
              result,
              locationFor(node, "/parameters/responseBody"),
              "whole_input_response_expression",
              traceEvidence(traced.traces[0]),
              traced.complete ? "supported_path" : "candidate",
              "medium",
            );
            diagnostic(
              result,
              location,
              "response_data_sensitivity_unverified",
            );
          }
        }
      } else if (mode !== "noData") {
        diagnostic(result, location, "unsupported_response_mode");
      }
    });
  }
  for (const node of context.nodes.filter((item) => item.type === codeNode)) {
    evaluate(result, node, "/parameters/jsCode", () => {
      const location = locationFor(node, "/parameters/jsCode");
      if (node.disabled) {
        diagnostic(result, location, "disabled_node_not_executed");
        return;
      }
      if (![1, 2].includes(node.typeVersion)) {
        diagnostic(result, location, "unsupported_code_profile");
        return;
      }
      const language =
        node.typeVersion === 1
          ? "javaScript"
          : (node.parameters.language ?? "javaScript");
      if (language !== "javaScript") {
        diagnostic(result, location, "unsupported_code_language");
        return;
      }
      if (typeof node.parameters.jsCode !== "string") {
        diagnostic(result, location, "javascript_source_missing");
        return;
      }
      try {
        if (
          inspectJavaScript(node.parameters.jsCode).has(
            "javascript_whole_input_log_call",
          )
        ) {
          const added = finding(
            result,
            location,
            "javascript_whole_input_log_call",
            [],
            "candidate",
            "medium",
          );
          added?.assumptions.push(
            "lexical_binding_unverified",
            "bounded_ast_patterns_only",
          );
        }
        diagnostic(
          result,
          location,
          "code_logging_and_sensitivity_partially_analyzed",
        );
      } catch {
        diagnostic(result, location, "javascript_parse_unavailable");
      }
    });
  }
}

/** Stop and Error stores the chosen message, or every field of errorObject as
 * error metadata. It is an output sink even though it has no main output port.
 * This reports potential sensitive error contents, never actual log delivery. */
function errorOutputRule(context: FlowContext, result: RuleResult): void {
  const flow = buildValueFlow(context);
  for (const node of context.nodes.filter(
    (item) => item.type === stopAndError,
  )) {
    evaluate(result, node, "/parameters", () => {
      const location = locationFor(node, "/parameters");
      if (node.disabled) {
        diagnostic(result, location, "disabled_node_not_executed");
        return;
      }
      if (node.typeVersion !== 1) {
        diagnostic(result, location, "unsupported_error_output_profile");
        return;
      }
      if (!safeExecution(node))
        diagnostic(result, location, "nonstandard_execution_semantics");
      const mode =
        node.parameters.errorType === undefined
          ? "errorMessage"
          : node.parameters.errorType;
      const validMode = mode === "errorMessage" || mode === "errorObject";
      if (!validMode)
        diagnostic(result, location, "unsupported_error_output_mode");
      const fields = validMode ? [mode] : ["errorMessage", "errorObject"];
      for (const field of fields) {
        const payload = node.parameters[field];
        const selected = locationFor(node, "/parameters/" + field);
        if (typeof payload !== "string") {
          diagnostic(result, selected, "error_payload_unavailable");
          continue;
        }
        let value;
        if (field === "errorObject" && !payload.startsWith("=")) {
          if (payload.length > 65536) {
            diagnostic(result, selected, "error_payload_analysis_limit");
            continue;
          }
          try {
            const parsed: unknown = JSON.parse(payload);
            if (!isObject(parsed))
              diagnostic(result, selected, "error_payload_object_unverified");
            // Parse the JSON as literal data. A string that resembles an n8n
            // expression inside metadata must never become an executed read.
            value = flow.resolveExpression(node.key, JSON.stringify(parsed));
          } catch {
            diagnostic(result, selected, "error_payload_json_unverified");
            continue;
          }
        } else {
          value = flow.resolve(node.key, payload);
        }
        const evidence: Finding["evidence"] = [];
        for (const origin of value.origins) {
          if (evidence.length >= 16) break;
          const source = context.nodeByKey.get(origin.nodeKey);
          if (
            source &&
            !evidence.some((item) => item.location.nodeKey === source.key)
          )
            evidence.push({
              code: "error_payload_origin",
              location: locationFor(source, "/parameters"),
            });
        }
        const candidates: [string, Finding["severity"]][] = [];
        if (value.sensitivityClasses.includes("secret_candidate"))
          candidates.push(["secret_candidate_in_error_payload", "high"]);
        if (value.sensitivityClasses.includes("pii_candidate"))
          candidates.push([
            "personal_data_candidate_in_error_payload",
            "medium",
          ]);
        if (
          value.fullObject &&
          value.origins.some((origin) => origin.kind !== "literal")
        )
          candidates.push(["whole_input_in_error_payload", "medium"]);
        for (const [code, severity] of candidates) {
          const added = finding(
            result,
            selected,
            code,
            evidence,
            "candidate",
            severity,
          );
          if (!added) continue;
          added.assumptions.push(
            "error_storage_visibility_unverified",
            "sensitivity_candidate_not_confirmed_content",
          );
          added.remediation = {
            code: "use_public_error_code_and_redact_metadata",
            checks: [
              "preserve_error_control_flow",
              "exclude_secrets_and_personal_data",
              "review_error_workflow_and_log_visibility",
              "rescan_same_profile",
            ],
          };
        }
        for (const code of value.diagnosticCodes.slice(0, 32))
          diagnostic(result, selected, code);
        if (
          value.status !== "resolved" ||
          value.sensitivityClasses.includes("unknown")
        )
          diagnostic(result, selected, "error_payload_provenance_unresolved");
      }
    });
  }
}

function reviewedBasicEffect(
  context: FlowContext,
  node: NormalizedNode,
): boolean {
  if (context.localEffects.has(node.key)) return true;
  const edges = [...context.edges, ...context.unsupportedEdges];
  const incoming = edges.filter((edge) => edge.to === node.key);
  const outgoing = edges.filter((edge) => edge.from === node.key);
  if (node.type === prefix + "stickyNote") {
    // Sticky Note 1 declares no input or output ports. Text remains subject to
    // content scanning; this does not permit a fabricated data-flow bridge.
    return node.typeVersion === 1 && !incoming.length && !outgoing.length;
  }
  const noOp = node.type === noop && node.typeVersion === 1;
  const intervalWait = isStaticIntervalWait(node);
  const conditionalNode =
    node.type === conditional && ifVersions.has(node.typeVersion);
  const trigger =
    (node.type === prefix + "manualTrigger" && node.typeVersion === 1) ||
    (node.type === prefix + "scheduleTrigger" &&
      scheduleVersions.has(node.typeVersion));
  if (!noOp && !intervalWait && !conditionalNode && !trigger) return false;
  if (
    !safeExecution(node) ||
    context.unsupportedEdges.some(
      (edge) => edge.from === node.key || edge.to === node.key,
    )
  )
    return false;
  // Manual emits an empty item; Schedule emits clock metadata. Neither is an
  // incoming Webhook value carrier. Their downstream data stays unproven.
  return (
    incoming.every((edge) => !trigger && edge.input === 0) &&
    outgoing.every((edge) => edge.output < (conditionalNode ? 2 : 1))
  );
}

function addUnknownCoverage(context: FlowContext, results: RuleResult[]): void {
  for (const result of results) {
    for (const node of context.nodes.filter(
      (item) =>
        !inspectedTypes.has(item.type) &&
        !reviewedBasicEffect(context, item) &&
        !(
          result.category === "output" &&
          (item.type === codeNode || item.type === stopAndError)
        ),
    )) {
      const location = locationFor(node);
      const id = stableId(result.ruleId, location, "opaque_node_effects");
      result.diagnostics.push({ id, code: "opaque_node_effects", location });
      result.coverage.push({
        location,
        status: "unsupported",
        findingIds: [],
        diagnosticIds: [id],
      });
    }
    if (context.topology === "partial") {
      const id = stableId(
        result.ruleId,
        rootLocation,
        "partial_workflow_topology",
      );
      result.diagnostics.push({
        id,
        code: "partial_workflow_topology",
        location: rootLocation,
      });
      result.coverage.push({
        location: rootLocation,
        status: "partial",
        findingIds: [],
        diagnosticIds: [id],
      });
    }
    if (!result.coverage.length)
      result.coverage.push({
        location: rootLocation,
        status: "not_applicable",
        findingIds: [],
        diagnosticIds: [],
      });
  }
}

/** Analyze declared fields and bounded paths without evaluating any expression. */
export function analyzeFlow(input: Context): RuleResult[] {
  const context: FlowContext = {
    ...input,
    localEffects: localDataEffects(input),
  };
  const egress = rule("N8N_HTTP_EGRESS", "egress");
  const ssrf = rule("N8N_HTTP_SSRF", "ssrf");
  const sql = rule("N8N_SQL_TEXT_FLOW", "sql");
  const output = rule("N8N_RESPONSE_EXPOSURE", "output");
  httpRules(context, egress, ssrf);
  sqlRule(context, sql);
  outputRule(context, output);
  const results = [egress, ssrf, sql, output];
  addUnknownCoverage(context, results);
  return results;
}
