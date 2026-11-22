import { createHash } from "node:crypto";
import { identityOf, resultVersions } from "./contract.js";
import type {
  Coverage,
  Diagnostic,
  Finding,
  Identity,
  Result,
} from "./contract.js";
import { parseReference, parseWorkflow, WorkflowError } from "./n8n.js";
import type { NormalizedNode, NormalizedWorkflow, Reference } from "./n8n.js";

const webhookType = "n8n-nodes-base.webhook";
const ifType = "n8n-nodes-base.if";
const postgresType = "n8n-nodes-base.postgres";
const ruleId = "N8N_POSTGRES_DYNAMIC_QUERY";

type ObjectValue = Record<string, unknown>;
type Location = Coverage["sink"];
type Route = {
  webhook: NormalizedNode;
  postgres: NormalizedNode;
  conditional?: { node: NormalizedNode; branch: 0 | 1 };
};
type Guard = { field: string; literal: number };
type QueryValue =
  | { mode: "constant" }
  | { mode: "bound" | "interpolated"; reference: Reference };

const shape =
  /^[ \t\r\n]*SELECT[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]+FROM[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]+WHERE[ \t\r\n]+([A-Za-z_][A-Za-z0-9_]*)[ \t\r\n]*=[ \t\r\n]*([^]*)$/i;

function hashParts(...parts: unknown[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function location(node: NormalizedNode, suffix = ""): Location {
  return { nodeKey: node.key, pointer: node.pointer + suffix };
}

function allowedObject(
  value: unknown,
  keys: readonly string[],
): ObjectValue | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return;
  const object = value as ObjectValue;
  if (Object.keys(object).every((key) => keys.includes(key))) return object;
}

function optionalObject(
  value: unknown,
  keys: readonly string[],
): ObjectValue | undefined {
  return value === undefined ? {} : allowedObject(value, keys);
}

function routeFor(workflow: NormalizedWorkflow): Route | undefined {
  const { nodes, edges } = workflow;
  const webhook = nodes.find((node) => node.type === webhookType);
  const postgres = nodes.find((node) => node.type === postgresType);
  if (
    !webhook ||
    !postgres ||
    nodes.length < 2 ||
    nodes.length > 3 ||
    edges.length !== nodes.length - 1
  )
    return;
  const first = edges.find(
    (edge) =>
      edge.from === webhook.key && edge.output === 0 && edge.input === 0,
  );
  if (!first) return;
  if (first.to === postgres.key)
    return nodes.length === 2 ? { webhook, postgres } : undefined;
  const intermediate = nodes.find(
    (node) => node.key === first.to && node.type === ifType,
  );
  const last = edges.find(
    (edge) =>
      edge.from === first.to && edge.to === postgres.key && edge.input === 0,
  );
  if (!intermediate || !last || (last.output !== 0 && last.output !== 1))
    return;
  return {
    webhook,
    postgres,
    conditional: { node: intermediate, branch: last.output },
  };
}

function defaultNodeExecution(node: NormalizedNode): boolean {
  const {
    continueOnFail,
    onError,
    alwaysOutputData,
    executeOnce,
    retryOnFail,
    rewireOutputLogTo,
    forceCustomOperation,
  } = node.raw;
  return (
    (continueOnFail === undefined || continueOnFail === false) &&
    (onError === undefined || onError === "stopWorkflow") &&
    (alwaysOutputData === undefined || alwaysOutputData === false) &&
    (executeOnce === undefined || executeOnce === false) &&
    (retryOnFail === undefined || retryOnFail === false) &&
    rewireOutputLogTo === undefined &&
    forceCustomOperation === undefined
  );
}

function webhookProfile(
  node: NormalizedNode,
): [string, string, string] | undefined {
  const params = allowedObject(node.parameters, [
    "httpMethod",
    "path",
    "authentication",
    "responseMode",
    "options",
    "multipleMethods",
  ]);
  if (
    !params ||
    params.httpMethod !== "POST" ||
    !optionalObject(params.options, [])
  )
    return;
  if (!(
    params.multipleMethods === undefined || params.multipleMethods === false
  ))
    return;
  if (!(
    params.authentication === undefined || params.authentication === "none"
  ))
    return;
  const path = params.path;
  const registration = node.raw.webhookId;
  const response =
    params.responseMode === undefined ? "onReceived" : params.responseMode;
  if (
    typeof path === "string" &&
    /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(path) &&
    (response === "onReceived" || response === "lastNode") &&
    (registration === undefined ||
      (typeof registration === "string" && registration.length > 0))
  )
    return [
      path,
      response,
      registration === undefined
        ? hashParts("name-based", node.name.toLowerCase())
        : "fixed-path",
    ];
}

function credentialReference(node: NormalizedNode): string | null | undefined {
  const credentials = node.raw.credentials;
  if (credentials === undefined) return null;
  const assigned = allowedObject(credentials, ["postgres"]);
  if (!assigned) return undefined;
  if (assigned.postgres === undefined) return null;
  const reference = allowedObject(assigned.postgres, ["id", "name"]);
  if (typeof reference?.id === "string" && reference.id.length > 0)
    return hashParts("id", reference.id);
  if (
    (reference?.id === undefined || reference.id === null) &&
    typeof reference?.name === "string" &&
    reference.name.length > 0
  )
    return hashParts("name", reference.name);
}

function fromWebhook(
  reference: Reference | undefined,
  node: NormalizedNode,
): reference is Reference {
  return (
    reference !== undefined &&
    (reference.kind === "current" || reference.nodeName === node.name) &&
    !["__proto__", "constructor", "prototype"].includes(reference.field)
  );
}

function conditionProfile(
  node: NormalizedNode,
  webhook: NormalizedNode,
): Guard | undefined {
  const params = allowedObject(node.parameters, [
    "conditions",
    "looseTypeValidation",
    "options",
  ]);
  if (!params || !optionalObject(params.options, [])) return;
  if (!(
    params.looseTypeValidation === undefined ||
    params.looseTypeValidation === false
  ))
    return;
  const filter = allowedObject(params.conditions, [
    "options",
    "conditions",
    "combinator",
  ]);
  if (
    !filter ||
    filter.combinator !== "and" ||
    !Array.isArray(filter.conditions) ||
    filter.conditions.length !== 1
  )
    return;
  const options = allowedObject(filter.options, [
    "caseSensitive",
    "leftValue",
    "typeValidation",
    "version",
  ]);
  if (
    options?.caseSensitive !== true ||
    options.leftValue !== "" ||
    options.typeValidation !== "strict" ||
    options.version !== 2
  )
    return;
  const condition = allowedObject(filter.conditions[0], [
    "id",
    "leftValue",
    "rightValue",
    "operator",
  ]);
  if (
    typeof condition?.leftValue !== "string" ||
    !Number.isSafeInteger(condition.rightValue)
  )
    return;
  const operator = allowedObject(condition.operator, ["type", "operation"]);
  if (operator?.type !== "number" || operator.operation !== "equals") return;
  const inner = /^=\{\{([^{}]+)\}\}$/.exec(condition.leftValue)?.[1];
  const reference = inner === undefined ? undefined : parseReference(inner);
  if (fromWebhook(reference, webhook)) {
    return { field: reference.field, literal: condition.rightValue as number };
  }
}

function queryValue(
  operand: string,
  expressionMode: boolean,
  parameter: unknown,
  webhook: NormalizedNode,
): QueryValue | undefined {
  let binding: Reference | undefined;
  if (parameter !== undefined) {
    if (typeof parameter !== "string") return;
    const inner = /^=\{\{\s*\[([^{}[\]]+)\]\s*\}\}$/.exec(parameter)?.[1];
    binding = inner === undefined ? undefined : parseReference(inner);
    if (!fromWebhook(binding, webhook)) return;
  }
  if (operand === "$1" && !expressionMode && binding)
    return { mode: "bound", reference: binding };
  const template = /^\{\{([^{}]+)\}\}$/.exec(operand)?.[1];
  if (template !== undefined) {
    const reference = parseReference(template);
    if (fromWebhook(reference, webhook))
      return { mode: "interpolated", reference };
    return;
  }
  if (
    !expressionMode &&
    !binding &&
    /^-?[0-9]+$/.test(operand) &&
    Number.isSafeInteger(Number(operand))
  ) {
    return { mode: "constant" };
  }
}

function trimSqlWhitespace(text: string): string {
  const whitespace = (character: string | undefined) =>
    character === " " ||
    character === "\t" ||
    character === "\r" ||
    character === "\n";
  let start = 0;
  let end = text.length;
  while (start < end && whitespace(text[start])) start++;
  while (end > start && whitespace(text[end - 1])) end--;
  return text.slice(start, end);
}

export function analyzeWorkflow(bytes: Buffer, identity: Identity): Result {
  const header = { ...identityOf(identity), ...resultVersions };
  let workflow: NormalizedWorkflow;
  try {
    workflow = parseWorkflow(bytes);
  } catch (error) {
    if (!(error instanceof WorkflowError)) throw error;
    return {
      ...header,
      status: "error",
      code: error.code,
      ...(error.pointer ? { location: error.pointer } : {}),
    };
  }

  const sinks = workflow.nodes.filter(
    ({ type, parameters }) =>
      type === postgresType &&
      parameters.resource === "database" &&
      parameters.operation === "executeQuery",
  );
  const unknownCoverage: Coverage[] = sinks.map((node) => ({
    sink: location(node, "/parameters/query"),
    disposition: "unknown",
    inputKey: null,
    shapeKey: null,
  }));
  const unsupported = (diagnostics: Diagnostic[]): Result => {
    const affectedNodeKeys = [
      ...new Set(diagnostics.flatMap(({ affected }) => affected)),
    ].sort();
    return {
      ...header,
      status: "unsupported",
      coverage: unknownCoverage,
      findings: [],
      affectedNodeKeys,
      diagnostics: diagnostics.map(({ affected, ...item }) => ({
        ...item,
        affected: affected.map((key) => affectedNodeKeys.indexOf(key)),
      })),
    };
  };
  if (workflow.diagnostics.length) return unsupported(workflow.diagnostics);
  if (!sinks.length) {
    return unsupported([
      { code: "no_supported_sink", location: "/nodes", affected: [] },
    ]);
  }
  const route = routeFor(workflow);
  const affected = sinks.map(({ key }) => key);
  const fail = (code: Diagnostic["code"], pos: string) =>
    unsupported([{ code, location: pos, affected }]);
  if (!route) return fail("unsupported_topology", "/connections");

  const nonstandard = workflow.nodes.find(
    (node) => !defaultNodeExecution(node),
  );
  if (nonstandard) return fail("unsupported_config", nonstandard.pointer);
  const { webhook, postgres, conditional } = route;
  const trigger = webhookProfile(webhook);
  if (!trigger)
    return fail("unsupported_config", webhook.pointer + "/parameters");

  const guard = conditional && conditionProfile(conditional.node, webhook);
  if (conditional && !guard)
    return fail(
      "unsupported_config",
      conditional.node.pointer + "/parameters/conditions",
    );

  const sink = location(postgres, "/parameters/query");
  const params = allowedObject(postgres.parameters, [
    "resource",
    "operation",
    "query",
    "options",
  ]);
  const options =
    params && optionalObject(params.options, ["queryReplacement"]);
  if (!params || !options || typeof params.query !== "string") {
    return fail("unsupported_config", postgres.pointer + "/parameters");
  }
  const connection = credentialReference(postgres);
  if (connection === undefined)
    return fail("unsupported_config", postgres.pointer + "/credentials");

  const expressionMode = params.query.startsWith("=");
  const statement = expressionMode ? params.query.slice(1) : params.query;
  const parsed = shape.exec(statement);
  if (!parsed?.[1] || !parsed[2] || !parsed[3] || !parsed[4])
    return fail("unsupported_expression", sink.pointer);
  const sqlOperand = trimSqlWhitespace(parsed[4]);
  const value = queryValue(
    sqlOperand,
    expressionMode,
    options.queryReplacement,
    webhook,
  );
  if (!value) return fail("unsupported_expression", sink.pointer);
  const shapeKey = hashParts(
    parsed[1].toLowerCase(),
    parsed[2].toLowerCase(),
    parsed[3].toLowerCase(),
    trigger,
    conditional && guard
      ? [conditional.node.key, conditional.branch, guard.field, guard.literal]
      : null,
    connection,
  );
  const inputKey =
    value.mode === "constant"
      ? null
      : hashParts(webhook.key, "body." + value.reference.field);
  const guarded =
    value.mode === "interpolated" && guard?.field === value.reference.field;
  const coverage: Coverage[] = [
    {
      sink,
      disposition: guarded ? "guarded" : value.mode,
      inputKey,
      shapeKey,
    },
  ];
  const findings: Finding[] = [];
  if (value.mode === "interpolated" && !guarded) {
    const source = location(webhook);
    const path = conditional
      ? [source, location(conditional.node), sink]
      : [source, sink];
    findings.push({
      id: hashParts(ruleId, source.nodeKey, sink.nodeKey, inputKey, "query"),
      ruleId,
      source,
      sink,
      path,
      reference:
        value.reference.kind === "direct" ? "direct_source" : "current_input",
      guard: !conditional
        ? "absent"
        : conditional.branch === 1
          ? "reject_branch"
          : "unrelated_value",
      assumptions: ["single_json_webhook_item", "pinned_node_semantics"],
      remediation: {
        strategy: "use_value_parameter",
        binding: location(postgres, "/parameters/options/queryReplacement"),
        checks: [
          "fixed_sql_value_position",
          "expected_rows_and_side_effects",
          "rescan_same_rules",
        ],
      },
    });
  }
  return { ...header, status: "analyzed", coverage, findings, diagnostics: [] };
}
