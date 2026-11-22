import { createHash } from "node:crypto";
import { parse, parseExpressionAt } from "acorn";
import sqlParser from "node-sql-parser";
import type { Context } from "./static-context.js";
import { isObject } from "./static-context.js";
import type { NormalizedNode } from "./n8n.js";
import { locationFor, stableId } from "./static-contract.js";
import type { Finding, RuleResult } from "./static-contract.js";
import { buildValueFlow } from "./value-flow.js";
import type { AbstractValue, ValueFlow } from "./value-flow.js";

export type SqlDialect = "Postgresql" | "MySQL" | "TransactSQL";
export type SqlOperation =
  | "select"
  | "insert"
  | "update"
  | "delete"
  | "drop"
  | "alter"
  | "create"
  | "truncate"
  | "execute"
  | "unknown";
export interface SqlOperationDescription {
  status: "parsed" | "unsupported";
  operations: SqlOperation[];
  statementCount: number;
  valueParameterCount: number;
  structureHash: string | null;
  diagnosticCodes: string[];
}
const parser = new sqlParser.Parser();
const prefix = "n8n-nodes-base.";
const hash = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const operationNames = new Set([
  "select",
  "insert",
  "update",
  "delete",
  "drop",
  "alter",
  "create",
  "truncate",
  "execute",
]);

export function inspectSqlOperation(
  query: string,
  dialect: SqlDialect = "Postgresql",
): SqlOperationDescription {
  const unavailable = (code: string): SqlOperationDescription => ({
    status: "unsupported",
    operations: [],
    statementCount: 0,
    valueParameterCount: 0,
    structureHash: null,
    diagnosticCodes: [code],
  });
  if (query.length > 16384) return unavailable("sql_parser_input_limit");
  try {
    const parsed = parser.astify(query, { database: dialect }) as unknown;
    const statements = Array.isArray(parsed) ? parsed : [parsed];
    if (statements.length > 32 || statements.some((item) => !isObject(item)))
      return unavailable("sql_statement_profile_unsupported");
    const operations: SqlOperation[] = statements.map((item) =>
      isObject(item) &&
      typeof item.type === "string" &&
      operationNames.has(item.type)
        ? (item.type as SqlOperation)
        : "unknown",
    );
    let count = 0,
      parameters = 0;
    const pending: unknown[] = [parsed];
    while (pending.length) {
      const value = pending.pop();
      if (Array.isArray(value)) {
        pending.push(...value);
        continue;
      }
      if (!isObject(value)) continue;
      if (++count > 4096) return unavailable("sql_ast_limit");
      if (
        typeof value.type === "string" &&
        operationNames.has(value.type) &&
        !operations.includes(value.type as SqlOperation)
      )
        operations.push(value.type as SqlOperation);
      if (
        (value.type === "var" && value.prefix === "$") ||
        (value.type === "origin" && value.value === "?") ||
        (dialect === "TransactSQL" &&
          value.type === "column_ref" &&
          typeof value.column === "string" &&
          /^@[A-Za-z_][A-Za-z0-9_]*$/.test(value.column))
      )
        parameters++;
      for (const child of Object.values(value))
        if (isObject(child) || Array.isArray(child)) pending.push(child);
    }
    return {
      status: "parsed",
      operations,
      statementCount: statements.length,
      valueParameterCount: parameters,
      structureHash: hash(parsed),
      diagnosticCodes: [],
    };
  } catch {
    return unavailable("sql_parse_unsupported");
  }
}

function rule(ruleId: string, category: "sql" | "code_execution"): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.0.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}
class Scope {
  private readonly findings: string[] = [];
  private readonly diagnostics: string[] = [];
  constructor(
    private readonly result: RuleResult,
    private readonly node: NormalizedNode,
  ) {}
  diagnostic(code: string): void {
    if (this.result.diagnostics.length >= 127) {
      const location = { nodeKey: null, pointer: "/nodes" };
      const id = stableId(this.result.ruleId, location, "diagnostic_limit");
      if (!this.result.diagnostics.some((item) => item.id === id))
        this.result.diagnostics.push({
          id,
          code: "diagnostic_limit",
          location,
        });
      if (!this.diagnostics.includes(id)) this.diagnostics.push(id);
      return;
    }
    const location = locationFor(this.node, "/parameters");
    const id = stableId(this.result.ruleId, location, code);
    if (this.result.diagnostics.some((item) => item.id === id)) return;
    this.result.diagnostics.push({ id, code, location });
    this.diagnostics.push(id);
  }
  add(
    code: string,
    severity: Finding["severity"],
    claim: Finding["claim"],
    value?: AbstractValue,
    extraCodes: string[] = [],
  ): void {
    const location = locationFor(this.node, "/parameters");
    const id = stableId(this.result.ruleId, location, code);
    if (this.result.findings.some((item) => item.id === id)) return;
    if (this.result.findings.length >= 128) {
      this.diagnostic("finding_limit");
      return;
    }
    const evidence: Finding["evidence"] = [
      { code, location },
      ...extraCodes.map((entry) => ({ code: entry, location })),
    ];
    for (const origin of value?.origins.slice(0, 8) ?? []) {
      const source = this.nodeContext?.nodeByKey.get(origin.nodeKey);
      if (source)
        evidence.push({
          code: "declared_value_origin",
          location: locationFor(source),
        });
    }
    this.result.findings.push({
      id,
      ruleId: this.result.ruleId,
      category: this.result.category,
      severity,
      claim,
      location,
      evidence,
      assumptions: [
        "static_definition_only",
        "runtime_permissions_unverified",
        ...(claim === "candidate" ? ["execution_reachability_unverified"] : []),
      ],
      remediation: {
        code: "review_context_specific_input_handling",
        checks: [
          "preserve_required_operation",
          "verify_same_value_binding",
          "rescan_same_profile",
          "verify_runtime_conditions",
        ],
      },
    });
    this.findings.push(id);
  }
  nodeContext?: Context;
  finish(): void {
    this.result.coverage.push({
      location: locationFor(this.node, "/parameters"),
      status: this.diagnostics.length
        ? this.findings.length
          ? "partial"
          : "unsupported"
        : "checked",
      findingIds: this.findings,
      diagnosticIds: this.diagnostics,
    });
  }
}
function finish(result: RuleResult): RuleResult {
  if (!result.coverage.length)
    result.coverage.push({
      location: { nodeKey: null, pointer: "/nodes" },
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  return result;
}
const postgresVersions = new Set([2.5, 2.6, 2.8]);
const mysqlVersions = new Set([2, 2.1, 2.2, 2.3, 2.4, 2.5]);
const mssqlVersions = new Set([1, 1.1, 1.2]);

interface SqlTemplate {
  expression: string;
  offset: number;
  end: number;
  quoted: boolean;
  valuePosition: boolean;
}
function sqlTemplates(query: string): SqlTemplate[] {
  const templates: SqlTemplate[] = [];
  let quote: string | undefined, comment: "line" | "block" | undefined;
  for (let index = 0; index < query.length; index++) {
    if (query.startsWith("{{", index)) {
      const end = query.indexOf("}}", index + 2);
      if (end < 0) break;
      const before = query.slice(0, index);
      // A narrow scalar comparator profile; identifiers, comments, quoted text,
      // and SQL structure positions never inherit a numeric value guard.
      const valuePosition =
        !quote && !comment && /(?:=|<>|!=|<=|>=|<|>)\s*$/.test(before);
      templates.push({
        expression: query.slice(index, end + 2),
        offset: index,
        end: end + 2,
        quoted: !!quote || !!comment,
        valuePosition,
      });
      index = end + 1;
      continue;
    }
    if (comment === "line") {
      if (query[index] === "\n") comment = undefined;
      continue;
    }
    if (comment === "block") {
      if (query.startsWith("*/", index)) {
        comment = undefined;
        index++;
      }
      continue;
    }
    if (quote) {
      if (query[index] === quote) {
        if (query[index + 1] === quote) index++;
        else quote = undefined;
      } else if (query[index] === "\\") index++;
      continue;
    }
    if (query.startsWith("--", index)) {
      comment = "line";
      index++;
    } else if (query.startsWith("/*", index)) {
      comment = "block";
      index++;
    } else if (["'", '"', "`"].includes(query[index]!)) quote = query[index];
  }
  return templates;
}
function replacementCount(value: unknown): number | undefined {
  if (Array.isArray(value)) return value.length;
  if (typeof value !== "string" || !value.startsWith("=")) return;
  const expression = /^=\s*\{\{([\s\S]*)\}\}\s*$/.exec(value)?.[1];
  if (!expression) return;
  try {
    const ast = parseExpressionAt(expression, 0, {
      ecmaVersion: "latest",
    }) as unknown;
    if (
      isObject(ast) &&
      ast.type === "ArrayExpression" &&
      Array.isArray(ast.elements) &&
      typeof ast.end === "number" &&
      !expression.slice(ast.end).trim() &&
      !ast.elements.some(
        (entry) => isObject(entry) && entry.type === "SpreadElement",
      )
    )
      return ast.elements.length;
  } catch {
    /* qualified below */
  }
}

function outsideSqlText(query: string): string {
  let masked = "",
    quote: string | undefined,
    block = false,
    line = false,
    dollar: string | undefined;
  for (let index = 0; index < query.length; index++) {
    if (dollar) {
      if (query.startsWith(dollar, index)) {
        masked += " ".repeat(dollar.length);
        index += dollar.length - 1;
        dollar = undefined;
      } else masked += " ";
      continue;
    }
    if (line) {
      masked += " ";
      if (query[index] === "\n") line = false;
      continue;
    }
    if (block) {
      masked += " ";
      if (query.startsWith("*/", index)) {
        masked += " ";
        index++;
        block = false;
      }
      continue;
    }
    if (quote) {
      masked += " ";
      if (query[index] === quote) {
        if (query[index + 1] === quote) {
          masked += " ";
          index++;
        } else quote = undefined;
      } else if (query[index] === "\\" && quote !== "]") {
        masked += " ";
        index++;
      }
      continue;
    }
    const tag = /^(\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$)/.exec(
      query.slice(index),
    )?.[1];
    if (tag) {
      dollar = tag;
      masked += " ".repeat(tag.length);
      index += tag.length - 1;
    } else if (query.startsWith("--", index)) {
      line = true;
      masked += "  ";
      index++;
    } else if (query.startsWith("/*", index)) {
      block = true;
      masked += "  ";
      index++;
    } else if (["'", '"', "`", "["].includes(query[index]!)) {
      quote = query[index] === "[" ? "]" : query[index];
      masked += " ";
    } else masked += query[index];
  }
  return masked;
}

function sqlRules(context: Context, flow: ValueFlow): RuleResult {
  const result = rule("N8N_ADVANCED_SQL", "sql");
  for (const node of context.nodes.filter((item) =>
    [prefix + "postgres", prefix + "mySql", prefix + "microsoftSql"].includes(
      item.type,
    ),
  )) {
    const scope = new Scope(result, node);
    scope.nodeContext = context;
    const dialect: SqlDialect =
      node.type === prefix + "postgres"
        ? "Postgresql"
        : node.type === prefix + "mySql"
          ? "MySQL"
          : "TransactSQL";
    const versions =
      dialect === "Postgresql"
        ? postgresVersions
        : dialect === "MySQL"
          ? mysqlVersions
          : mssqlVersions;
    if (node.disabled || !versions.has(node.typeVersion)) {
      scope.diagnostic(
        node.disabled
          ? "disabled_node_not_executed"
          : "unsupported_node_version",
      );
      scope.finish();
      continue;
    }
    if (
      (node.parameters.operation ?? "insert") !== "executeQuery" ||
      (dialect !== "TransactSQL" &&
        (node.parameters.resource ?? "database") !== "database")
    ) {
      scope.diagnostic("database_operation_profile_unsupported");
      scope.finish();
      continue;
    }
    const raw = node.parameters.query;
    if (typeof raw !== "string") {
      scope.diagnostic("query_unavailable");
      scope.finish();
      continue;
    }
    const query = raw.startsWith("=") ? raw.slice(1) : raw;
    const templates = sqlTemplates(query);
    let structure = query;
    for (const [index, template] of [...templates.entries()].reverse())
      structure =
        structure.slice(0, template.offset) +
        (template.valuePosition
          ? String(970000 + index)
          : "__workflow_template_" + index) +
        structure.slice(template.end);
    // n8n MySQL and MSSQL expose $N; their adapters convert them to native
    // driver placeholders. :name is an identifier formatting mode, not a value.
    const outside = outsideSqlText(query);
    const identifiers = [
      ...outside.matchAll(/\$(\d+):(name|csv|raw|value|alias)/g),
    ];
    const placeholders = [...outside.matchAll(/\$(\d+)(?!\d|:)/g)].map(
      (match) => Number(match[1]),
    );
    if (dialect !== "Postgresql")
      structure = structure.replace(/\$(\d+)(?!\d|:)/g, (_, index: string) =>
        dialect === "MySQL" ? "?" : "@p" + index,
      );
    const operation = inspectSqlOperation(structure, dialect);
    if (operation.status === "parsed")
      scope.add(
        "sql_operation_capability",
        "info",
        "configuration",
        undefined,
        [...new Set(operation.operations)].map(
          (name) => "sql_operation_" + name,
        ),
      );
    else for (const code of operation.diagnosticCodes) scope.diagnostic(code);
    const options = isObject(node.parameters.options)
      ? node.parameters.options
      : {};
    if (
      options.queryReplacement !== undefined &&
      [...query.matchAll(/\$(\d+)(?!\d|:)/g)].length !== placeholders.length
    )
      scope.diagnostic("sql_quoted_parameter_mapping_unverified");
    if (identifiers.length) {
      scope.add(
        "sql_identifier_or_raw_format_review",
        "medium",
        "configuration",
      );
      scope.diagnostic("sql_identifier_value_binding_not_equivalent");
      if (identifiers.some((match) => ["raw", "value"].includes(match[2]!)))
        scope.add("sql_raw_format_input_candidate", "high", "candidate");
    }
    if (placeholders.length) {
      const count = replacementCount(options.queryReplacement);
      if (
        count !== undefined &&
        count >= Math.max(...placeholders) &&
        placeholders.every((number) => number >= 1) &&
        !identifiers.length &&
        operation.status === "parsed"
      )
        scope.add("sql_value_binding_configured", "info", "configuration");
      else scope.diagnostic("sql_parameter_binding_unresolved");
    }
    if (
      dialect === "TransactSQL" &&
      /@[A-Za-z_]/.test(query) &&
      !placeholders.length
    )
      scope.diagnostic("sql_native_parameter_mapping_unverified");
    if (dialect === "MySQL" && query.includes("?") && !placeholders.length)
      scope.diagnostic("sql_native_parameter_mapping_unverified");
    if (!templates.length && raw.startsWith("="))
      scope.diagnostic("sql_dynamic_expression_unresolved");
    for (const template of templates) {
      const value = flow.resolve(node.key, "=" + template.expression);
      const numeric =
        operation.status === "parsed" &&
        operation.statementCount === 1 &&
        template.valuePosition &&
        value.status === "resolved" &&
        value.guards.some(
          (guard) =>
            guard.kind === "number_type" && guard.valueId === value.valueId,
        );
      if (!numeric)
        scope.add(
          template.valuePosition
            ? "sql_text_input_candidate"
            : "sql_structure_or_quoted_input_candidate",
          "high",
          value.status === "resolved" &&
            value.origins.some((origin) => origin.kind === "webhook")
            ? "supported_path"
            : "candidate",
          value,
        );
      else
        scope.add(
          "sql_numeric_value_guard_observed",
          "info",
          "configuration",
          value,
        );
      if (value.status !== "resolved")
        scope.diagnostic("sql_input_flow_partially_analyzed");
    }
    if (
      node.raw.continueOnFail === true ||
      (node.raw.onError !== undefined && node.raw.onError !== "stopWorkflow")
    )
      scope.diagnostic("nonstandard_execution_semantics");
    scope.finish();
  }
  return finish(result);
}

interface Binding {
  value?: AbstractValue;
  module?: string;
  member?: string;
}
const member = (ast: Record<string, unknown>): string | undefined => {
  if (ast.type !== "MemberExpression" || !isObject(ast.property)) return;
  const name =
    ast.computed === true
      ? ast.property.type === "Literal"
        ? ast.property.value
        : undefined
      : ast.property.name;
  return typeof name === "string" ? name : undefined;
};
const hasExternal = (value: AbstractValue | undefined): boolean =>
  !!value &&
  (value.trust === "external" ||
    value.origins.some(
      (origin) => origin.kind === "webhook" || origin.kind === "subworkflow",
    ));

function javascriptRules(context: Context, flow: ValueFlow): RuleResult {
  const result = rule("N8N_ADVANCED_EXECUTION", "code_execution");
  for (const node of context.nodes.filter((item) =>
    [prefix + "code", prefix + "executeCommand", prefix + "ssh"].includes(
      item.type,
    ),
  )) {
    const scope = new Scope(result, node);
    scope.nodeContext = context;
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    if (node.type !== prefix + "code") {
      if (
        node.typeVersion !== 1 ||
        (node.type === prefix + "ssh" &&
          (node.parameters.resource ?? "command") !== "command")
      ) {
        scope.diagnostic("command_profile_unsupported");
        scope.finish();
        continue;
      }
      const command = node.parameters.command;
      if (typeof command !== "string")
        scope.diagnostic("command_content_missing");
      else {
        scope.add("command_execution_capability", "medium", "configuration");
        if (command.startsWith("=")) {
          const value = flow.resolve(node.key, command);
          scope.add(
            hasExternal(value)
              ? "command_external_value_candidate"
              : "command_dynamic_value_candidate",
            "high",
            "candidate",
            value,
          );
          if (value.status !== "resolved")
            scope.diagnostic("command_input_flow_partially_analyzed");
        }
      }
      scope.finish();
      continue;
    }
    if (
      ![1, 2].includes(node.typeVersion) ||
      (node.typeVersion === 2 &&
        (node.parameters.language ?? "javaScript") !== "javaScript")
    ) {
      scope.diagnostic("javascript_profile_unsupported");
      scope.finish();
      continue;
    }
    const source = node.parameters.jsCode;
    if (typeof source !== "string" || source.length > 65536) {
      scope.diagnostic("javascript_source_unavailable");
      scope.finish();
      continue;
    }
    const textFor = (ast: Record<string, unknown>): string =>
      typeof ast.start === "number" && typeof ast.end === "number"
        ? source.slice(ast.start, ast.end)
        : "";
    const env = new Map<string, Binding>();
    let visited = 0;
    const valueFor = (
      ast: Record<string, unknown>,
      bindings: Map<string, Binding>,
      depth = 0,
    ): AbstractValue => {
      if (depth > 32)
        return flow.resolve(node.key, "={{ __unsupported_depth() }}");
      if (
        ast.type === "Identifier" &&
        typeof ast.name === "string" &&
        bindings.has(ast.name)
      )
        return (
          bindings.get(ast.name)?.value ??
          flow.resolve(node.key, "={{ __local_binding_unresolved() }}")
        );
      if (ast.type === "Literal") return flow.resolve(node.key, ast.value);
      const nested: AbstractValue[] = [];
      for (const child of Object.values(ast)) {
        if (isObject(child) && typeof child.type === "string")
          nested.push(valueFor(child, bindings, depth + 1));
        else if (Array.isArray(child))
          for (const entry of child)
            if (isObject(entry) && typeof entry.type === "string")
              nested.push(valueFor(entry, bindings, depth + 1));
      }
      const pending: unknown[] = [ast];
      let shadowsGlobal = false;
      while (pending.length) {
        const item = pending.pop();
        if (!isObject(item)) continue;
        if (
          item.type === "Identifier" &&
          ["$json", "$input", "$node", "$"].includes(String(item.name)) &&
          bindings.has(String(item.name))
        )
          shadowsGlobal = true;
        for (const child of Object.values(item)) {
          if (isObject(child)) pending.push(child);
          else if (Array.isArray(child)) pending.push(...child);
        }
      }
      const direct = flow.resolve(
        node.key,
        shadowsGlobal
          ? "={{ __local_binding_unresolved() }}"
          : "={{ " + textFor(ast) + " }}",
      );
      const inherited = nested.filter(hasExternal);
      if (!inherited.length) return direct;
      return {
        ...direct,
        status: direct.status === "resolved" ? "resolved" : "partial",
        trust: "external",
        origins: [
          ...new Map(
            [
              ...direct.origins,
              ...inherited.flatMap((value) => value.origins),
            ].map((origin) => [JSON.stringify(origin), origin]),
          ).values(),
        ].slice(0, 64),
        guards: [],
        diagnosticCodes: [
          ...new Set([
            ...direct.diagnosticCodes,
            "javascript_alias_flow_candidate",
          ]),
        ],
      };
    };
    const moduleFor = (
      ast: Record<string, unknown>,
      bindings: Map<string, Binding>,
    ): Binding | undefined => {
      if (ast.type === "Identifier" && typeof ast.name === "string")
        return (
          bindings.get(ast.name) ??
          (["eval", "Function", "fetch", "require"].includes(ast.name) &&
          !bindings.has(ast.name)
            ? { module: "global", member: ast.name }
            : undefined)
        );
      if (
        ast.type === "CallExpression" &&
        isObject(ast.callee) &&
        ast.callee.type === "Identifier" &&
        typeof ast.callee.name === "string" &&
        ((ast.callee.name === "require" && !bindings.has("require")) ||
          (bindings.get(ast.callee.name)?.module === "global" &&
            bindings.get(ast.callee.name)?.member === "require")) &&
        Array.isArray(ast.arguments) &&
        ast.arguments.length === 1 &&
        isObject(ast.arguments[0]) &&
        ast.arguments[0].type === "Literal" &&
        typeof ast.arguments[0].value === "string"
      )
        return { module: ast.arguments[0].value.replace(/^node:/, "") };
      if (ast.type === "MemberExpression" && isObject(ast.object)) {
        const parent = moduleFor(ast.object, bindings);
        if (parent?.module)
          return { module: parent.module, member: member(ast) };
      }
    };
    const visit = (
      ast: Record<string, unknown>,
      bindings: Map<string, Binding>,
      depth = 0,
    ): void => {
      if (++visited > 4096 || depth > 64) {
        scope.diagnostic("javascript_ast_limit");
        return;
      }
      if (
        (ast.type === "Program" || ast.type === "BlockStatement") &&
        Array.isArray(ast.body)
      ) {
        const local =
          ast.type === "BlockStatement" ? new Map(bindings) : bindings;
        const localNames = new Set<string>();
        const declare = (pattern: unknown): void => {
          if (!isObject(pattern)) return;
          if (
            pattern.type === "Identifier" &&
            typeof pattern.name === "string"
          ) {
            localNames.add(pattern.name);
            local.set(pattern.name, {});
          } else if (
            pattern.type === "ObjectPattern" &&
            Array.isArray(pattern.properties)
          ) {
            for (const property of pattern.properties)
              if (isObject(property))
                declare(property.value ?? property.argument);
          } else if (
            pattern.type === "ArrayPattern" &&
            Array.isArray(pattern.elements)
          )
            pattern.elements.forEach(declare);
        };
        for (const statement of ast.body)
          if (isObject(statement)) {
            if (
              statement.type === "VariableDeclaration" &&
              statement.kind !== "var" &&
              Array.isArray(statement.declarations)
            )
              for (const declaration of statement.declarations)
                if (isObject(declaration)) declare(declaration.id);
            if (statement.type === "FunctionDeclaration") declare(statement.id);
          }
        for (const statement of ast.body)
          if (isObject(statement)) visit(statement, local, depth + 1);
        if (local !== bindings)
          for (const [name, binding] of local)
            if (!localNames.has(name)) bindings.set(name, binding);
        return;
      }
      if (ast.type === "VariableDeclarator" && isObject(ast.id)) {
        const initial = isObject(ast.init) ? ast.init : undefined;
        const binding: Binding = initial
          ? {
              ...moduleFor(initial, bindings),
              value: valueFor(initial, bindings),
            }
          : ast.id.type === "Identifier" && typeof ast.id.name === "string"
            ? (bindings.get(ast.id.name) ?? {})
            : {};
        if (ast.id.type === "Identifier" && typeof ast.id.name === "string")
          bindings.set(ast.id.name, binding);
        else if (
          ast.id.type === "ObjectPattern" &&
          Array.isArray(ast.id.properties)
        )
          for (const property of ast.id.properties)
            if (
              isObject(property) &&
              isObject(property.key) &&
              isObject(property.value) &&
              property.value.type === "Identifier" &&
              typeof property.value.name === "string"
            )
              bindings.set(property.value.name, {
                module: binding.module,
                member:
                  typeof property.key.name === "string"
                    ? property.key.name
                    : typeof property.key.value === "string"
                      ? property.key.value
                      : undefined,
                value: (() => {
                  const key =
                    typeof property.key.name === "string"
                      ? property.key.name
                      : typeof property.key.value === "string"
                        ? property.key.value
                        : undefined;
                  if (!key || !binding.value) return undefined;
                  const part =
                    "/" + key.replace(/~/g, "~0").replace(/\//g, "~1");
                  if (binding.value.fields?.[part])
                    return binding.value.fields[part];
                  const origin = binding.value.origins[0];
                  return origin &&
                    binding.value.origins.length === 1 &&
                    origin.kind !== "literal" &&
                    binding.value.transforms.length === 0
                    ? flow.output(origin.nodeKey, origin.fieldPath + part)
                    : {
                        ...binding.value,
                        status: "partial" as const,
                        guards: [],
                      };
                })(),
              });
      }
      if (
        ast.type === "AssignmentExpression" &&
        isObject(ast.left) &&
        ast.left.type === "Identifier" &&
        typeof ast.left.name === "string" &&
        isObject(ast.right)
      )
        bindings.set(ast.left.name, {
          ...moduleFor(ast.right, bindings),
          value: valueFor(ast.right, bindings),
        });
      if (
        [
          "FunctionDeclaration",
          "FunctionExpression",
          "ArrowFunctionExpression",
        ].includes(String(ast.type))
      ) {
        const local = new Map(bindings);
        if (isObject(ast.id) && typeof ast.id.name === "string")
          bindings.set(ast.id.name, {});
        const bindParam = (param: unknown): void => {
          if (!isObject(param)) return;
          if (param.type === "Identifier" && typeof param.name === "string")
            local.set(param.name, {});
          else if (
            param.type === "ObjectPattern" &&
            Array.isArray(param.properties)
          ) {
            for (const property of param.properties)
              if (isObject(property))
                bindParam(property.value ?? property.argument);
          } else if (
            param.type === "ArrayPattern" &&
            Array.isArray(param.elements)
          )
            param.elements.forEach(bindParam);
          else if (
            param.type === "AssignmentPattern" ||
            param.type === "RestElement"
          )
            bindParam(param.left ?? param.argument);
        };
        if (Array.isArray(ast.params)) ast.params.forEach(bindParam);
        if (isObject(ast.body)) visit(ast.body, local, depth + 1);
        return;
      }
      if (ast.type === "IfStatement") {
        if (isObject(ast.test)) visit(ast.test, bindings, depth + 1);
        const yes = new Map(bindings),
          no = new Map(bindings);
        if (isObject(ast.consequent)) visit(ast.consequent, yes, depth + 1);
        if (isObject(ast.alternate)) visit(ast.alternate, no, depth + 1);
        for (const name of new Set([...yes.keys(), ...no.keys()])) {
          const a = yes.get(name),
            b = no.get(name);
          bindings.set(name, {
            module: a?.module === b?.module ? a?.module : undefined,
            member: a?.member === b?.member ? a?.member : undefined,
            value: hasExternal(a?.value)
              ? a?.value
              : hasExternal(b?.value)
                ? b?.value
                : undefined,
          });
        }
        scope.diagnostic("javascript_control_flow_partial");
        return;
      }
      if (
        [
          "WhileStatement",
          "ForStatement",
          "ForOfStatement",
          "ForInStatement",
          "DoWhileStatement",
          "TryStatement",
          "SwitchStatement",
        ].includes(String(ast.type))
      ) {
        const possible = new Map(bindings);
        for (const child of Object.values(ast)) {
          if (isObject(child) && typeof child.type === "string")
            visit(child, possible, depth + 1);
          else if (Array.isArray(child))
            for (const entry of child)
              if (isObject(entry) && typeof entry.type === "string")
                visit(entry, possible, depth + 1);
        }
        for (const [name, candidate] of possible) {
          const original = bindings.get(name);
          bindings.set(name, {
            module:
              original?.module === candidate.module
                ? original?.module
                : undefined,
            member:
              original?.member === candidate.member
                ? original?.member
                : undefined,
            value: hasExternal(original?.value)
              ? original?.value
              : hasExternal(candidate.value)
                ? candidate.value
                : undefined,
          });
        }
        scope.diagnostic("javascript_control_flow_partial");
        return;
      }
      if (
        (ast.type === "CallExpression" || ast.type === "NewExpression") &&
        isObject(ast.callee) &&
        Array.isArray(ast.arguments)
      ) {
        const callee = ast.callee;
        const target = moduleFor(callee, bindings);
        const global =
          target?.module === "global"
            ? target.member
            : callee.type === "Identifier" &&
                typeof callee.name === "string" &&
                !bindings.has(callee.name)
              ? callee.name
              : undefined;
        const args = ast.arguments.filter(isObject);
        const values = args.map((argument) => valueFor(argument, bindings));
        const external = values.find(hasExternal);
        if (
          target?.module === "child_process" &&
          [
            "exec",
            "execSync",
            "execFile",
            "execFileSync",
            "spawn",
            "spawnSync",
          ].includes(target.member ?? "")
        ) {
          scope.add(
            "javascript_process_execution_capability",
            "medium",
            "candidate",
          );
          const shell =
            target.member === "exec" ||
            target.member === "execSync" ||
            args.some(
              (argument) =>
                argument.type === "ObjectExpression" &&
                Array.isArray(argument.properties) &&
                argument.properties.some(
                  (property) =>
                    isObject(property) &&
                    isObject(property.key) &&
                    (property.key.name ?? property.key.value) === "shell" &&
                    isObject(property.value) &&
                    property.value.value === true,
                ),
            );
          const unknownShell = args.some(
            (argument) =>
              argument.type === "ObjectExpression" &&
              Array.isArray(argument.properties) &&
              argument.properties.some(
                (property) =>
                  isObject(property) &&
                  isObject(property.key) &&
                  (property.key.name ?? property.key.value) === "shell" &&
                  (!isObject(property.value) ||
                    property.value.type !== "Literal" ||
                    typeof property.value.value !== "boolean"),
              ),
          );
          if (unknownShell)
            scope.diagnostic("javascript_shell_option_unresolved");
          if (external)
            scope.add(
              shell || unknownShell
                ? "javascript_shell_input_candidate"
                : "javascript_argv_option_input_candidate",
              shell || unknownShell ? "high" : "medium",
              "candidate",
              external,
            );
        } else if (global === "eval" || global === "Function") {
          scope.add(
            "javascript_dynamic_evaluation_capability",
            "high",
            "candidate",
            external,
          );
          if (external)
            scope.add(
              "javascript_external_evaluation_input",
              "high",
              "candidate",
              external,
            );
        } else if (
          global === "fetch" ||
          ["http", "https", "axios", "undici"].includes(target?.module ?? "")
        ) {
          scope.add(
            "javascript_network_call_capability",
            "medium",
            "candidate",
            external,
          );
          if (external)
            scope.add(
              "javascript_dynamic_network_input",
              "high",
              "candidate",
              external,
            );
        } else if (["fs", "fs/promises"].includes(target?.module ?? "")) {
          scope.add(
            "javascript_filesystem_call_capability",
            "medium",
            "candidate",
            external,
          );
          if (external)
            scope.add(
              "javascript_dynamic_file_input",
              "high",
              "candidate",
              external,
            );
        }
      }
      for (const child of Object.values(ast)) {
        if (isObject(child) && typeof child.type === "string")
          visit(child, bindings, depth + 1);
        else if (Array.isArray(child))
          for (const entry of child)
            if (isObject(entry) && typeof entry.type === "string")
              visit(entry, bindings, depth + 1);
      }
    };
    try {
      const ast = parse(source, {
        ecmaVersion: "latest",
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
      }) as unknown;
      if (isObject(ast)) visit(ast, env);
      scope.diagnostic("javascript_semantics_partially_analyzed");
    } catch {
      scope.diagnostic("javascript_parse_unavailable");
    }
    scope.finish();
  }
  return finish(result);
}

export function analyzeAdvancedRisks(
  context: Context,
  flow: ValueFlow = buildValueFlow(context),
): RuleResult[] {
  return [sqlRules(context, flow), javascriptRules(context, flow)];
}
