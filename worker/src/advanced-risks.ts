import { createHash } from "node:crypto";
import { parse, parseExpressionAt } from "acorn";
import sqlParser from "node-sql-parser";
import type { Context } from "./static-context.js";
import { isObject } from "./static-context.js";
import type { NormalizedNode } from "./n8n.js";
import { locationFor, stableId } from "./static-contract.js";
import type { Finding, RuleResult } from "./static-contract.js";
import { buildValueFlow, isExternalValue } from "./value-flow.js";
import type { AbstractValue, ValueFlow } from "./value-flow.js";
import { isStructuredPostgres } from "./definition-risks.js";

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
    // PostgreSQL's $N::type is valid in expressions where this parser version
    // only accepts ($N)::type. Parentheses preserve the value and cast. Never
    // rewrite quoted strings/identifiers, comments, or dollar-quoted bodies.
    const lexical = sqlLexicalView(query, dialect);
    if (lexical.diagnosticCodes.length)
      return unavailable(lexical.diagnosticCodes[0]!);
    const outside = dialect === "Postgresql" ? lexical.text : "";
    let normalized = query;
    for (const match of [
      ...outside.matchAll(/(?<![A-Za-z0-9_$\u0080-\uFFFF])\$(\d+)(?=\s*::)/g),
    ].reverse())
      normalized =
        normalized.slice(0, match.index) +
        "(" +
        match[0] +
        ")" +
        normalized.slice(match.index + match[0].length);
    const parsed = parser.astify(normalized, { database: dialect }) as unknown;
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
    profileVersion: "1.5.0",
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
const postgresVersions = new Set([2.4, 2.5, 2.6, 2.8]);
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

interface ParameterBinding {
  configured: boolean;
  count?: number;
  diagnostics: string[];
}

function postgresBinding(value: unknown, version: number): ParameterBinding {
  const arrayCount = replacementCount(value);
  if (arrayCount !== undefined)
    return { configured: true, count: arrayCount, diagnostics: [] };
  if (typeof value === "number")
    return { configured: true, count: 1, diagnostics: [] };
  if (typeof value !== "string") return { configured: false, diagnostics: [] };
  const raw = value.replace(/^=+/, "");
  const expressions = [...raw.matchAll(/\{\{([\s\S]*?)\}\}/g)];
  const remainder = raw.replace(/\{\{([\s\S]*?)\}\}/g, "");
  if (remainder.includes("{{") || remainder.includes("}}"))
    return {
      configured: false,
      diagnostics: ["sql_parameter_expression_unresolved"],
    };
  if (!expressions.length)
    return {
      configured: raw.length > 0,
      count: raw.split(",").filter(Boolean).length,
      diagnostics: [],
    };
  // 2.5/2.6 split each evaluated scalar on commas and can omit undefined array
  // entries. This is still a value channel, but the positional mapping depends
  // on actual data. 2.8 preserves each scalar as one value, including null.
  if (version >= 2.5 && version < 2.8) {
    for (const match of expressions) {
      try {
        const expression = match[1]!;
        const ast = parseExpressionAt(expression, 0, {
          ecmaVersion: "latest",
        }) as unknown;
        if (
          !isObject(ast) ||
          typeof ast.end !== "number" ||
          expression.slice(ast.end).trim()
        )
          return {
            configured: false,
            diagnostics: ["sql_parameter_expression_unresolved"],
          };
      } catch {
        return {
          configured: false,
          diagnostics: ["sql_parameter_expression_unresolved"],
        };
      }
    }
    return {
      configured: true,
      diagnostics: ["sql_parameter_mapping_data_dependent"],
    };
  }
  let count = 0;
  for (const match of expressions) {
    try {
      const expression = match[1]!;
      const ast = parseExpressionAt(expression, 0, {
        ecmaVersion: "latest",
      }) as unknown;
      if (
        !isObject(ast) ||
        typeof ast.end !== "number" ||
        expression.slice(ast.end).trim()
      )
        return {
          configured: false,
          diagnostics: ["sql_parameter_expression_unresolved"],
        };
      if (
        version < 2.5 &&
        value.startsWith("=") &&
        raw.trim() === match[0] &&
        ast.type !== "Literal"
      )
        return {
          configured: true,
          diagnostics: ["sql_parameter_mapping_data_dependent"],
        };
      if (version >= 2.8) {
        // A field can evaluate to an array. Its runtime cardinality is unknown;
        // literal primitive expressions and literal array syntax are bounded.
        if (ast.type === "Literal") count++;
        else if (
          ast.type === "ArrayExpression" &&
          Array.isArray(ast.elements) &&
          !ast.elements.some(
            (item) => !isObject(item) || item.type === "SpreadElement",
          )
        )
          count += ast.elements.length;
        else
          return {
            configured: true,
            diagnostics: ["sql_parameter_mapping_data_dependent"],
          };
      } else {
        // <2.5 splits raw text first. Commas inside an expression can break the
        // token boundary; do not treat such syntax as an exact scalar mapping.
        if (expression.includes(","))
          return {
            configured: true,
            diagnostics: ["sql_parameter_mapping_data_dependent"],
          };
        count++;
      }
    } catch {
      return {
        configured: false,
        diagnostics: ["sql_parameter_expression_unresolved"],
      };
    }
  }
  if (version < 2.5)
    count += raw
      .split(",")
      .filter((part) => part.length > 0 && !part.includes("{{")).length;
  return { configured: true, count, diagnostics: [] };
}

function sqlLexicalView(
  query: string,
  dialect: SqlDialect,
): { text: string; diagnosticCodes: string[] } {
  let masked = "",
    quote: string | undefined,
    blockDepth = 0,
    line = false,
    dollar: string | undefined,
    escapeString = false,
    ambiguousString = false;
  const identifierPart = (value: string | undefined): boolean =>
    value !== undefined && /[A-Za-z0-9_$\u0080-\uFFFF]/.test(value);
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
    if (blockDepth) {
      if (dialect !== "MySQL" && query.startsWith("/*", index)) {
        masked += "  ";
        index++;
        blockDepth++;
      } else if (query.startsWith("*/", index)) {
        masked += "  ";
        index++;
        blockDepth--;
      } else masked += " ";
      continue;
    }
    if (quote) {
      masked += " ";
      if (query[index] === quote) {
        if (query[index + 1] === quote) {
          masked += " ";
          index++;
        } else quote = undefined;
      } else if (query[index] === "\\") {
        if (escapeString || (dialect === "MySQL" && quote !== "]")) {
          if (index + 1 < query.length) {
            masked += " ";
            index++;
          }
        } else if (dialect === "Postgresql" && quote === "'") {
          // The workflow does not provide standard_conforming_strings. Do
          // not normalize or certify bindings across an ambiguous boundary.
          ambiguousString = true;
        }
      }
      continue;
    }
    const tag =
      dialect === "Postgresql" && !identifierPart(query[index - 1])
        ? /^(\$[A-Za-z_\u0080-\uFFFF][A-Za-z0-9_\u0080-\uFFFF]*\$|\$\$)/.exec(
            query.slice(index),
          )?.[1]
        : undefined;
    if (tag) {
      dollar = tag;
      masked += " ".repeat(tag.length);
      index += tag.length - 1;
    } else if (query.startsWith("--", index)) {
      line = true;
      masked += "  ";
      index++;
    } else if (query.startsWith("/*", index)) {
      blockDepth = 1;
      masked += "  ";
      index++;
    } else if (
      [
        "'",
        '"',
        ...(dialect === "MySQL" ? ["`"] : []),
        ...(dialect === "TransactSQL" ? ["["] : []),
      ].includes(query[index]!)
    ) {
      quote = query[index] === "[" ? "]" : query[index];
      escapeString =
        dialect === "Postgresql" &&
        quote === "'" &&
        /[eE]/.test(query[index - 1] ?? "") &&
        !identifierPart(query[index - 2]);
      masked += " ";
    } else masked += query[index];
  }
  return {
    text: masked,
    diagnosticCodes: ambiguousString
      ? ["sql_string_escape_context_unverified"]
      : quote || dollar || blockDepth
        ? ["sql_lexical_boundary_unresolved"]
        : [],
  };
}

function sqlRules(context: Context, flow: ValueFlow): RuleResult {
  const result = rule("N8N_ADVANCED_SQL", "sql");
  for (const node of context.nodes.filter((item) =>
    [
      prefix + "postgres",
      prefix + "postgresTool",
      prefix + "mySql",
      prefix + "microsoftSql",
    ].includes(item.type),
  )) {
    const scope = new Scope(result, node);
    scope.nodeContext = context;
    const dialect: SqlDialect = [
      prefix + "postgres",
      prefix + "postgresTool",
    ].includes(node.type)
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
    if (node.type === prefix + "postgresTool")
      scope.diagnostic("model_tool_invocation_unverified");
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
      if (isStructuredPostgres(node)) {
        scope.add(
          "database_structured_operation_declared",
          "info",
          "configuration",
        );
        scope.diagnostic("database_runtime_schema_and_permissions_unverified");
      } else scope.diagnostic("database_operation_profile_unsupported");
      scope.finish();
      continue;
    }
    const raw = node.parameters.query;
    if (typeof raw !== "string") {
      scope.diagnostic("query_unavailable");
      scope.finish();
      continue;
    }
    let query = raw.startsWith("=") ? raw.slice(1) : raw;
    let templates = sqlTemplates(query);
    let constantQuery = false;
    if (
      templates.length === 1 &&
      templates[0]!.offset === 0 &&
      templates[0]!.end === query.length
    ) {
      const value = flow.resolve(
        node.key,
        raw.startsWith("=") ? raw : "=" + raw,
      );
      const constant = (value as AbstractValue & { constant?: unknown })
        .constant;
      if (
        value.status === "resolved" &&
        typeof constant === "string" &&
        constant.length <= 16384
      ) {
        // A static scalar definition obtained by the bounded AST analyzer is
        // SQL text, not another n8n template. Never re-evaluate its delimiters.
        query = constant;
        templates = [];
        constantQuery = true;
        scope.add("sql_query_definition_resolved", "info", "configuration");
      } else {
        scope.add(
          "sql_dynamic_query_text_candidate",
          "high",
          "candidate",
          value,
        );
        scope.diagnostic("sql_query_structure_unresolved");
        if (
          isObject(node.parameters.options) &&
          node.parameters.options.queryReplacement !== undefined
        )
          scope.diagnostic("sql_parameter_binding_unresolved");
        scope.finish();
        continue;
      }
    }
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
    const lexical = sqlLexicalView(query, dialect);
    const outside = lexical.text;
    for (const code of lexical.diagnosticCodes) scope.diagnostic(code);
    const identifiers = [
      ...outside.matchAll(/\$(\d+):(name|csv|raw|value|alias)/g),
    ];
    const placeholders = [
      ...outside.matchAll(
        /(?<![A-Za-z0-9_$\u0080-\uFFFF])\$(\d+)(?!\d|:(?!:))/g,
      ),
    ].map((match) => Number(match[1]));
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
      [
        ...query.matchAll(
          /(?<![A-Za-z0-9_$\u0080-\uFFFF])\$(\d+)(?!\d|:(?!:))/g,
        ),
      ].length !== placeholders.length
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
      const binding =
        dialect === "Postgresql"
          ? postgresBinding(options.queryReplacement, node.typeVersion)
          : {
              configured:
                replacementCount(options.queryReplacement) !== undefined,
              count: replacementCount(options.queryReplacement),
              diagnostics: [],
            };
      const count = binding.count;
      for (const code of binding.diagnostics) scope.diagnostic(code);
      if (
        count !== undefined &&
        count >= Math.max(...placeholders) &&
        placeholders.every((number) => number >= 1) &&
        !identifiers.length &&
        operation.status === "parsed" &&
        operation.valueParameterCount >= placeholders.length
      )
        scope.add("sql_value_binding_configured", "info", "configuration");
      else {
        if (
          binding.configured &&
          !identifiers.length &&
          operation.status === "parsed" &&
          operation.valueParameterCount > 0
        )
          scope.add(
            "sql_value_parameter_channel_configured",
            "info",
            "configuration",
          );
        scope.diagnostic("sql_parameter_binding_unresolved");
      }
    }
    if (
      dialect === "TransactSQL" &&
      /@[A-Za-z_]/.test(query) &&
      !placeholders.length
    )
      scope.diagnostic("sql_native_parameter_mapping_unverified");
    if (dialect === "MySQL" && query.includes("?") && !placeholders.length)
      scope.diagnostic("sql_native_parameter_mapping_unverified");
    if (!constantQuery && !templates.length && /\{\{|\}\}/.test(raw))
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
const hasExternal = isExternalValue;

function javascriptRules(context: Context, flow: ValueFlow): RuleResult {
  const result = rule("N8N_ADVANCED_EXECUTION", "code_execution");
  for (const node of context.nodes.filter((item) =>
    [
      prefix + "code",
      "@n8n/n8n-nodes-langchain.toolCode",
      prefix + "executeCommand",
      prefix + "ssh",
    ].includes(item.type),
  )) {
    const scope = new Scope(result, node);
    scope.nodeContext = context;
    const toolCode = node.type === "@n8n/n8n-nodes-langchain.toolCode";
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    if (node.type !== prefix + "code" && !toolCode) {
      if (
        node.typeVersion !== 1 ||
        (node.type === prefix + "ssh" &&
          ((node.parameters.resource ?? "command") !== "command" ||
            (node.parameters.operation ?? "execute") !== "execute"))
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
        if (command.startsWith("=") && /\{\{|\}\}/.test(command)) {
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
      !(toolCode ? [1, 1.1, 1.2, 1.3] : [1, 2]).includes(node.typeVersion) ||
      ((node.typeVersion === 2 || toolCode) &&
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
    if (!toolCode) {
      const body = flow.output(node.key, "");
      for (const code of body.diagnosticCodes) scope.diagnostic(code);
    }
    const textFor = (ast: Record<string, unknown>): string =>
      typeof ast.start === "number" && typeof ast.end === "number"
        ? source.slice(ast.start, ast.end)
        : "";
    const env = new Map<string, Binding>();
    if (toolCode) {
      const query = flow.resolve(node.key, "={{ __model_tool_query }}");
      // ToolCode receives this argument from a possible model tool call. Its
      // content and actual invocation are unknown, but its untrusted input
      // provenance must survive into process/network sink candidates.
      env.set("query", {
        value: {
          ...query,
          status: "partial",
          trust: "external",
          origins: [
            { nodeKey: node.key, fieldPath: "/query", kind: "node_output" },
          ],
          guards: [],
          constant: undefined,
          diagnosticCodes: [
            ...query.diagnosticCodes,
            "model_tool_query_and_execution_unverified",
          ],
        },
      });
      scope.diagnostic("model_tool_query_and_execution_unverified");
    }
    let visited = 0;
    const expressionKinds = new Set([
      "Identifier",
      "Literal",
      "MemberExpression",
      "CallExpression",
      "ArrayExpression",
      "ObjectExpression",
      "TemplateLiteral",
      "BinaryExpression",
      "LogicalExpression",
      "UnaryExpression",
      "ConditionalExpression",
      "ChainExpression",
      "AwaitExpression",
    ]);
    const valueChildren = (
      ast: Record<string, unknown>,
    ): Record<string, unknown>[] => {
      const children: Record<string, unknown>[] = [];
      for (const [key, child] of Object.entries(ast)) {
        // Fixed property names and template fragments are syntax, not reads
        // of similarly named variables. Computed keys still carry input.
        if (
          ((ast.type === "MemberExpression" && key === "property") ||
            (ast.type === "Property" && key === "key")) &&
          ast.computed !== true
        )
          continue;
        if (ast.type === "TemplateLiteral" && key === "quasis") continue;
        const candidates = Array.isArray(child) ? child : [child];
        for (const item of candidates) {
          if (!isObject(item) || typeof item.type !== "string") continue;
          if (item.type === "Property") children.push(...valueChildren(item));
          else if (item.type !== "TemplateElement") children.push(item);
        }
      }
      return children;
    };
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
      if (ast.type === "Literal")
        return flow.resolveExpression(node.key, textFor(ast));
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
      const direct = flow.resolveExpression(
        node.key,
        shadowsGlobal
          ? "__local_binding_unresolved()"
          : expressionKinds.has(String(ast.type))
            ? textFor(ast)
            : "__javascript_syntax_container_unresolved()",
      );
      // A completely resolved literal already includes its nested fields and
      // sensitivity. Rewalking that constant tree wastes the bounded flow budget.
      if (direct.status === "resolved" && direct.origins.length === 0)
        return direct;
      const nested = valueChildren(ast).map((child) =>
        valueFor(child, bindings, depth + 1),
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
    const childModule = (
      parent: Binding | undefined,
      key: string | undefined,
    ): Binding | undefined => {
      if (!parent?.module || !key) return undefined;
      if (parent.module === "global_object")
        return ["eval", "Function", "fetch"].includes(key)
          ? { module: "global", member: key }
          : undefined;
      if (parent.module === "n8n_this")
        return key === "helpers" ? { module: "n8n_helpers" } : undefined;
      return { module: parent.module, member: key };
    };
    const moduleFor = (
      ast: Record<string, unknown>,
      bindings: Map<string, Binding>,
    ): Binding | undefined => {
      if (ast.type === "ThisExpression") return { module: "n8n_this" };
      if (ast.type === "Identifier" && typeof ast.name === "string")
        return (
          bindings.get(ast.name) ??
          (ast.name === "globalThis" && !bindings.has(ast.name)
            ? { module: "global_object" }
            : ["eval", "Function", "fetch", "require"].includes(ast.name) &&
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
        return childModule(moduleFor(ast.object, bindings), member(ast));
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
            ) {
              const key =
                property.computed !== true &&
                typeof property.key.name === "string"
                  ? property.key.name
                  : property.key.type === "Literal" &&
                      typeof property.key.value === "string"
                    ? property.key.value
                    : undefined;
              bindings.set(property.value.name, {
                ...childModule(binding, key),
                value: (() => {
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
          (target?.module === "n8n_helpers" &&
            [
              "httpRequest",
              "httpRequestWithAuthentication",
              "request",
              "requestWithAuthentication",
            ].includes(target.member ?? "")) ||
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
