import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import {
  analyzeAdvancedRisks,
  inspectSqlOperation,
} from "../dist/advanced-risks.js";

const node = (name, type, typeVersion, parameters = {}) => ({
  id: name,
  name,
  type: "n8n-nodes-base." + type,
  typeVersion,
  parameters,
});
const web = () => node("Input", "webhook", 2.1);
const sql = (query, type = "postgres", version = 2.8, options = {}) =>
  node("Database", type, version, {
    operation: "executeQuery",
    query,
    options,
  });
const code = (jsCode) => node("Code", "code", 2, { jsCode });
const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((item, index) => [
        item.name,
        { main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});
const scan = (document, category = "sql") =>
  analyzeAdvancedRisks(createContext(Buffer.from(JSON.stringify(document))))
    .map((result) => ruleResultSchema.parse(result))
    .find((result) => result.category === category);
const codes = (result) =>
  result.findings.flatMap(({ evidence }) => evidence.map(({ code }) => code));

test("SQL AST describes actual operations without issuing SQL and keeps raw names out of description", () => {
  for (const [query, operation] of [
    ["SELECT label FROM private_table", "select"],
    ["UPDATE private_table SET label = 'value'", "update"],
    ["DELETE FROM private_table WHERE id = 1", "delete"],
    ["DROP TABLE private_table", "drop"],
  ]) {
    const description = inspectSqlOperation(query);
    assert.equal(description.status, "parsed");
    assert.deepEqual(description.operations, [operation]);
    assert.ok(!JSON.stringify(description).includes("private_table"));
  }
  assert.equal(
    inspectSqlOperation("SELECT 1; DELETE FROM t").statementCount,
    2,
  );
  assert.equal(inspectSqlOperation("malformed input").status, "unsupported");
  assert.equal(
    inspectSqlOperation("x".repeat(16385)).diagnosticCodes[0],
    "sql_parser_input_limit",
  );
});

test("Postgres, MySQL and MSSQL templates report input paths with node-specific operation defaults", () => {
  for (const [type, version] of [
    ["postgres", 2.5],
    ["postgres", 2.8],
    ["mySql", 2.5],
    ["microsoftSql", 1.2],
  ]) {
    const database = sql(
      "SELECT label FROM items WHERE id = {{ $json.body.id }}",
      type,
      version,
    );
    let result = scan(chain(web(), database));
    assert.ok(codes(result).includes("sql_text_input_candidate"), type);
    assert.ok(codes(result).includes("sql_operation_select"), type);
    delete database.parameters.operation;
    result = scan(chain(web(), database));
    assert.ok(
      result.diagnostics.some(
        ({ code }) => code === "database_operation_profile_unsupported",
      ),
    );
  }
});

test("fixed SQL value bindings and raw/identifier formatting are different observations", () => {
  for (const [type, version] of [
    ["postgres", 2.8],
    ["mySql", 2.5],
    ["microsoftSql", 1.2],
  ]) {
    const result = scan(
      chain(
        web(),
        sql("SELECT label FROM items WHERE id = $1", type, version, {
          queryReplacement: "={{ [$json.body.id] }}",
        }),
      ),
    );
    assert.ok(codes(result).includes("sql_value_binding_configured"), type);
    assert.ok(!codes(result).includes("sql_text_input_candidate"));
  }
  const identifier = scan(
    chain(
      web(),
      sql("SELECT label FROM $1:name", "postgres", 2.8, {
        queryReplacement: "={{ [$json.body.table] }}",
      }),
    ),
  );
  assert.ok(codes(identifier).includes("sql_identifier_or_raw_format_review"));
  assert.ok(!codes(identifier).includes("sql_value_binding_configured"));
  const unresolved = scan(
    chain(
      web(),
      sql("SELECT label FROM t WHERE id = $2", "postgres", 2.8, {
        queryReplacement: "={{ [$json.body.id] }}",
      }),
    ),
  );
  assert.ok(
    unresolved.diagnostics.some(
      ({ code }) => code === "sql_parameter_binding_unresolved",
    ),
  );
});

test("parameter-looking string/comment text is not counted as a verified value-binding position", () => {
  for (const query of ["SELECT '$1'", "SELECT 1 -- $1", "SELECT $$ $1 $$"]) {
    const result = scan(
      chain(
        web(),
        sql(query, "postgres", 2.8, {
          queryReplacement: "={{ [$json.body.id] }}",
        }),
      ),
    );
    assert.ok(!codes(result).includes("sql_value_binding_configured"));
    assert.ok(
      result.diagnostics.some(
        ({ code }) => code === "sql_quoted_parameter_mapping_unverified",
      ),
    );
  }
  assert.equal(
    inspectSqlOperation("SELECT value FROM t WHERE id=@p1", "TransactSQL")
      .valueParameterCount,
    1,
  );
});

test("bindings never suppress simultaneous direct interpolation or dynamic identifiers", () => {
  const result = scan(
    chain(
      web(),
      sql(
        "SELECT label FROM {{ $json.body.table }} WHERE id = {{ $json.body.id }}",
        "postgres",
        2.8,
        { queryReplacement: "={{ [$json.body.id] }}" },
      ),
    ),
  );
  assert.ok(codes(result).includes("sql_structure_or_quoted_input_candidate"));
  assert.ok(codes(result).includes("sql_text_input_candidate"));
});

test("SQL flow follows Set mappings and only an exact strict numeric value guard suppresses the narrow candidate", () => {
  const mapping = node("Map", "set", 3.4, {
    assignments: {
      assignments: [
        {
          id: "id",
          name: "target",
          value: "={{ $json.body.id }}",
          type: "string",
        },
      ],
    },
  });
  const filter = {
    combinator: "and",
    options: { version: 2, caseSensitive: true, typeValidation: "strict" },
    conditions: [
      {
        leftValue: "={{ $json.target }}",
        rightValue: 7,
        operator: { type: "number", operation: "equals" },
      },
    ],
  };
  const guard = node("Guard", "if", 2.2, { conditions: filter });
  const database = sql("SELECT label FROM items WHERE id = {{ $json.target }}");
  let result = scan(chain(web(), mapping, guard, database));
  assert.ok(codes(result).includes("sql_numeric_value_guard_observed"));
  assert.ok(!codes(result).includes("sql_text_input_candidate"));
  filter.conditions[0].leftValue = "={{ $json.other }}";
  result = scan(chain(web(), mapping, guard, database));
  assert.ok(codes(result).includes("sql_text_input_candidate"));
});

test("quoted SQL and unsupported DB versions cannot become numeric guard safety claims", () => {
  const result = scan(
    chain(
      web(),
      sql("SELECT label FROM items WHERE id = '{{ $json.body.id }}'"),
    ),
  );
  assert.ok(codes(result).includes("sql_structure_or_quoted_input_candidate"));
  assert.ok(
    scan(chain(web(), sql("SELECT 1", "mySql", 999))).diagnostics.some(
      ({ code }) => code === "unsupported_node_version",
    ),
  );
});

test("command node expression flow crosses mappings and fixed command capability remains separate", () => {
  const mapping = node("Map", "set", 3.4, {
    assignments: {
      assignments: [
        {
          id: "value",
          name: "value",
          value: "={{ $json.body.command }}",
          type: "string",
        },
      ],
    },
  });
  const command = node("Command", "executeCommand", 1, {
    command: "=echo {{ $json.value }}",
  });
  assert.ok(
    codes(scan(chain(web(), mapping, command), "code_execution")).includes(
      "command_external_value_candidate",
    ),
  );
  command.parameters.command = "echo fixed";
  const fixed = scan(chain(web(), mapping, command), "code_execution");
  assert.ok(codes(fixed).includes("command_execution_capability"));
  assert.ok(!codes(fixed).includes("command_external_value_candidate"));
});

test("JavaScript module and variable aliases reach process execution candidates without running code", () => {
  const source =
    "const {exec: run} = require('node:child_process'); const payload = $input.first().json.body.command; run(payload);";
  const result = scan(chain(web(), code(source)), "code_execution");
  assert.ok(codes(result).includes("javascript_process_execution_capability"));
  assert.ok(codes(result).includes("javascript_shell_input_candidate"));
  assert.ok(result.findings.every(({ claim }) => claim === "candidate"));
  assert.ok(
    result.diagnostics.some(
      ({ code }) => code === "javascript_semantics_partially_analyzed",
    ),
  );
});

test("shell false with argv reports option-input uncertainty rather than declaring safe execution", () => {
  const source =
    "const cp = require('child_process'); const argument = $json.body.option; cp.execFile('synthetic', [argument], {shell:false});";
  const result = scan(chain(web(), code(source)), "code_execution");
  assert.ok(codes(result).includes("javascript_argv_option_input_candidate"));
  assert.ok(!codes(result).includes("javascript_shell_input_candidate"));
});

test("eval and fetch through local input aliases are recognized while comments and strings are inert", () => {
  const result = scan(
    chain(
      web(),
      code("const data = $json.body.value; eval(data); fetch(data);"),
    ),
    "code_execution",
  );
  assert.ok(codes(result).includes("javascript_external_evaluation_input"));
  assert.ok(codes(result).includes("javascript_dynamic_network_input"));
  const inert = scan(
    chain(
      web(),
      code(
        "// eval($json.body.value)\nconst note = 'fetch($json.url)'; return [];",
      ),
    ),
    "code_execution",
  );
  assert.equal(inert.findings.length, 0);
  assert.ok(inert.diagnostics.length > 0);
});

test("global call aliases and loop alternatives retain possible external values", () => {
  const source =
    "const evaluate = eval; let value = $json.body.code; while (false) { value = 'fixed'; } evaluate(value); const request = fetch; request(value);";
  const result = scan(chain(web(), code(source)), "code_execution");
  assert.ok(codes(result).includes("javascript_external_evaluation_input"));
  assert.ok(codes(result).includes("javascript_dynamic_network_input"));
  assert.ok(
    result.diagnostics.some(
      ({ code }) => code === "javascript_control_flow_partial",
    ),
  );
});

test("shadowed input parameters do not become proven workflow-source aliases", () => {
  const result = scan(
    chain(web(), code("function local($json) { eval($json.command); }")),
    "code_execution",
  );
  assert.ok(codes(result).includes("javascript_dynamic_evaluation_capability"));
  assert.ok(!codes(result).includes("javascript_external_evaluation_input"));
  const destructured = scan(
    chain(web(), code("function local({$json}) { eval($json.command); }")),
    "code_execution",
  );
  assert.ok(
    !codes(destructured).includes("javascript_external_evaluation_input"),
  );
});

test("block shadowing and destructured data aliases do not erase external possibilities", () => {
  const source =
    "const cp = require('child_process'); const {command: payload} = $json.body; { const payload = 'fixed'; } cp.exec(payload);";
  assert.ok(
    codes(scan(chain(web(), code(source)), "code_execution")).includes(
      "javascript_shell_input_candidate",
    ),
  );
  const overwritten =
    "const cp = require('child_process'); let payload = $json.body.command; payload = 'fixed'; cp.exec(payload);";
  assert.ok(
    !codes(scan(chain(web(), code(overwritten)), "code_execution")).includes(
      "javascript_shell_input_candidate",
    ),
  );
});

test("untrusted code and parser failures never execute or become a clean result", () => {
  delete globalThis.__advancedExecuted;
  const result = scan(
    chain(
      web(),
      code("globalThis.__advancedExecuted = true; const f = eval; return [];"),
    ),
    "code_execution",
  );
  assert.equal(globalThis.__advancedExecuted, undefined);
  assert.ok(result.diagnostics.length > 0);
  assert.ok(
    scan(chain(web(), code("(")), "code_execution").diagnostics.some(
      ({ code }) => code === "javascript_parse_unavailable",
    ),
  );
});
