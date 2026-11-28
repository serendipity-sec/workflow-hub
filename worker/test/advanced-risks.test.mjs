import assert from "node:assert/strict";
import test from "node:test";
import sqlParser from "node-sql-parser";
import { createContext } from "../dist/workflow/static-context.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";
import {
  analyzeAdvancedRisks,
  inspectSqlOperation,
} from "../dist/rules/advanced-risks.js";

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
    ["postgres", 2.4],
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
        ({ code }) =>
          code ===
          (type === "postgres"
            ? "database_runtime_schema_and_permissions_unverified"
            : "database_operation_profile_unsupported"),
      ),
    );
    assert.equal(codes(result).includes("sql_operation_select"), false);
  }
});

test("Postgres cast parameters retain AST structure through CTE upserts and conditional writes", () => {
  const query =
    "WITH changed AS (INSERT INTO records (id, label) SELECT $1::int, $2::text ON CONFLICT (id) DO UPDATE SET label=$2::text RETURNING id) SELECT * FROM changed";
  const description = inspectSqlOperation(query);
  assert.equal(description.status, "parsed");
  assert.ok(description.operations.includes("select"));
  assert.ok(description.operations.includes("insert"));
  assert.ok(description.operations.includes("update"));
  assert.equal(description.statementCount, 1);
  assert.equal(description.valueParameterCount, 3);
  const result = scan(
    chain(
      web(),
      sql(query, "postgres", 2.6, {
        queryReplacement: "={{ [$json.body.id, $json.body.label] }}",
      }),
    ),
  );
  assert.ok(codes(result).includes("sql_value_binding_configured"));
  assert.ok(
    !result.diagnostics.some(({ code }) => code === "sql_parse_unsupported"),
  );
  const conditional = scan(
    chain(
      web(),
      sql(
        "UPDATE records SET label=$1::text, changed_at=CASE WHEN $2::boolean THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=$3::int RETURNING id",
        "postgres",
        2.6,
        {
          queryReplacement:
            "={{ [$json.body.label, $json.body.changed, $json.body.id] }}",
        },
      ),
    ),
  );
  assert.ok(codes(conditional).includes("sql_operation_update"));
  assert.ok(codes(conditional).includes("sql_value_binding_configured"));
});

test("cast normalization excludes quoted and commented text and never accepts raw identifier formatting", () => {
  for (const query of [
    "SELECT '$1::text'",
    "SELECT 1 /* $1::text */",
    "SELECT $$ $1::text $$",
    "SELECT café$1::text FROM records",
  ]) {
    const description = inspectSqlOperation(query);
    if (description.status === "parsed")
      assert.equal(description.valueParameterCount, 0);
    const result = scan(
      chain(
        web(),
        sql(query, "postgres", 2.6, {
          queryReplacement: "={{ [$json.body.id] }}",
        }),
      ),
    );
    assert.ok(!codes(result).includes("sql_value_binding_configured"));
  }
  const raw = scan(
    chain(
      web(),
      sql("SELECT * FROM $1:name WHERE id=$2::int", "postgres", 2.6, {
        queryReplacement: "={{ [$json.body.table, $json.body.id] }}",
      }),
    ),
  );
  assert.ok(codes(raw).includes("sql_identifier_or_raw_format_review"));
  assert.ok(!codes(raw).includes("sql_value_binding_configured"));
  assert.equal(
    inspectSqlOperation("WITH broken AS (nonsense) SELECT * FROM broken")
      .status,
    "unsupported",
  );
});

test("Postgres cast normalization preserves nested comments, Unicode dollar literals and identifier bytes", () => {
  const parserInputs = [];
  const original = sqlParser.Parser.prototype.astify;
  sqlParser.Parser.prototype.astify = function (query, options) {
    parserInputs.push(query);
    return original.call(this, query, options);
  };
  try {
    for (const query of [
      "SELECT 1 /* outer /* inner */ $1::text */",
      "SELECT $é$ $1::text $é$",
      "SELECT $cafe\u0301$ $1::text $cafe\u0301$",
      "SELECT cafe\u0301$1::text FROM records",
    ]) {
      parserInputs.length = 0;
      const description = inspectSqlOperation(query);
      assert.deepEqual(parserInputs, [query]);
      if (description.status === "parsed")
        assert.equal(description.valueParameterCount, 0);
    }
    const escapeString = String.raw`SELECT E'\\' AS c, '$1::text' AS literal, $2::text`;
    parserInputs.length = 0;
    inspectSqlOperation(escapeString);
    assert.deepEqual(parserInputs, [
      escapeString.replace("$2::text", "($2)::text"),
    ]);
    const normalString = String.raw`SELECT '\' AS c, '$1::text' AS literal`;
    parserInputs.length = 0;
    const ambiguous = inspectSqlOperation(normalString);
    assert.equal(ambiguous.status, "unsupported");
    assert.ok(
      ambiguous.diagnosticCodes.includes(
        "sql_string_escape_context_unverified",
      ),
    );
    assert.deepEqual(parserInputs, []);
  } finally {
    sqlParser.Parser.prototype.astify = original;
  }
});

test("Postgres 2.6 string replacements expose the value channel without inventing stable positions", () => {
  for (const replacement of [
    "={{ $json.body.id }},{{ $json.body.label }}",
    "{{ $json.body.id }},{{ $json.body.label }}",
    "={{ $json.body.id }}",
  ]) {
    const result = scan(
      chain(
        web(),
        sql("SELECT * FROM records WHERE id=$1", "postgres", 2.6, {
          queryReplacement: replacement,
        }),
      ),
    );
    assert.ok(codes(result).includes("sql_value_parameter_channel_configured"));
    assert.ok(!codes(result).includes("sql_value_binding_configured"));
    assert.ok(
      result.diagnostics.some(
        ({ code }) => code === "sql_parameter_mapping_data_dependent",
      ),
    );
  }
  const fixed = scan(
    chain(
      web(),
      sql("SELECT * FROM records WHERE id=$1 AND label=$2", "postgres", 2.6, {
        queryReplacement: "7,label",
      }),
    ),
  );
  assert.ok(codes(fixed).includes("sql_value_binding_configured"));
  const malformed = scan(
    chain(
      web(),
      sql("SELECT * FROM records WHERE id=$1", "postgres", 2.6, {
        queryReplacement: "={{ broken( }}",
      }),
    ),
  );
  assert.ok(
    !codes(malformed).includes("sql_value_parameter_channel_configured"),
  );
  assert.ok(
    malformed.diagnostics.some(
      ({ code }) => code === "sql_parameter_expression_unresolved",
    ),
  );
});

test("Postgres replacement versions do not silently equate variable arrays with one scalar", () => {
  for (const version of [2.4, 2.8]) {
    const result = scan(
      chain(
        web(),
        sql("SELECT * FROM records WHERE id=$1", "postgres", version, {
          queryReplacement: "={{ $json.body.value }}",
        }),
      ),
    );
    assert.ok(!codes(result).includes("sql_value_binding_configured"));
    assert.ok(codes(result).includes("sql_value_parameter_channel_configured"));
  }
  const legacy = scan(
    chain(
      web(),
      sql("SELECT * FROM records WHERE id=$1 AND label=$2", "postgres", 2.4, {
        queryReplacement: "={{ $json.body.id }},{{ $json.body.label }}",
      }),
    ),
  );
  assert.ok(codes(legacy).includes("sql_value_binding_configured"));
  const direct = scan(
    chain(
      web(),
      sql(
        "UPDATE records SET amount={{ $json.body.amount }}, label='{{ $json.body.label }}' WHERE id='{{ $json.body.id }}'",
        "postgres",
        2.4,
      ),
    ),
  );
  assert.ok(codes(direct).includes("sql_text_input_candidate"));
  assert.ok(codes(direct).includes("sql_structure_or_quoted_input_candidate"));
  assert.ok(
    direct.findings.some((finding) => finding.claim === "supported_path"),
  );
});

test("expression-mode fixed commands retain execution capability without dynamic input claims", () => {
  for (const command of [
    "=printf constant",
    "=cd /tmp\nprintf constant\n",
    "printf '{{literal-format}}'",
  ]) {
    const result = scan(
      chain(web(), node("Command", "executeCommand", 1, { command })),
      "code_execution",
    );
    assert.ok(codes(result).includes("command_execution_capability"));
    assert.ok(!codes(result).includes("command_dynamic_value_candidate"));
    assert.ok(!codes(result).includes("command_external_value_candidate"));
  }
  for (const command of [
    "=printf {{ $json.body.value }}",
    "=printf {{ broken(",
  ]) {
    const result = scan(
      chain(web(), node("Command", "executeCommand", 1, { command })),
      "code_execution",
    );
    assert.ok(
      codes(result).some((code) =>
        [
          "command_dynamic_value_candidate",
          "command_external_value_candidate",
        ].includes(code),
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

test("AST value inspection does not parse object properties or template fragments as n8n templates", () => {
  const source = [
    "const cp = require('child_process');",
    "const payload = {fixed: {suffix: '}}'}, value: $json.body.command};",
    "const message = `prefix ${$json.body.command} }} suffix`;",
    "cp.exec(message); fetch(JSON.stringify(payload));",
  ].join("\n");
  const context = createContext(
    Buffer.from(JSON.stringify(chain(web(), code(source)))),
  );
  const flow = buildValueFlow(context);
  const result = analyzeAdvancedRisks(context, flow).find(
    (rule) => rule.category === "code_execution",
  );
  assert.ok(codes(result).includes("javascript_shell_input_candidate"));
  assert.ok(codes(result).includes("javascript_dynamic_network_input"));
  assert.ok(
    !flow.diagnostics.some(({ code }) =>
      [
        "expression_syntax_unsupported",
        "expression_parse_unavailable",
        "flow_budget_exceeded",
      ].includes(code),
    ),
  );
});

test("fixed property names do not inherit unrelated local bindings but computed keys do", () => {
  for (const computed of [false, true]) {
    const source = [
      "const cp = require('child_process');",
      "const command = $json.body.command;",
      `const payload = {${computed ? "[command]" : "command"}: 'fixed'};`,
      "cp.exec(JSON.stringify(payload));",
    ].join("\n");
    const result = scan(chain(web(), code(source)), "code_execution");
    assert.equal(
      codes(result).includes("javascript_shell_input_candidate"),
      computed,
    );
    assert.ok(
      codes(result).includes("javascript_process_execution_capability"),
    );
  }
});

test("method and function bodies retain execution candidates while syntax containers stay partial", () => {
  const source =
    "const payload = { run() { eval($json.body.code); } }; return [];";
  const result = scan(chain(web(), code(source)), "code_execution");
  assert.ok(codes(result).includes("javascript_external_evaluation_input"));
  assert.ok(
    result.diagnostics.some(
      ({ code }) => code === "javascript_semantics_partially_analyzed",
    ),
  );
});

test("bounded constant declarations do not consume the budget needed for a later external sink", () => {
  const declarations = Array.from(
    { length: 180 },
    (_, i) => `const fixed${i} = {outer: {value: ${i}}};`,
  ).join("\n");
  const context = createContext(
    Buffer.from(
      JSON.stringify(
        chain(
          web(),
          code(
            declarations + "\nconst input = $json.body.command; eval(input);",
          ),
        ),
      ),
    ),
  );
  const flow = buildValueFlow(context);
  const result = analyzeAdvancedRisks(context, flow).find(
    (rule) => rule.category === "code_execution",
  );
  assert.ok(codes(result).includes("javascript_external_evaluation_input"));
  assert.ok(
    !flow.diagnostics.some(({ code }) => code === "flow_budget_exceeded"),
  );
});

test("JavaScript string literals containing n8n delimiters remain fixed strings", () => {
  for (const source of [
    "const cp=require('child_process'); cp.exec('={{ $json.body.command }}');",
    "const cp=require('child_process'); const fixed='={{ $json.body.command }}'; cp.exec(fixed);",
    "const cp=require('child_process'); cp.exec('=fixed {{ broken(');",
  ]) {
    const context = createContext(
      Buffer.from(JSON.stringify(chain(web(), code(source)))),
    );
    const flow = buildValueFlow(context);
    const result = analyzeAdvancedRisks(context, flow).find(
      (rule) => rule.category === "code_execution",
    );
    assert.ok(
      codes(result).includes("javascript_process_execution_capability"),
    );
    assert.ok(!codes(result).includes("javascript_shell_input_candidate"));
    assert.ok(
      !flow.diagnostics.some(
        ({ code }) => code === "expression_syntax_unsupported",
      ),
    );
  }
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

test("whole-query expressions retain dynamic SQL uncertainty rather than a false parser failure", () => {
  const result = scan(chain(web(), sql("={{ $json.body.statement }}")));
  assert.ok(codes(result).includes("sql_dynamic_query_text_candidate"));
  assert.ok(
    result.diagnostics.some((d) => d.code === "sql_query_structure_unresolved"),
  );
  assert.equal(
    result.diagnostics.some((d) => d.code === "sql_parse_unsupported"),
    false,
  );
  assert.equal(codes(result).includes("sql_value_binding_configured"), false);
});

test("literal SQL definitions behind a whole-query expression retain AST and value channels", () => {
  const result = scan(
    chain(
      web(),
      code('return [{json:{statement:"SELECT id FROM records WHERE id=$1"}}];'),
      sql("={{ $json.statement }}", "postgres", 2.8, {
        queryReplacement: ["synthetic"],
      }),
    ),
  );
  assert.ok(codes(result).includes("sql_query_definition_resolved"));
  assert.ok(codes(result).includes("sql_operation_select"));
  assert.ok(codes(result).includes("sql_value_binding_configured"));
  assert.equal(
    codes(result).includes("sql_dynamic_query_text_candidate"),
    false,
  );
});

test("generated Postgres tools keep SQL candidates and model invocation uncertainty", () => {
  const target = sql("SELECT id FROM records WHERE id={{ $fromAI('id') }}");
  target.type = "n8n-nodes-base.postgresTool";
  const result = scan(chain(web(), target));
  assert.ok(codes(result).includes("sql_text_input_candidate"));
  assert.ok(
    result.diagnostics.some(
      (d) => d.code === "model_tool_invocation_unverified",
    ),
  );
  assert.equal(codes(result).includes("sql_value_binding_configured"), false);
});

test("SSH never treats a command field on an unsupported operation as an active command", () => {
  const result = scan(
    chain(
      web(),
      node("SSH", "ssh", 1, {
        resource: "command",
        operation: "unknown",
        command: "={{ $json.body.command }}",
      }),
    ),
    "code_execution",
  );
  assert.equal(codes(result).includes("command_execution_capability"), false);
  assert.ok(
    result.diagnostics.some((d) => d.code === "command_profile_unsupported"),
  );
});

test("JavaScript Code tools are AST inspected while their model query and execution stay unverified", () => {
  delete globalThis.__toolWasExecuted;
  const tool = code(
    'globalThis.__toolWasExecuted=true; const cp=require("child_process"); cp.exec(query); eval(query); fetch(query); return "done";',
  );
  tool.type = "@n8n/n8n-nodes-langchain.toolCode";
  tool.typeVersion = 1.3;
  const result = scan(chain(web(), tool), "code_execution");
  assert.ok(codes(result).includes("javascript_dynamic_evaluation_capability"));
  assert.ok(codes(result).includes("javascript_network_call_capability"));
  assert.ok(codes(result).includes("javascript_dynamic_network_input"));
  assert.ok(codes(result).includes("javascript_external_evaluation_input"));
  assert.ok(codes(result).includes("javascript_shell_input_candidate"));
  assert.ok(
    result.diagnostics.some(
      (d) => d.code === "model_tool_query_and_execution_unverified",
    ),
  );
  assert.equal(globalThis.__toolWasExecuted, undefined);
  tool.parameters.jsCode =
    'query="public"; fetch(query); function local(query) { fetch(query); } return "done";';
  const fixed = scan(chain(web(), tool), "code_execution");
  assert.equal(
    codes(fixed).includes("javascript_dynamic_network_input"),
    false,
  );
  tool.parameters.language = "python";
  assert.ok(
    scan(chain(web(), tool), "code_execution").diagnostics.some(
      (d) => d.code === "javascript_profile_unsupported",
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
