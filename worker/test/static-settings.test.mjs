import assert from "node:assert/strict";
import { test } from "node:test";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import { analyzeSettings, inspectJavaScript } from "../dist/static-settings.js";

const node = (kind, parameters = {}, extra = {}) => ({
  id: `${kind}-id`,
  name: `${kind}-fixture`,
  type: `n8n-nodes-base.${kind}`,
  typeVersion:
    kind === "webhook" || kind === "code"
      ? 2
      : kind === "httpRequest"
        ? 4.2
        : 1,
  parameters,
  ...extra,
});
function analyze(nodes, connections = {}, extra = {}) {
  const context = createContext(
    Buffer.from(JSON.stringify({ nodes, connections, ...extra })),
  );
  const rules = analyzeSettings(context);
  for (const rule of rules) ruleResultSchema.parse(rule);
  return {
    context,
    rules,
    category: (category) => rules.find((rule) => rule.category === category),
  };
}
const codes = (rule) =>
  rule.findings.flatMap(({ evidence }) => evidence.map(({ code }) => code));
const diagnosticCodes = (rule) => rule.diagnostics.map(({ code }) => code);

test("request authentication reports omitted default and explicit none without assuming upstream access", () => {
  for (const parameters of [{}, { authentication: "none" }]) {
    const rule = analyze([node("webhook", parameters)]).category(
      "request_auth",
    );
    assert.equal(rule.coverage[0].status, "checked");
    assert.equal(rule.findings[0].claim, "configuration");
    assert.ok(
      rule.findings[0].assumptions.includes(
        "upstream_authentication_not_observed",
      ),
    );
    assert.ok(
      codes(rule).some(
        (code) => code.includes("authentication") && code.includes("none"),
      ),
    );
  }
});

test("configured authentication requires a credential reference and rejects unknown values", () => {
  const configured = node(
    "webhook",
    { authentication: "headerAuth" },
    { credentials: { httpHeaderAuth: { id: "synthetic-credential-id" } } },
  );
  const rule = analyze([configured]).category("request_auth");
  assert.equal(rule.coverage[0].status, "checked");
  assert.deepEqual(codes(rule), ["webhook_authentication_configured"]);
  delete configured.credentials;
  const missing = analyze([configured]).category("request_auth");
  assert.equal(missing.coverage[0].status, "partial");
  assert.deepEqual(diagnosticCodes(missing), [
    "authentication_credential_reference_missing",
  ]);
  for (const authentication of [
    null,
    false,
    "={{ $json.auth }}",
    "unreviewed-auth",
  ])
    assert.deepEqual(
      diagnosticCodes(
        analyze([node("webhook", { authentication })]).category("request_auth"),
      ),
      ["unsupported_authentication_mode"],
    );
});

test("TLS settings preserve insecure configuration facts while masking URL credentials and hosts", () => {
  const rule = analyze([
    node("httpRequest", {
      url: "http://synthetic-user:synthetic-secret@private.fixture.invalid/data",
      options: { allowUnauthorizedCerts: true },
    }),
  ]).category("transport");
  assert.deepEqual(
    new Set(codes(rule)),
    new Set([
      "tls_certificate_validation_disabled",
      "plaintext_http_url",
      "url_contains_authentication_material",
    ]),
  );
  const text = JSON.stringify(rule);
  for (const secret of [
    "synthetic-user",
    "synthetic-secret",
    "private.fixture.invalid",
  ])
    assert.equal(text.includes(secret), false);
  assert.equal(rule.coverage[0].status, "checked");
});

test("transport default TLS and explicit false are checked only for pinned HTTP versions", () => {
  for (const options of [undefined, {}, { allowUnauthorizedCerts: false }]) {
    const rule = analyze([
      node("httpRequest", {
        url: "https://fixture.invalid",
        ...(options === undefined ? {} : { options }),
      }),
    ]).category("transport");
    assert.equal(rule.findings.length, 0);
    assert.equal(rule.diagnostics.length, 0);
    assert.equal(rule.coverage[0].status, "checked");
  }
  const unknown = analyze([
    node(
      "httpRequest",
      { url: "https://fixture.invalid" },
      { typeVersion: 99 },
    ),
  ]).category("transport");
  assert.deepEqual(diagnosticCodes(unknown), ["unsupported_node_version"]);
  assert.equal(unknown.coverage[0].status, "unsupported");
});

test("dynamic TLS options and URLs do not erase independently observed settings", () => {
  const result = analyze([
    node("httpRequest", {
      url: "={{ $json.url }}",
      options: { allowUnauthorizedCerts: true },
    }),
    node(
      "httpRequest",
      {
        url: "http://fixture.invalid",
        options: { allowUnauthorizedCerts: "false" },
      },
      { id: "other-http", name: "other-http" },
    ),
  ]).category("transport");
  assert.ok(codes(result).includes("tls_certificate_validation_disabled"));
  assert.ok(codes(result).includes("plaintext_http_url"));
  assert.ok(diagnosticCodes(result).includes("transport_url_unresolved"));
  assert.ok(
    diagnosticCodes(result).includes("dynamic_certificate_validation_option"),
  );
  assert.ok(result.coverage.every(({ status }) => status === "partial"));
});

test("command capability, dynamic expression and directly traced webhook input are distinct", () => {
  const source = node("webhook", { httpMethod: "POST", options: {} });
  const command = node("executeCommand", {
    command: '=echo "{{ $json.body.value }}"',
  });
  const connections = {
    [source.name]: { main: [[{ node: command.name, type: "main", index: 0 }]] },
  };
  const traced = analyze([source, command], connections).category(
    "code_execution",
  );
  const path = traced.findings.find(({ claim }) => claim === "supported_path");
  assert.ok(path);
  assert.equal(path.evidence.length, 2);
  assert.ok(path.assumptions.includes("shell_context_not_executed"));
  const opaque = analyze([command]).category("code_execution");
  assert.equal(
    opaque.findings.some(({ claim }) => claim === "supported_path"),
    false,
  );
  assert.ok(
    diagnosticCodes(opaque).includes("command_input_origin_unresolved"),
  );
  command.parameters.command = "echo fixed-synthetic-output";
  const fixed = analyze([command]).category("code_execution");
  assert.deepEqual(codes(fixed), ["command_execution_capability"]);
  assert.equal(fixed.diagnostics.length, 0);
});

test("command tracing does not accept a disabled node, raw-body source, or unrelated direct source", () => {
  for (const alteration of [
    "disabled",
    "raw_body",
    "unrelated_source",
    "prototype_field",
  ]) {
    const source = node("webhook", {});
    const command = node("executeCommand", {
      command: "=echo {{ $json.body.value }}",
    });
    if (alteration === "disabled") command.disabled = true;
    if (alteration === "raw_body")
      source.parameters.options = { rawBody: true };
    if (alteration === "unrelated_source")
      command.parameters.command =
        "=echo {{ $('Other').first().json.body.value }}";
    if (alteration === "prototype_field")
      command.parameters.command = "=echo {{ $json.body.__proto__ }}";
    const connections = {
      [source.name]: {
        main: [[{ node: command.name, type: "main", index: 0 }]],
      },
    };
    const rule = analyze([source, command], connections).category(
      "code_execution",
    );
    assert.equal(
      rule.findings.some(({ claim }) => claim === "supported_path"),
      false,
      alteration,
    );
    assert.ok(
      diagnosticCodes(rule).includes("command_input_origin_unresolved"),
      alteration,
    );
  }
});

test("JavaScript AST finds executable syntax and excludes comments and string literals", () => {
  const harmless = analyze([
    node("code", {
      jsCode:
        '// eval($json.value)\nconst text = "require(\"child_process\").exec(input)"; return [{ json: { text } }];',
    }),
  ]).category("code_execution");
  assert.deepEqual(codes(harmless), ["custom_code_node_declared"]);
  const source =
    "eval($json.value); new Function('return 1'); require('child_process').exec($json.value);";
  const risky = analyze([node("code", { jsCode: source })]).category(
    "code_execution",
  );
  for (const code of [
    "javascript_eval_call",
    "javascript_function_constructor",
    "javascript_privileged_module_reference",
    "javascript_process_execution_call",
  ])
    assert.ok(codes(risky).includes(code), code);
  assert.ok(
    risky.findings
      .filter(({ severity }) => severity === "high")
      .every(({ claim }) => claim === "candidate"),
  );
  assert.equal(JSON.stringify(risky).includes(source), false);
});

test("unsupported languages and syntax retain capability findings without clean analysis", () => {
  for (const parameters of [
    { language: "pythonNative", pythonCode: "print('synthetic')" },
    { language: null, jsCode: "return [];" },
    { jsCode: "function {" },
  ]) {
    const rule = analyze([node("code", parameters)]).category("code_execution");
    assert.ok(codes(rule).includes("custom_code_node_declared"));
    assert.equal(rule.coverage[0].status, "partial");
    assert.equal(rule.diagnostics.length, 1);
  }
});

test("JavaScript accepts n8n async-wrapper syntax without evaluating await", () => {
  const source =
    "await Promise.resolve(); console.log($json); return [{ json: {} }];";
  assert.ok(inspectJavaScript(source).has("javascript_whole_input_log_call"));
  const rule = analyze([node("code", { jsCode: source })]).category(
    "code_execution",
  );
  assert.equal(rule.diagnostics.length, 0);
  assert.equal(rule.coverage[0].status, "checked");
  const invalid = analyze([
    node("code", {
      jsCode: "function notAsync() { await Promise.resolve(); }",
    }),
  ]).category("code_execution");
  assert.deepEqual(diagnosticCodes(invalid), ["javascript_parse_unavailable"]);
});

test("code inspection never evaluates uploaded content and exposes only fixed log capability codes", () => {
  delete globalThis.__static_settings_must_not_execute;
  const source =
    "globalThis.__static_settings_must_not_execute = true; console.log(JSON.stringify($json));";
  const capabilities = inspectJavaScript(source);
  assert.equal(globalThis.__static_settings_must_not_execute, undefined);
  assert.ok(capabilities.has("javascript_whole_input_log_call"));
  assert.equal(
    inspectJavaScript(
      "console.log('safe constant'); // console.log($json)",
    ).has("javascript_whole_input_log_call"),
    false,
  );
  assert.equal(
    codes(
      analyze([node("code", { jsCode: source })]).category("code_execution"),
    ).includes("javascript_whole_input_log_call"),
    false,
  );
});

test("dependency inventory separates privileges, missing workflows and unknown package versions", () => {
  const inputs = [
    node("ssh", { resource: "file", operation: "download" }),
    node("readWriteFile", { operation: "read" }, { typeVersion: 1.1 }),
    node(
      "executeWorkflow",
      { source: "database", workflowId: "private-workflow-id" },
      { typeVersion: 1.3 },
    ),
    node(
      "external",
      {},
      { type: "synthetic-community.secret-provider", typeVersion: 42 },
    ),
  ];
  const rule = analyze(inputs).category("dependencies");
  assert.ok(codes(rule).includes("remote_shell_or_file_capability"));
  assert.ok(codes(rule).includes("local_file_access_capability"));
  assert.ok(diagnosticCodes(rule).includes("subworkflow_content_not_provided"));
  assert.ok(
    diagnosticCodes(rule).includes(
      "installed_package_version_and_content_missing",
    ),
  );
  assert.equal(JSON.stringify(rule).includes("private-workflow-id"), false);
  assert.equal(JSON.stringify(rule).includes("secret-provider"), false);
  const inline = analyze([
    node("executeWorkflow", {
      source: "parameter",
      workflowJson: '{"nodes":[]}',
    }),
  ]).category("dependencies");
  assert.deepEqual(diagnosticCodes(inline), [
    "inline_subworkflow_not_analyzed",
  ]);
});

test("AI tool channels and future builtin nodes stay explicit unknown scopes", () => {
  const tool = node("executeCommand", { command: "echo synthetic" });
  const ai = node(
    "ai",
    {},
    { type: "@n8n/n8n-nodes-langchain.agent", typeVersion: 3 },
  );
  const future = node("futureBuiltin", {});
  const connections = {
    [tool.name]: { ai_tool: [[{ node: ai.name, type: "ai_tool", index: 0 }]] },
  };
  const rule = analyze([tool, ai, future], connections).category(
    "dependencies",
  );
  assert.ok(codes(rule).includes("ai_tool_connection_declared"));
  assert.ok(
    diagnosticCodes(rule).includes("ai_tool_approval_and_access_unverified"),
  );
  assert.ok(
    diagnosticCodes(rule).includes("builtin_capability_profile_unreviewed"),
  );
  assert.ok(rule.coverage.some(({ status }) => status === "unsupported"));
  assert.ok(rule.coverage.some(({ status }) => status === "partial"));
});
