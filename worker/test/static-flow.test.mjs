import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import { analyzeFlow } from "../dist/static-flow.js";

const prefix = "n8n-nodes-base.";
const node = (name, type, version, parameters = {}) => ({
  id: `synthetic-${name}`,
  name,
  type: prefix + type,
  typeVersion: version,
  parameters,
});
const web = () =>
  node("Webhook", "webhook", 2.1, { httpMethod: "POST", path: "test" });
const request = (url) => node("Request", "httpRequest", 4.2, { url });
const workflow = (nodes) => ({
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
const scan = (document) =>
  analyzeFlow(createContext(Buffer.from(JSON.stringify(document)))).map(
    (item) => ruleResultSchema.parse(item),
  );
const category = (document, name) =>
  scan(document).find((item) => item.category === name);
const fixture = async (name) =>
  JSON.parse(
    await readFile(
      new URL(`../fixtures/workflows/${name}.json`, import.meta.url),
    ),
  );

test("HTTP destination inventory is masked and fixed origin is not an SSRF claim", () => {
  const document = workflow([
    web(),
    request("https://example.invalid/collection?private=synthetic-value"),
  ]);
  const egress = category(document, "egress");
  assert.equal(egress.findings.length, 1);
  assert.equal(egress.findings[0].severity, "info");
  assert.equal(egress.findings[0].claim, "configuration");
  assert.equal(category(document, "ssrf").findings.length, 0);
  assert.ok(!JSON.stringify(scan(document)).includes("synthetic-value"));
  assert.ok(!JSON.stringify(scan(document)).includes("example.invalid"));
});

test("outbound body inventory selects the active mode and ignores saved inactive fields", () => {
  const saved = {
    url: "https://example.invalid/resource",
    method: "POST",
    sendBody: true,
    jsonBody: '{"inactive":"synthetic"}',
    body: "synthetic=raw",
    bodyParameters: { parameters: [{ name: "synthetic", value: "value" }] },
    inputDataFieldName: "synthetic-binary",
  };
  for (const [selection, selectedField] of [
    [{}, "bodyParameters"],
    [{ contentType: "json", specifyBody: "json" }, "jsonBody"],
    [{ contentType: "json", specifyBody: "keypair" }, "bodyParameters"],
    [{ contentType: "form-urlencoded", specifyBody: "string" }, "body"],
    [
      { contentType: "form-urlencoded", specifyBody: "keypair" },
      "bodyParameters",
    ],
    [
      { contentType: "multipart-form-data", specifyBody: "json" },
      "bodyParameters",
    ],
    [{ contentType: "raw", specifyBody: "json" }, "body"],
    [{ contentType: "binaryData", specifyBody: "json" }, "inputDataFieldName"],
  ]) {
    const result = category(
      workflow([
        node("Request", "httpRequest", 4.2, { ...saved, ...selection }),
      ]),
      "egress",
    );
    const body = result.findings.filter(
      ({ evidence }) => evidence[0].code === "configured_outbound_body",
    );
    assert.equal(body.length, 1);
    assert.ok(
      body[0].location.pointer.endsWith("/parameters/" + selectedField),
    );
    assert.ok(result.coverage[0].location.pointer.endsWith("/parameters"));
  }
  const inactive = node("Request", "httpRequest", 4.2, {
    url: "https://example.invalid",
    sendBody: true,
    contentType: "json",
    specifyBody: "keypair",
    jsonBody: '{"notSent":true}',
  });
  assert.equal(
    category(workflow([inactive]), "egress").findings.length,
    1,
    "saved inactive JSON must not become an outbound body finding",
  );
  inactive.parameters.sendBody = false;
  inactive.parameters.specifyBody = "={{ $json.mode }}";
  assert.equal(
    category(workflow([inactive]), "egress").diagnostics.length,
    0,
    "disabled body does not inspect inactive mode fields",
  );
});

test("unresolved body toggles, selectors, shapes and methods cannot produce checked body coverage", () => {
  const saved = {
    url: "https://example.invalid",
    sendBody: true,
    jsonBody: "{}",
    contentType: "json",
    specifyBody: "json",
  };
  for (const extra of [
    { sendBody: "={{ $json.enabled }}" },
    { sendBody: "true" },
    { sendBody: null },
    { contentType: "={{ $json.kind }}" },
    { specifyBody: "unknown" },
    {
      contentType: "json",
      specifyBody: "keypair",
      bodyParameters: "={{ $json.fields }}",
    },
    { method: "HEAD" },
    { method: "OPTIONS" },
    { method: "={{ $json.method }}" },
  ]) {
    const result = category(
      workflow([node("Request", "httpRequest", 4.2, { ...saved, ...extra })]),
      "egress",
    );
    assert.equal(result.findings.length, 1, "independent URL fact is retained");
    assert.equal(result.coverage[0].status, "partial");
    assert.ok(result.diagnostics.length > 0);
  }
});

test("SSRF candidates distinguish authority control from fixed-origin path and query values", () => {
  for (const url of [
    "={{ $json.body.url }}",
    "=https://{{ $json.body.host }}/resource",
    "=https://example.invalid{{ $json.body.host }}",
  ]) {
    const result = category(workflow([web(), request(url)]), "ssrf");
    assert.equal(result.findings.length, 1, url);
    assert.equal(result.findings[0].claim, "supported_path", url);
  }
  for (const url of [
    "=https://example.invalid/{{ $json.body.path }}",
    "=https://example.invalid?value={{ $json.body.value }}",
  ]) {
    const result = category(workflow([web(), request(url)]), "ssrf");
    assert.equal(result.findings.length, 0, url);
  }
});

test("ordinary URL and response fields do not evaluate bare template text", () => {
  const literal = workflow([
    web(),
    request("https://example.invalid/{{ $json.body.path }}"),
  ]);
  assert.equal(category(literal, "ssrf").findings.length, 0);
  assert.equal(category(literal, "egress").findings[0].claim, "configuration");
  const response = workflow([
    web(),
    node("Response", "respondToWebhook", 1.4, {
      respondWith: "text",
      responseBody: "{{ $json }}",
    }),
  ]);
  assert.equal(category(response, "output").findings.length, 0);
  response.nodes[1].parameters.responseBody = "={{ $json }}";
  assert.equal(category(response, "output").findings.length, 1);
});

test("opaque transforms break current-item provenance but retain independent configuration facts", () => {
  const document = workflow([
    web(),
    node("Transform", "code", 2, {
      jsCode: "throw new Error('must not execute')",
    }),
    request("={{ $json.body.url }}"),
  ]);
  const results = scan(document);
  const ssrf = results.find((item) => item.category === "ssrf");
  assert.equal(ssrf.findings[0].claim, "candidate");
  assert.ok(
    ssrf.diagnostics.some(
      (item) => item.code === "input_provenance_unresolved",
    ),
  );
  assert.ok(ssrf.coverage.some((item) => item.status === "unsupported"));
  assert.equal(
    results.find((item) => item.category === "egress").findings.length,
    1,
  );
});

test("HTTP response does not inherit the request input, while direct original references remain explicit", () => {
  const first = request("https://example.invalid/fixed");
  const second = node("Second", "httpRequest", 4.2, {
    url: "={{ $json.body.url }}",
  });
  const document = workflow([web(), first, second]);
  assert.equal(category(document, "ssrf").findings[0].claim, "candidate");
  second.parameters.url = "={{ $('Webhook').first().json.body.url }}";
  const supported = category(document, "ssrf").findings[0];
  assert.equal(supported.claim, "supported_path");
  assert.equal(supported.evidence[1].code, "webhook_input_source");
});

test("named source without a declared path is unresolved and expressions are never evaluated", () => {
  const document = workflow([
    web(),
    request("={{ $('Webhook').first().json.body.url }}"),
  ]);
  document.connections = {};
  assert.equal(category(document, "ssrf").findings[0].claim, "candidate");
  document.nodes[1].parameters.url =
    "={{ globalThis.__staticFlowExecuted = true }}";
  delete globalThis.__staticFlowExecuted;
  assert.equal(category(document, "ssrf").findings[0].claim, "candidate");
  assert.equal(globalThis.__staticFlowExecuted, undefined);
});

test("SQL interpolation recognizes omitted database resource on supported older versions, not omitted operation", () => {
  for (const version of [2.5, 2.6, 2.8]) {
    const sql = node("SQL", "postgres", version, {
      operation: "executeQuery",
      query: "SELECT label FROM items WHERE id = {{ $json.body.id }}",
    });
    const document = workflow([web(), sql]);
    assert.equal(category(document, "sql").findings[0].claim, "supported_path");
    delete sql.parameters.operation;
    const result = category(document, "sql");
    assert.equal(result.findings.length, 0);
    assert.ok(
      result.diagnostics.some(
        (item) => item.code === "unsupported_database_operation",
      ),
    );
  }
});

test("SQL retains the pinned dangerous, numeric-guarded, bound and unrelated-IF distinctions", async () => {
  for (const name of [
    "interpolated",
    "unrelated-if",
    "direct-origin",
    "reject-branch",
  ]) {
    assert.equal(category(await fixture(name), "sql").findings.length, 1, name);
  }
  for (const name of [
    "guarded",
    "type-constrained-false",
    "bound",
    "constant",
  ]) {
    assert.equal(category(await fixture(name), "sql").findings.length, 0, name);
  }
  const invalidGuard = await fixture("guarded");
  invalidGuard.nodes[1].parameters.looseTypeValidation = true;
  assert.equal(category(invalidGuard, "sql").findings.length, 1);
});

test("binding options do not sanitize SQL text and arbitrary SQL expressions remain qualified", async () => {
  const document = await fixture("interpolated");
  document.nodes[1].parameters.options = {
    queryReplacement: "={{ [ $json.body.id ] }}",
  };
  assert.equal(category(document, "sql").findings.length, 1);
  document.nodes[1].parameters.query =
    "={{ $json.body.id + ' trailing text' }}";
  const result = category(document, "sql");
  assert.equal(result.findings[0].claim, "candidate");
  assert.ok(result.diagnostics.length > 0);
});

test("whole-input responses are review findings while selected fields are not called whole-input exposure", () => {
  const response = node("Response", "respondToWebhook", 1.4);
  const document = workflow([web(), response]);
  const whole = category(document, "output");
  assert.equal(whole.findings[0].claim, "supported_path");
  assert.ok(
    whole.diagnostics.some(
      (item) => item.code === "response_data_sensitivity_unverified",
    ),
  );
  response.parameters.options = { responseKey: "selected" };
  assert.equal(
    category(document, "output").findings.length,
    1,
    "responseKey wraps the full item rather than selecting a field",
  );
  response.parameters = {
    respondWith: "json",
    responseBody: "={{ $json.body }}",
  };
  assert.equal(category(document, "output").findings.length, 1);
  response.parameters.responseBody = "={{ $json.body.id }}";
  assert.equal(category(document, "output").findings.length, 0);
});

test("literal private, loopback, link-local and mapped destinations are configuration reviews, without requests", () => {
  for (const url of [
    "http://127.1/path",
    "http://2130706433/path",
    "http://0x7f000001/path",
    "http://10.4.5.6/path",
    "http://172.31.255.2/path",
    "http://192.168.1.2/path",
    "http://169.254.169.254/latest/meta-data",
    "http://localhost./path",
    "http://a.localhost/path",
    "http://[::1]/path",
    "http://[fd00::2]/path",
    "http://[fe80::2]/path",
    "http://[::ffff:127.0.0.1]/path",
    "=http://127.0.0.1/{{ $json.body.path }}",
  ]) {
    const result = category(workflow([request(url)]), "ssrf");
    assert.equal(result.findings.length, 1, url);
    assert.equal(result.findings[0].claim, "configuration", url);
    assert.equal(
      result.findings[0].evidence[0].code,
      "configured_nonpublic_destination",
      url,
    );
    assert.ok(
      result.findings[0].assumptions.includes(
        "dns_redirects_and_network_unverified",
      ),
    );
    assert.ok(!JSON.stringify(result).includes(url));
  }
  for (const url of [
    "https://example.invalid",
    "https://8.8.8.8/",
    "http://172.32.1.1/",
    "http://[::ffff:8.8.8.8]/",
  ]) {
    assert.equal(
      category(workflow([request(url)]), "ssrf").findings.length,
      0,
      url,
    );
  }
  for (const url of [
    "file:///synthetic/not-read",
    "ftp://example.invalid/path",
    "javascript:globalThis.__staticFlowExecuted=true",
    "=file:///synthetic/{{ $json.path }}",
  ]) {
    const result = category(workflow([request(url)]), "ssrf");
    assert.equal(result.findings.length, 0);
    assert.ok(
      result.diagnostics.some(
        (item) => item.code === "unsupported_request_scheme",
      ),
    );
  }
});

test("Webhook output defaults and invalid outputs do not invent input provenance", () => {
  const source = web();
  source.parameters = { multipleMethods: true };
  const document = workflow([source, request("={{ $json.body.url }}")]);
  document.connections.Webhook.main = [
    null,
    [{ node: "Request", type: "main", index: 0 }],
  ];
  assert.equal(category(document, "ssrf").findings[0].claim, "supported_path");
  document.connections.Webhook.main = [
    null,
    null,
    [{ node: "Request", type: "main", index: 0 }],
  ];
  assert.equal(category(document, "ssrf").findings[0].claim, "candidate");
  document.connections.Webhook.main = [
    [{ node: "Request", type: "main", index: 0 }],
  ];
  source.parameters = {
    multipleMethods: true,
    httpMethod: "={{ $json.method }}",
  };
  assert.equal(category(document, "ssrf").findings[0].claim, "candidate");
});

test("last-node response settings do not let stale body options hide an explicit response", () => {
  const source = web();
  source.parameters = {
    responseMode: "lastNode",
    responseData: "allEntries",
    options: { noResponseBody: true, responsePropertyName: "onlyThis" },
  };
  assert.equal(category(workflow([source]), "output").findings.length, 1);
  source.parameters.responseData = "noData";
  assert.equal(category(workflow([source]), "output").findings.length, 0);
});

test("Acorn finds bounded whole-input console calls without evaluating code or treating comments as calls", () => {
  for (const source of [
    "console.log($json)",
    "console.info(JSON.stringify($input.all()))",
    "console['warn']($input.first()); return $input.all();",
    "const console = { log() {} }; console.log($json)",
  ]) {
    const document = workflow([
      web(),
      node("Logger", "code", 2, { jsCode: source }),
    ]);
    const result = category(document, "output");
    assert.equal(result.findings.length, 1, source);
    assert.equal(result.findings[0].claim, "candidate");
    assert.ok(
      result.findings[0].assumptions.includes("lexical_binding_unverified"),
    );
    assert.ok(result.coverage.some((item) => item.status === "partial"));
  }
  for (const source of [
    "// console.log($json)\nreturn [];",
    "const text = 'console.log($json)'; return [];",
    "console.log($json.id); return [];",
    "globalThis.__staticFlowExecuted = true; return [];",
  ]) {
    const result = category(
      workflow([node("Logger", "code", 2, { jsCode: source })]),
      "output",
    );
    assert.equal(result.findings.length, 0, source);
    assert.ok(result.diagnostics.length > 0);
  }
  assert.equal(globalThis.__staticFlowExecuted, undefined);
  for (const parameters of [
    { jsCode: "(" },
    { language: "pythonNative", pythonCode: "print(_items)" },
  ]) {
    assert.equal(
      category(workflow([node("Logger", "code", 2, parameters)]), "output")
        .findings.length,
      0,
    );
    assert.ok(
      category(workflow([node("Logger", "code", 2, parameters)]), "output")
        .diagnostics.length > 0,
    );
  }
});

test("unsupported versions, cycles, and merges never become proven current-input paths", () => {
  const unsupported = workflow([
    web(),
    node("Request", "httpRequest", 999, { url: "={{ $json.body.url }}" }),
  ]);
  assert.equal(category(unsupported, "ssrf").findings.length, 0);
  assert.ok(
    category(unsupported, "ssrf").diagnostics.some(
      (item) => item.code === "unsupported_node_version",
    ),
  );
  const merged = workflow([
    web(),
    node("Merge", "merge", 3),
    request("={{ $json.body.url }}"),
  ]);
  assert.equal(category(merged, "ssrf").findings[0].claim, "candidate");
  const cyclic = workflow([
    node("Pass", "noOp", 1),
    request("={{ $json.body.url }}"),
  ]);
  cyclic.connections.Request = {
    main: [[{ node: "Pass", type: "main", index: 0 }]],
  };
  assert.equal(category(cyclic, "ssrf").findings[0].claim, "candidate");
});

test("rule identities survive node ordering and supported output size stays bounded", () => {
  const document = workflow([web(), request("={{ $json.body.url }}")]);
  const id = category(document, "ssrf").findings[0].id;
  document.nodes.reverse();
  assert.equal(category(document, "ssrf").findings[0].id, id);
  const nodes = Array.from({ length: 64 }, (_, i) =>
    node(`N${i}`, "httpRequest", 4.2, {
      url: "https://example.invalid",
      sendBody: true,
      contentType: "json",
      specifyBody: "json",
      jsonBody: "{}",
      body: "text",
      bodyParameters: {},
    }),
  );
  const result = category({ nodes, connections: {} }, "egress");
  assert.equal(result.findings.length, 128);
});
