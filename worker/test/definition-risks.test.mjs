import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/workflow/static-context.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";
import { analyzeDefinitionRisks } from "../dist/rules/definition-risks.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";
const node = (id, type, version, parameters = {}) => ({
  id,
  name: id,
  type: "n8n-nodes-base." + type,
  typeVersion: version,
  parameters,
});
const web = () => node("Input", "webhook", 2);
const run = (target, options = {}) => {
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes: [web(), target],
        connections: {
          Input: { main: [[{ node: target.name, type: "main", index: 0 }]] },
        },
      }),
    ),
  );
  return analyzeDefinitionRisks(context, buildValueFlow(context, options)).map(
    (r) => ruleResultSchema.parse(r),
  );
};
const rule = (rules, id) => rules.find((r) => r.ruleId === id);
const codes = (r) => r.findings.flatMap((f) => f.evidence.map((e) => e.code));
const gaps = (r) => r.diagnostics.map((d) => d.code);
test("structured Postgres operations keep their value channel separate from raw SQL and runtime schema", () => {
  for (const operation of [
    "insert",
    "update",
    "upsert",
    "select",
    "deleteTable",
    undefined,
  ]) {
    const r = rule(
      run(
        node("DB", "postgres", 2.4, {
          operation,
          schema: { value: "private_schema" },
          table: { value: "private_table" },
          columns: { mappingMode: "autoMapInputData" },
          query: "DROP TABLE inactive_text",
        }),
      ),
      "N8N_DATABASE_OPERATIONS",
    );
    assert.ok(
      codes(r).includes(
        "database_" +
          (operation === "deleteTable"
            ? "delete_table"
            : (operation ?? "insert")) +
          "_capability",
      ),
    );
    assert.ok(
      gaps(r).includes("database_runtime_schema_and_permissions_unverified"),
    );
    assert.equal(JSON.stringify(r).includes("private_schema"), false);
    assert.equal(JSON.stringify(r).includes("inactive_text"), false);
    if ([undefined, "insert", "update", "upsert"].includes(operation))
      assert.ok(codes(r).includes("database_input_item_value_channel"));
  }
});
test("Postgres mapped data never exports custom field names and invalid mappings stay partial", () => {
  for (const columns of [
    {
      mappingMode: "defineBelow",
      value: { "private-column": "={{ $json.body.email }}" },
    },
    { mappingMode: "dynamic" },
    null,
  ]) {
    const r = rule(
      run(node("DB", "postgres", 2.8, { schema: "s", table: "t", columns })),
      "N8N_DATABASE_OPERATIONS",
    );
    assert.equal(r.coverage[0].status, "partial");
    assert.equal(JSON.stringify(r).includes("private-column"), false);
  }
  const r = rule(
    run(
      node("DB", "postgres", 2.8, {
        schema: "={{ $json.body.schema }}",
        table: "t",
        columns: { mappingMode: "defineBelow", value: {} },
      }),
    ),
    "N8N_DATABASE_OPERATIONS",
  );
  assert.ok(
    codes(r).includes("database_identifier_selection_external_input_candidate"),
  );
});
test("unknown Postgres resources operations and future versions never receive a structured profile", () => {
  for (const p of [
    { resource: "unknown" },
    { operation: "custom" },
    { operation: "executeQuery" },
  ])
    assert.equal(
      rule(run(node("DB", "postgres", 2.8, p)), "N8N_DATABASE_OPERATIONS")
        .coverage[0].status,
      "not_applicable",
    );
  assert.equal(
    rule(run(node("DB", "postgres", 99, {})), "N8N_DATABASE_OPERATIONS")
      .findings.length,
    0,
  );
});
test("local file read and write paths preserve external source evidence without reading files", () => {
  for (const [type, parameters] of [
    ["readWriteFile", { fileSelector: "={{ $json.body.path }}" }],
    [
      "readWriteFile",
      { operation: "write", fileName: "={{ $json.body.path }}" },
    ],
    ["readBinaryFile", { filePath: "={{ $json.body.path }}" }],
    ["writeBinaryFile", { fileName: "={{ $json.body.path }}" }],
  ]) {
    const r = rule(
      run(node("Disk", type, 1, parameters)),
      "N8N_FILE_OPERATION_PATHS",
    );
    assert.ok(codes(r).includes("local_file_path_external_input_candidate"));
    assert.ok(
      gaps(r).includes("filesystem_permissions_and_path_scope_unverified"),
    );
    assert.ok(gaps(r).includes("binary_payload_unavailable"));
  }
});
test("SSH paths and working directories are selected by active resource and operation", () => {
  for (const operation of ["upload", "download", undefined]) {
    const r = rule(
      run(
        node("SSH", "ssh", 1, {
          resource: "file",
          operation,
          path: "={{ $json.body.path }}",
          command: "inactive-command",
        }),
      ),
      "N8N_FILE_OPERATION_PATHS",
    );
    assert.ok(codes(r).includes("remote_file_path_external_input_candidate"));
    assert.equal(JSON.stringify(r).includes("inactive-command"), false);
  }
  const r = rule(
    run(
      node("SSH", "ssh", 1, {
        cwd: "={{ $json.body.path }}",
        command: "fixed",
      }),
    ),
    "N8N_FILE_OPERATION_PATHS",
  );
  assert.ok(
    codes(r).includes("remote_working_directory_external_input_candidate"),
  );
  assert.equal(gaps(r).includes("binary_payload_unavailable"), false);
});
test("unsupported and disabled file operations preserve their analysis states", () => {
  for (const target of [
    node("Disk", "readWriteFile", 99),
    node("SSH", "ssh", 1, { resource: "file", operation: "custom" }),
    node("Disk", "readWriteFile", 1, { operation: "unknown" }),
  ]) {
    const r = rule(run(target), "N8N_FILE_OPERATION_PATHS");
    assert.equal(r.coverage[0].status, "partial");
    assert.equal(r.findings.length, 0);
  }
  const target = node("Disk", "readWriteFile", 1, {
    fileSelector: "/never-read",
  });
  target.disabled = true;
  assert.equal(
    rule(run(target), "N8N_FILE_OPERATION_PATHS").coverage[0].status,
    "not_applicable",
  );
});
test("mapped HTTP destination controls distinguish authority from a fixed-origin resource", () => {
  for (const url of [
    "={{ $json.body.url }}",
    "https://{{ $json.body.host }}/resource",
  ]) {
    const r = rule(
      run(
        node("HTTP", "httpRequest", 4.2, { url: "=" + url.replace(/^=/, "") }),
      ),
      "N8N_MAPPED_HTTP_DESTINATION",
    );
    assert.ok(codes(r).includes("http_destination_external_input_candidate"));
    assert.ok(gaps(r).includes("dns_redirect_and_network_access_unverified"));
  }
  const r = rule(
    run(
      node("HTTP", "httpRequest", 4.2, {
        url: "=https://example.invalid/api/{{ $json.body.path }}",
      }),
    ),
    "N8N_MAPPED_HTTP_DESTINATION",
  );
  assert.ok(codes(r).includes("http_fixed_origin_dynamic_resource"));
  assert.equal(
    codes(r).includes("http_destination_external_input_candidate"),
    false,
  );
});
test("HTTP constants derived from an expression retain their fixed destination semantics", () => {
  const r = rule(
    run(
      node("HTTP", "httpRequest", 4.2, {
        url: '={{ "http://127.0.0.1/data" }}',
      }),
    ),
    "N8N_MAPPED_HTTP_DESTINATION",
  );
  assert.ok(codes(r).includes("http_local_or_private_destination_candidate"));
  assert.equal(
    codes(r).includes("http_destination_dynamic_value_candidate"),
    false,
  );
  assert.equal(JSON.stringify(r).includes("127.0.0.1"), false);
});

test("fixed private destinations and unsupported protocols remain reviewable without probing them", () => {
  for (const url of [
    "http://127.0.0.1/data",
    "http://169.254.169.254/latest",
    "http://[::1]/",
    "http://10.4.2.1",
  ]) {
    const r = rule(
      run(node("HTTP", "httpRequest", 4.2, { url })),
      "N8N_MAPPED_HTTP_DESTINATION",
    );
    assert.ok(codes(r).includes("http_local_or_private_destination_candidate"));
  }
  const r = rule(
    run(node("HTTP", "httpRequest", 4.2, { url: "file:///private-path" })),
    "N8N_MAPPED_HTTP_DESTINATION",
  );
  assert.ok(gaps(r).includes("http_destination_format_unresolved"));
  assert.equal(JSON.stringify(r).includes("private-path"), false);
});
