import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeNativeInspection,
  nativeInspectionResultSchema,
  nativeNlpScope,
  runNativeInspection,
} from "../dist/native-inspection.js";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";

const context = () =>
  createContext(
    Buffer.from(
      JSON.stringify({
        nodes: [
          {
            id: "code",
            name: "Code",
            type: "n8n-nodes-base.code",
            typeVersion: 2,
            parameters: {
              language: "pythonNative",
              pythonCode: "print(_items)",
            },
          },
        ],
        connections: {},
        notes: "Synthetic text",
      }),
    ),
  );
const result = (mode, fields = [], diagnostics = []) => ({
  tool: "native_inspection",
  version: "1.0.0",
  modes: [
    {
      mode,
      status: "completed",
      findings: fields,
      diagnostics,
      versions: {
        python: "3.12.10",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    },
  ],
});

test("NER scope separates schema metadata and programs while preserving literal data and notes", () => {
  const ctx = createContext(
    Buffer.from(
      JSON.stringify({
        name: "Synthetic workflow label",
        nodes: [
          {
            id: "00000000-0000-4000-8000-000000000001",
            name: "Gmail",
            type: "n8n-nodes-base.code",
            typeVersion: 2,
            parameters: {
              jsCode: "const label = 'John Smith';",
              command: "printf 'synthetic@example.com'",
              options: { customEmailConfig: '["UNSEEN"]' },
              conditions: {
                conditions: [
                  {
                    operator: { type: "string", operation: "notEmpty" },
                    rightValue: "Li",
                  },
                ],
              },
              operation: "json",
              body: { id: "Li" },
              jsonBody: JSON.stringify({ name: "John Smith", city: "London" }),
              message: "Contact John Smith {{ $json.id }}",
              assignments: {
                assignments: [
                  {
                    id: "schema-id",
                    type: "string",
                    name: "customer",
                    value: "Li",
                  },
                ],
              },
            },
          },
        ],
        connections: {},
        notes: "[John Smith lives in London]",
        pinData: { source: [{ json: { name: "Li", type: "John Smith" } }] },
      }),
    ),
  );
  const scope = (pointer, kind = "value") =>
    nativeNlpScope(
      ctx.fields.find(
        (field) => field.pointer === pointer && field.kind === kind,
      ),
    );
  for (const pointer of [
    "/name",
    "/nodes/0/id",
    "/nodes/0/type",
    "/nodes/0/parameters/operation",
    "/nodes/0/parameters/assignments/assignments/0/id",
    "/nodes/0/parameters/assignments/assignments/0/name",
    "/nodes/0/parameters/conditions/conditions/0/operator/operation",
  ])
    assert.equal(scope(pointer), "metadata");
  assert.equal(scope("/nodes/0/parameters/jsCode"), "program");
  assert.equal(scope("/nodes/0/parameters/command"), "program");
  assert.equal(
    scope("/nodes/0/parameters/options/customEmailConfig"),
    "program",
  );
  assert.equal(
    scope("/nodes/0/parameters/conditions/conditions/0/rightValue"),
    "prose",
  );
  assert.equal(scope("/nodes/0/parameters/jsonBody"), "json");
  assert.equal(scope("/nodes/0/parameters/message"), "template");
  assert.equal(scope("/nodes/0/parameters/body/id"), "prose");
  assert.equal(
    scope("/nodes/0/parameters/assignments/assignments/0/value"),
    "prose",
  );
  assert.equal(scope("/notes"), "prose");
  assert.equal(scope("/pinData/source/0/json/name"), "data");
  assert.equal(scope("/pinData/source/0/json/type"), "data");
  assert.equal(scope("/pinData/source/0/json/name", "key"), "metadata");
});

test("metadata NER rejection preserves format results and short names in real data slots", () => {
  const ctx = createContext(
    Buffer.from(
      JSON.stringify({
        nodes: [
          {
            id: "fixture",
            name: "Code",
            type: "n8n-nodes-base.code",
            typeVersion: 2,
            parameters: {},
          },
        ],
        connections: {},
        notes: "Li",
        pinData: { source: [{ json: { name: "Li" } }] },
      }),
    ),
  );
  const fields = ["/nodes/0/type", "/notes", "/pinData/source/0/json/name"].map(
    (pointer) =>
      ctx.fields.find(
        (field) => field.kind === "value" && field.pointer === pointer,
      ),
  );
  const scan = result(
    "nlp",
    fields.map((field) => ({
      fieldIndex: field.index,
      code: "nlp_person_candidate",
      start: 0,
      end: 2,
      line: null,
    })),
  );
  const rules = analyzeNativeInspection(ctx, scan).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  assert.equal(rules[0].findings.length, 2);
  assert.equal(rules[0].profileVersion, "1.2.0");
  assert.ok(
    rules[0].diagnostics.some((d) => d.code === "nlp_metadata_formats_only"),
  );
  const format = result("nlp", [
    {
      fieldIndex: fields[0].index,
      code: "nlp_email_candidate",
      start: 0,
      end: 2,
      line: null,
    },
  ]);
  assert.equal(analyzeNativeInspection(ctx, format)[0].findings.length, 1);
});

test("program format candidates remain candidates in source, not runtime output claims", () => {
  const ctx = context();
  const field = ctx.fields.find(
    (item) => item.pointer.endsWith("/pythonCode") && item.kind === "value",
  );
  const rules = analyzeNativeInspection(
    ctx,
    result("nlp", [
      {
        fieldIndex: field.index,
        code: "nlp_email_candidate",
        start: 0,
        end: 2,
        line: null,
      },
    ]),
  ).map((rule) => ruleResultSchema.parse(rule));
  const finding = rules[0].findings[0];
  assert.equal(finding.claim, "candidate");
  assert.ok(
    finding.evidence.some(
      (item) => item.code === "format_candidate_in_program_text",
    ),
  );
  assert.ok(finding.assumptions.includes("program_text_is_not_runtime_output"));
});

test("native helper absence relative paths and cancellation never become clean", async () => {
  for (const options of [
    {},
    { pythonExecutable: "python" },
    { pythonExecutable: process.execPath, signal: AbortSignal.abort() },
  ]) {
    const scan = await runNativeInspection(context(), options);
    assert.ok(
      scan.modes.every(
        (mode) => mode.status === "error" && mode.findings.length === 0,
      ),
    );
    const rules = analyzeNativeInspection(context(), scan).map((rule) =>
      ruleResultSchema.parse(rule),
    );
    assert.ok(rules.every((rule) => rule.coverage[0].status === "partial"));
  }
});

test("native result schema rejects raw text wrong model and mixed mode entities", () => {
  const bad = result("nlp");
  bad.modes[0].versions.model = "another-model";
  assert.equal(nativeInspectionResultSchema.safeParse(bad).success, false);
  assert.equal(
    nativeInspectionResultSchema.safeParse({
      ...result("python"),
      rawText: "private",
    }).success,
    false,
  );
  assert.equal(
    nativeInspectionResultSchema.safeParse(
      result("python", [
        {
          fieldIndex: 0,
          code: "nlp_person_candidate",
          start: 0,
          end: 1,
          line: null,
        },
      ]),
    ).success,
    false,
  );
});

test("native PII result maps safe locations without copying candidate text", () => {
  const ctx = context();
  const field = ctx.fields.find(
    (item) => item.kind === "value" && item.value === "Synthetic text",
  );
  const scan = result(
    "nlp",
    [
      {
        fieldIndex: field.index,
        code: "nlp_person_candidate",
        start: 0,
        end: 9,
        line: null,
      },
    ],
    [{ fieldIndex: null, code: "nlp_english_model_profile" }],
  );
  const rules = analyzeNativeInspection(ctx, scan).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  assert.equal(rules[0].findings[0].claim, "candidate");
  assert.equal(JSON.stringify(rules).includes("Synthetic text"), false);
  assert.equal(rules[0].coverage[0].status, "partial");
});

test("Python log findings stay in output and incorrect source indices are rejected", () => {
  const ctx = context();
  const field = ctx.fields.find(
    (item) => item.kind === "value" && item.pointer.endsWith("/pythonCode"),
  );
  const good = result(
    "python",
    [
      {
        fieldIndex: field.index,
        code: "python_external_input_log_call",
        start: null,
        end: null,
        line: 1,
      },
    ],
    [{ fieldIndex: field.index, code: "python_static_profile_limited" }],
  );
  const rules = analyzeNativeInspection(ctx, good).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  assert.equal(rules[0].findings.length, 0);
  assert.equal(rules[1].findings.length, 1);
  const bad = result("python", [
    {
      fieldIndex: 99999,
      code: "python_log_call",
      start: null,
      end: null,
      line: 1,
    },
  ]);
  assert.ok(
    analyzeNativeInspection(ctx, bad).some((rule) =>
      rule.diagnostics.some((item) => item.code === "native_invalid_report"),
    ),
  );
});

test("malformed options and missing Python source produce explicit errors", async () => {
  const empty = await runNativeInspection(context(), { modes: [] });
  assert.ok(empty.modes.every((mode) => mode.status === "error"));
  const scan = await runNativeInspection(context(), {
    pythonExecutable: process.execPath,
    modes: ["python"],
    timeoutMs: 0,
  });
  assert.equal(scan.modes[0].diagnostics[0].code, "native_invalid_input");
  const document = {
    nodes: [
      {
        id: "code",
        name: "Code",
        type: "n8n-nodes-base.code",
        typeVersion: 2,
        parameters: { language: "pythonNative" },
      },
    ],
    connections: {},
  };
  const rules = analyzeNativeInspection(
    createContext(Buffer.from(JSON.stringify(document))),
    result("python"),
  );
  assert.ok(rules.every((rule) => rule.coverage[0].status === "partial"));
});
