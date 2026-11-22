import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeNativeInspection,
  nativeInspectionResultSchema,
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
