import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow } from "../dist/value-flow.js";
import { transferDataClasses } from "../dist/extended-sinks.js";

function analyze(jsCode, field = "/result", annotations = []) {
  const nodes = [
    {
      name: "Input",
      type: "n8n-nodes-base.webhook",
      typeVersion: 2.1,
      parameters: {},
    },
    {
      name: "Code",
      type: "n8n-nodes-base.code",
      typeVersion: 2,
      parameters: { jsCode },
    },
  ];
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes,
        connections: {
          Input: { main: [[{ node: "Code", type: "main", index: 0 }]] },
        },
      }),
    ),
  );
  const source = context.nodeByName.get("Input").key;
  const flow = buildValueFlow(context, {
    sourceAnnotations: annotations.map((annotation) => ({
      ...annotation,
      nodeKey: source,
      provenance: "operator",
    })),
  });
  const value = flow.output(context.nodeByName.get("Code").key, field);
  return {
    value,
    source,
    flow,
    context,
    codes: flow.diagnostics.map((entry) => entry.code),
  };
}

function candidate(run) {
  assert.ok(run.value.sensitivityClasses.includes("secret_candidate"));
  assert.notEqual(run.value.status, "resolved");
  assert.equal(run.value.constant, undefined);
  assert.equal(run.value.guards.length, 0);
  assert.ok(!run.codes.includes("code_effects_partially_analyzed"));
  assert.ok(!run.codes.includes("code_call_effect_unresolved"));
}

test("pop of a fresh split keeps the whole input dependency without alias mutation claims", () => {
  const code =
    "const filename=$json.body.password.split('/').pop();return {json:{result:filename,fixed:'public'}};";
  const run = analyze(code);
  candidate(run);
  assert.ok(
    run.value.origins.some((origin) => origin.fieldPath === "/body/password"),
  );
  assert.equal(analyze(code, "/fixed").value.constant, "public");
  const clean = analyze(
    "const result='file.bin'.split('.').pop();return {json:{result}};",
  );
  assert.ok(!clean.value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(clean.value.constant, undefined);
});

test("join retains selected element and separator classes without copying array shape to a string", () => {
  const run = analyze(
    "const rows=[$json.body.password,$json.body.email];const selected=rows.filter(Boolean);return {json:{result:selected.join($json.body.separator)}};",
  );
  candidate(run);
  assert.ok(run.value.sensitivityClasses.includes("pii_candidate"));
  assert.ok(
    run.value.origins.some((origin) => origin.fieldPath === "/body/separator"),
  );
  assert.equal(run.value.fields, undefined);
  assert.equal(run.value.representativeElement, undefined);
  assert.equal(run.value.fullObject, false);
});

test("slice keeps possible elements and bound dependencies while avoiding sibling classification", () => {
  const code =
    "const rows=$json.body.rows.filter(Boolean);const selected=rows.slice(1,-1);return {json:{result:selected[7].label}};";
  const run = analyze(code, "/result", [
    { fieldPath: "/body/rows/1/password", sensitivity: "secret_candidate" },
  ]);
  const classes = transferDataClasses(run.value, {
    classifications: [
      {
        nodeKey: run.source,
        field: "/body/rows/1/label",
        dataClass: "internal",
      },
      {
        nodeKey: run.source,
        field: "/body/rows/1/password",
        dataClass: "secret",
      },
    ],
  });
  assert.ok(classes.includes("internal"));
  assert.ok(!classes.includes("secret"));
  assert.equal(run.value.presence, "unknown");
  assert.ok(
    run.value.origins.some(
      (origin) => JSON.stringify(origin.descendantPath) === '[null,"label"]',
    ),
  );
  const bounds = analyze(
    "const rows=[{label:'public'}];return {json:{result:rows.slice($json.body.password)[0].label}};",
  );
  candidate(bounds);
});

test("literal regular-expression match summarizes captures without executing a regex or validating input", () => {
  const code =
    "const captures=$json.body.password.match(/Subject:(.+?)\\n/i);return {json:{result:captures?.[1].trim(),fixed:'public'}};";
  const run = analyze(code);
  candidate(run);
  assert.ok(
    run.value.origins.some(
      (origin) =>
        origin.fieldPath === "/body/password" && origin.projectionUnknown,
    ),
  );
  assert.equal(analyze(code, "/fixed").value.constant, "public");
});

test("Date and numeric builtins propagate arguments without asserting finite values or guard success", () => {
  for (const value of [
    "new Date($json.body.password)",
    "Date.parse($json.body.password)",
    "Math.floor(Number($json.body.password))",
    "Math.min(1,Number($json.body.password))",
    "Number.isFinite($json.body.password)",
    "Number.isSafeInteger($json.body.password)",
  ]) {
    const run = analyze(
      `const calculated=${value};return {json:{result:calculated,fixed:'public'}};`,
    );
    candidate(run);
    assert.ok(
      run.value.origins.some((origin) => origin.fieldPath === "/body/password"),
    );
  }
  for (const value of ["new Date()", "Date.now()", "Math.round(12.3)"])
    assert.ok(
      !analyze(
        `return {json:{result:${value}}};`,
      ).value.sensitivityClasses.includes("secret_candidate"),
    );
});

test("general mutation custom dispatch dynamic methods and callback effects remain unsupported", () => {
  for (const code of [
    "const list=$json.body.password.split('/');list.pop();return {json:{result:list}};",
    "const list=[$json.body.password];return {json:{result:list.pop()}};",
    "const source=$json.body;return {json:{result:source.join()}};",
    "return {json:{result:$json.body.password.match($json.body.matcher)}};",
    "const fn=$json.body.method;return {json:{result:Math[fn]($json.body.password)}};",
    "const Math={floor:value=>value};return {json:{result:Math.floor($json.body.password)}};",
    "const values=[$json.body.password];return {json:{result:values.join(fetch($json.body.password))}};",
  ]) {
    const run = analyze(code);
    assert.notEqual(run.value.status, "resolved");
    assert.ok(
      run.codes.includes("code_effects_partially_analyzed") ||
        run.codes.includes("code_statement_profile_unresolved"),
      code,
    );
    assert.equal(run.value.guards.length, 0);
  }
});

test("Date and clock method chains retain local arguments and closure parameters", () => {
  for (const expression of [
    "new Date(x).toISOString()",
    "new Date($json.body.password).toISOString()",
    "new Date().toLocaleString(x)",
    "$now.toFormat(x)",
    "$today.toLocaleString(x)",
    "convert(x)",
  ]) {
    const run = analyze(
      `const x=$json.body.password;function convert(v){return new Date(v).toISOString();}return {json:{result:${expression},fixed:'public'}};`,
    );
    candidate(run);
    assert.ok(
      run.value.origins.some((origin) => origin.fieldPath === "/body/password"),
    );
  }
  const clean = analyze("return {json:{result:new Date().toISOString()}};");
  assert.ok(!clean.value.sensitivityClasses.includes("secret_candidate"));
  assert.equal(clean.value.guards.length, 0);
});

test("unsupported constructors and clock dispatch preserve candidates without claiming pure effects", () => {
  for (const expression of [
    "new Date(x).unknownMethod()",
    "new Date().unknownMethod(x)",
    "new Date(x)[method]()",
    "$now[method](x)",
    "new Date(x).toISOString(...[x])",
    "new Custom(x).format()",
  ]) {
    const run = analyze(
      `const x=$json.body.password;const method=$json.body.method;return {json:{result:${expression}}};`,
    );
    assert.ok(
      run.value.sensitivityClasses.includes("secret_candidate"),
      expression,
    );
    assert.ok(
      run.value.origins.some((origin) => origin.fieldPath === "/body/password"),
      expression,
    );
    assert.ok(run.codes.includes("code_call_effect_unresolved"));
    assert.ok(run.codes.includes("code_effects_partially_analyzed"));
    assert.equal(run.value.guards.length, 0);
  }
  for (const code of [
    "const Date=$json.body.factory;const x=$json.body.password;return {json:{result:new Date(x).toISOString()}};",
    "const $now=$json.body.clock;const x=$json.body.password;return {json:{result:$now.toFormat(x)}};",
  ]) {
    const run = analyze(code);
    assert.ok(run.value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(run.codes.includes("code_effects_partially_analyzed"));
    assert.equal(run.value.guards.length, 0);
  }
});
