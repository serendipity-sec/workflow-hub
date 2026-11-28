import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/workflow/static-context.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";
import {
  analyzeExtendedSinks,
  transferDataClasses,
} from "../dist/rules/extended-sinks.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";

function analyze(jsCode, options = {}) {
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
    {
      name: "Sink",
      type: "n8n-nodes-base.slack",
      typeVersion: 2.3,
      parameters: {
        select: "channel",
        channelId: { mode: "id", value: "synthetic-channel" },
        text: options.expression ?? "={{ $json.result }}",
      },
    },
  ];
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes,
        connections: {
          Input: { main: [[{ node: "Code", type: "main", index: 0 }]] },
          Code: { main: [[{ node: "Sink", type: "main", index: 0 }]] },
        },
      }),
    ),
  );
  const source = context.nodeByName.get("Input").key;
  const sink = context.nodeByName.get("Sink").key;
  const flow = buildValueFlow(context, {
    sourceAnnotations: (options.annotations ?? []).map((entry) => ({
      ...entry,
      nodeKey: source,
      provenance: "operator",
    })),
  });
  const value = flow.output(
    context.nodeByName.get("Code").key,
    options.field ?? "/result",
  );
  const evidence = {
    classifications: (
      options.classifications ?? [
        { field: "/body/rows/1/label", dataClass: "internal" },
      ]
    ).map((entry) => ({ ...entry, nodeKey: source })),
    policy: {
      egress: [
        {
          id: "public-only",
          nodeKey: sink,
          sink: "slack",
          mode: "allowlist",
          destinations: ["synthetic-channel"],
          allowedDataClasses: ["public"],
        },
      ],
    },
  };
  const rules = analyzeExtendedSinks(context, flow, evidence).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  const codes = rules.flatMap((rule) =>
    rule.findings.flatMap((finding) =>
      finding.evidence.map((entry) => entry.code),
    ),
  );
  return {
    value,
    flow,
    context,
    evidence,
    classes: transferDataClasses(value, evidence),
    codes,
    rules,
  };
}

const choose = (kind, left, right) =>
  kind === "if"
    ? `let kept=${left}; if($json.body.pick){kept=${right};}`
    : `const kept=${kind === "?:" ? `$json.body.pick ? ${left} : ${right}` : `${left} ${kind} ${right}`};`;

test("common alternative joins retain representative and literal array candidates through every selection syntax", () => {
  const representative = "rows.filter(Boolean)";
  const literal = "[{label:'public'}]";
  for (const kind of ["if", "?:", "||", "??"])
    for (const [left, right] of [
      [representative, literal],
      [literal, representative],
      [representative, representative],
    ])
      for (const index of [0, 1, 7])
        for (const downstream of [false, true]) {
          const run = analyze(
            `const rows=$json.body.rows; ${choose(kind, left, right)} return {json:{result:${downstream ? "kept" : `kept[${index}].label`}}};`,
            {
              ...(downstream
                ? {
                    field: `/result/${index}/label`,
                    expression: `={{ $json.result[${index}].label }}`,
                  }
                : {}),
              annotations: [
                { fieldPath: "/body/rows/0", sensitivity: "public_literal" },
                {
                  fieldPath: "/body/rows/1/label",
                  sensitivity: "secret_candidate",
                },
              ],
            },
          );
          assert.ok(
            run.classes.includes("internal"),
            JSON.stringify({ kind, left, right, index, downstream }),
          );
          assert.ok(run.classes.includes("secret"));
          assert.ok(run.classes.includes("unknown"));
          assert.ok(run.codes.includes("trusted_policy_transfer_disallowed"));
          assert.notEqual(run.value.status, "resolved");
          assert.equal(run.value.constant, undefined);
          assert.equal(run.value.guards.length, 0);
          assert.ok(
            !JSON.stringify(run.rules).includes("projectionAlternatives"),
          );
          assert.ok(
            !JSON.stringify(run.rules).includes("projectionDependencies"),
          );
        }
});

test("collection callbacks consume each joined array alternative without adding a second source index", () => {
  for (const kind of ["if", "?:", "||", "??"])
    for (const callback of ["filter(Boolean)", "map(row=>row)"])
      for (const right of ["[{label:'public'}]", "rows.filter(Boolean)"]) {
        const run = analyze(
          `const rows=$json.body.rows; ${choose(kind, "rows.filter(Boolean)", right)} const again=kept.${callback}; return {json:{result:again[7].label}};`,
        );
        assert.ok(
          run.classes.includes("internal"),
          JSON.stringify({ kind, callback, right }),
        );
        assert.ok(run.codes.includes("trusted_policy_transfer_disallowed"));
        assert.ok(
          run.value.origins.some(
            (origin) =>
              JSON.stringify(origin.descendantPath) === '[null,"label"]',
          ),
          JSON.stringify({ kind, callback, right, value: run.value }),
        );
      }
});

test("a real numeric object member after the selected item is retained in the source selector", () => {
  const run = analyze(
    "const rows=$json.body.rows; const kept=rows.filter(Boolean) ?? [{label:'public'}]; return {json:{result:kept[0]['0'].label}};",
    {
      classifications: [
        { field: "/body/rows/1/0/label", dataClass: "internal" },
        { field: "/body/rows/1/label", dataClass: "secret" },
      ],
    },
  );
  assert.ok(run.classes.includes("internal"));
  assert.ok(!run.classes.includes("secret"), JSON.stringify(run.value));
  assert.ok(
    run.value.origins.some(
      (origin) =>
        JSON.stringify(origin.descendantPath) === '[null,"0","label"]',
    ),
  );
});

test("JSON parse and opaque calls retain input dependency selectors without assuming the same output shape", () => {
  for (const annotation of [false, true])
    for (const operation of [
      "JSON.parse(JSON.stringify(kept))",
      "JSON.parse(kept)",
      "unavailable(kept)",
    ])
      for (const selectedField of [false, true]) {
        const run = analyze(
          `const rows=$json.body.rows; const kept=rows.filter(Boolean)${selectedField ? "[0].label" : ""}; const parsed=${operation}; return {json:{result:parsed[0].label}};`,
          {
            annotations: annotation
              ? [
                  {
                    fieldPath: "/body/rows/1/label",
                    sensitivity: "secret_candidate",
                  },
                ]
              : [],
            classifications: [
              { field: "/body/rows/1/label", dataClass: "secret" },
            ],
          },
        );
        assert.ok(
          run.classes.includes("secret"),
          JSON.stringify({ annotation, operation, selectedField }),
        );
        assert.ok(run.codes.includes("secret_candidate_transferred"));
        assert.ok(run.codes.includes("trusted_policy_transfer_disallowed"));
        assert.notEqual(run.value.status, "resolved");
        assert.ok(run.value.origins.some((origin) => origin.projectionUnknown));
        assert.ok(
          !run.value.origins.some(
            (origin) =>
              JSON.stringify(origin.descendantPath) === '[null,"0","label"]',
          ),
        );
      }
  const selected = analyze(
    "const kept=$json.body.rows.filter(Boolean)[0].label; return {json:{result:JSON.parse(JSON.stringify(kept))[0].label}};",
    {
      classifications: [
        { field: "/body/rows/1/password", dataClass: "secret" },
      ],
    },
  );
  assert.ok(!selected.classes.includes("secret"));
});

test("conditional dependencies remain distinct from candidate array elements", () => {
  const run = analyze(
    "const rows=$json.body.rows; const kept=$json.body.secretFlag ? rows.filter(Boolean) : [{label:'public'}]; return {json:{result:kept[0].label}};",
  );
  assert.ok(run.classes.includes("internal"));
  assert.ok(run.classes.includes("secret"));
  const dependency = run.value.origins.find(
    (origin) => origin.fieldPath === "/body/secretFlag",
  );
  assert.ok(dependency);
  assert.equal(dependency.descendantPath, undefined);
  assert.equal(dependency.projectionUnknown, true);
});

test("mixed scalar alternatives remain uncertain without discarding collection candidates", () => {
  for (const other of ["'public'", "$json.body.other"])
    for (const kind of ["if", "?:", "||", "??"]) {
      const run = analyze(
        `const rows=$json.body.rows; ${choose(kind, "rows.filter(Boolean)", other)} return {json:{result:kept[1].label}};`,
      );
      assert.ok(run.classes.includes("internal"));
      assert.ok(run.classes.includes("unknown"));
      assert.notEqual(run.value.status, "resolved");
      assert.equal(run.value.guards.length, 0);
    }
});

test("known member selection excludes sibling annotations through conditional and repeated member projections", () => {
  for (const kind of ["if", "?:", "||", "??"])
    for (const callback of ["", ".filter(Boolean)", ".map(row=>row)"]) {
      const run = analyze(
        `const rows=$json.body.rows; ${choose(kind, "rows.filter(Boolean)", "[{'0':{label:'public'}}]")} const again=kept${callback}; return {json:{result:again[1]['0'].label}};`,
        {
          annotations: [
            {
              fieldPath: "/body/rows/1/0/password",
              sensitivity: "secret_candidate",
            },
          ],
          classifications: [
            { field: "/body/rows/1/0/password", dataClass: "secret" },
          ],
        },
      );
      assert.ok(
        !run.classes.includes("secret"),
        JSON.stringify({ kind, callback, origins: run.value.origins }),
      );
      assert.ok(run.classes.includes("unknown"));
    }
});

test("serialization keeps dependency classes without copying collection output structure", () => {
  const run = analyze(
    "const kept=$json.body.rows.filter(Boolean); return {json:{result:JSON.stringify(kept)}};",
  );
  assert.ok(run.classes.includes("internal"));
  assert.equal(run.value.representativeElement, undefined);
  assert.equal(run.value.projectionAlternatives, undefined);
  assert.equal(run.value.fields, undefined);
  assert.ok(run.value.origins.some((origin) => origin.projectionUnknown));
});

test("bounded nested joins retain observed risk candidates when structure is simplified", () => {
  const repeated = Array.from(
    { length: 22 },
    () => "kept=$json.body.pick ? kept : kept;",
  ).join("\n");
  const run = analyze(
    `let kept=$json.body.rows.filter(Boolean); ${repeated} return {json:{result:kept[7].label}};`,
    {
      annotations: [
        { fieldPath: "/body/rows/1/label", sensitivity: "secret_candidate" },
      ],
    },
  );
  assert.notEqual(run.value.status, "resolved");
  assert.ok(run.classes.includes("secret"));
  assert.ok(run.classes.includes("internal"));
  assert.ok(run.codes.includes("trusted_policy_transfer_disallowed"));
  assert.ok(
    run.value.diagnosticCodes.includes("code_value_shape_limit") ||
      run.value.diagnosticCodes.includes("flow_budget_exceeded"),
  );
});

test("optional branch fields preserve collection structure and unknown presence through later projections", () => {
  for (const index of [0, 1, 7])
    for (const [possible, suffix, field] of [
      ["rows.filter(Boolean)", `[${index}].label`, `/${index}/label`],
      [
        "$json.body.pick ? rows.filter(Boolean) : [{label:'public'}]",
        `[${index}].label`,
        `/${index}/label`,
      ],
      [
        "(rows.filter(Boolean) ?? [{label:'public'}]).map(row=>row)",
        `[${index}].label`,
        `/${index}/label`,
      ],
      ["rows.filter(Boolean)[0]", ".label", "/label"],
      [
        "{items:rows.filter(Boolean)}",
        `.items[${index}].label`,
        `/items/${index}/label`,
      ],
    ])
      for (const annotation of [false, true]) {
        const run = analyze(
          `const rows=$json.body.rows;let output={};if($json.body.pick){output={result:${possible}};}return {json:output};`,
          {
            field: `/result${field}`,
            expression: `={{ $json.result${suffix} }}`,
            annotations: annotation
              ? [
                  {
                    fieldPath: "/body/rows/1/label",
                    sensitivity: "secret_candidate",
                  },
                ]
              : [],
          },
        );
        assert.ok(
          run.classes.includes("internal"),
          JSON.stringify({ index, possible, annotation }),
        );
        if (annotation) assert.ok(run.classes.includes("secret"));
        assert.ok(run.classes.includes("unknown"));
        assert.ok(run.codes.includes("trusted_policy_transfer_disallowed"));
        assert.notEqual(run.value.status, "resolved");
        assert.equal(run.value.presence, "unknown");
        assert.equal(run.value.constant, undefined);
        assert.equal(run.value.guards.length, 0);
        assert.ok(!JSON.stringify(run.rules).includes("representativeElement"));
        assert.ok(
          !JSON.stringify(run.rules).includes("projectionAlternatives"),
        );
      }
});

test("optional wrappers do not invent known presence or import unrelated sibling classifications", () => {
  for (const possible of ["[{label:'public'}]", "rows.filter(Boolean)"]) {
    const run = analyze(
      `const rows=$json.body.rows;let output={};if($json.body.pick){output={result:${possible}};}return {json:output};`,
      {
        field: "/result/0/label",
        expression: "={{ $json.result[0].label }}",
        annotations: [
          {
            fieldPath: "/body/rows/1/password",
            sensitivity: "secret_candidate",
          },
        ],
        classifications: [
          { field: "/body/rows/1/password", dataClass: "secret" },
        ],
      },
    );
    assert.ok(!run.classes.includes("secret"));
    assert.notEqual(run.value.status, "resolved");
    assert.equal(run.value.presence, "unknown");
    assert.equal(run.value.constant, undefined);
    assert.equal(run.value.guards.length, 0);
  }
  const scalar = analyze(
    "let output={};if($json.body.pick){output={result:'public'};}return {json:output};",
  );
  assert.equal(scalar.value.presence, "unknown");
  assert.equal(scalar.value.constant, undefined);
  assert.ok(scalar.value.sensitivityClasses.includes("public_literal"));
});
