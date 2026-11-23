import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow } from "../dist/value-flow.js";
import {
  analyzeExtendedSinks,
  transferDataClasses,
} from "../dist/extended-sinks.js";
import { ruleResultSchema } from "../dist/static-contract.js";

function analyze(
  jsCode,
  field = "/result",
  withSink = false,
  annotations = [],
  sinkExpression = "={{ $json.result }}",
) {
  const nodes = [
    {
      id: "input",
      name: "Input",
      type: "n8n-nodes-base.webhook",
      typeVersion: 2.1,
      parameters: {},
    },
    {
      id: "code",
      name: "Code",
      type: "n8n-nodes-base.code",
      typeVersion: 2,
      parameters: { jsCode },
    },
  ];
  if (withSink)
    nodes.push({
      id: "sink",
      name: "Sink",
      type: "n8n-nodes-base.slack",
      typeVersion: 2.3,
      parameters: {
        select: "channel",
        channelId: { mode: "id", value: "synthetic-channel" },
        text: sinkExpression,
      },
    });
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes,
        connections: {
          Input: { main: [[{ node: "Code", type: "main", index: 0 }]] },
          ...(withSink
            ? { Code: { main: [[{ node: "Sink", type: "main", index: 0 }]] } }
            : {}),
        },
      }),
    ),
  );
  const flow = buildValueFlow(context, {
    sourceAnnotations: annotations.map((annotation) => ({
      ...annotation,
      nodeKey: context.nodeByName.get("Input").key,
      provenance: "operator",
    })),
  });
  const value = flow.output(context.nodeByName.get("Code").key, field);
  return {
    value,
    context,
    flow,
    codes: flow.diagnostics.map(({ code }) => code),
  };
}
const sensitive = (value) => {
  assert.ok(value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(
    value.origins.some(({ fieldPath }) => fieldPath.includes("password")),
  );
  assert.equal(value.guards.length, 0);
};

test("filter(Boolean) retains secret origins and leaves survivor indices unverified", () => {
  const { value, codes } = analyze(
    "const values = ['', $json.body.password]; const kept = values.filter(Boolean); return {json:{result:kept[0]}};",
  );
  sensitive(value);
  assert.ok(codes.includes("code_collection_cardinality_unverified"));
  assert.ok(!codes.includes("code_call_effect_unresolved"));
  assert.ok(!codes.includes("code_effects_partially_analyzed"));
  const clean = analyze(
    "const values = ['public']; return {json:{result:values.filter(Boolean)}};",
  );
  assert.ok(!clean.value.sensitivityClasses.includes("secret_candidate"));
});

test("named map callbacks use their defining primitive capture and retain source fields", () => {
  const { value, codes } = analyze(
    "const key = 'password'; const select = value => value[key]; const input = [$json.body]; const result = input.map(select); return {json:{result:result[0]}};",
  );
  sensitive(value);
  assert.ok(!codes.includes("code_call_effect_unresolved"));
  assert.ok(!codes.includes("code_closure_capture_unresolved"));
  assert.ok(!codes.includes("code_effects_partially_analyzed"));
});

test("inline and named filtering never retain a stale public value at a shifted index", () => {
  for (const predicate of ["value=>Boolean(value)", "accept"]) {
    const { value, codes } = analyze(
      `const accept=value=>Boolean(value); const values=['', $json.body.password]; const kept=values.filter(${predicate}); return {json:{result:kept[0]}};`,
    );
    sensitive(value);
    assert.ok(codes.includes("code_collection_cardinality_unverified"));
    assert.notEqual(value.constant, "");
    assert.ok(!codes.includes("code_effects_partially_analyzed"));
  }
});

test("unknown collection filtering preserves named sensitive candidates through an outgoing connector", () => {
  for (const predicate of ["value=>value.password", "Boolean"]) {
    const run = analyze(
      `const values=$json.body.rows; const kept=values.filter(${predicate}); return {json:{result:kept[0].password}};`,
      "/result",
      true,
    );
    assert.ok(run.value.sensitivityClasses.includes("secret_candidate"));
    assert.equal(run.value.status, "partial");
    assert.ok(
      run.value.origins.some(({ fieldPath }) => fieldPath === "/body/rows"),
    );
    assert.ok(
      !run.value.origins.some(({ fieldPath }) => fieldPath.includes("/0")),
    );
    assert.equal(run.value.guards.length, 0);
    const rules = analyzeExtendedSinks(run.context, run.flow);
    assert.ok(
      rules.some(({ findings }) =>
        findings.some(({ evidence }) =>
          evidence.some(({ code }) => code === "secret_candidate_transferred"),
        ),
      ),
    );
  }
});

test("filter reindexing retains explicit descendant classes and public-only Slack policy violations", () => {
  for (const predicate of ["row=>true", "row=>row.keep", "Boolean"]) {
    for (const dataClass of ["secret", "internal", "personal"]) {
      for (const annotation of [false, true]) {
        const field = "/body/rows/0/label";
        const run = analyze(
          `const rows=$json.body.rows; const kept=rows.filter(${predicate}); return {json:{result:kept[0].label}};`,
          "/result",
          true,
          annotation && dataClass !== "internal"
            ? [
                {
                  fieldPath: field,
                  sensitivity:
                    dataClass === "secret"
                      ? "secret_candidate"
                      : "pii_candidate",
                },
              ]
            : [],
        );
        const inputKey = run.context.nodeByName.get("Input").key;
        const sinkKey = run.context.nodeByName.get("Sink").key;
        const evidence = {
          classifications: [{ nodeKey: inputKey, field, dataClass }],
          policy: {
            egress: [
              {
                id: "public-only",
                nodeKey: sinkKey,
                sink: "slack",
                mode: "allowlist",
                destinations: ["synthetic-channel"],
                allowedDataClasses: ["public"],
              },
            ],
          },
        };
        const classes = transferDataClasses(run.value, evidence);
        assert.ok(classes.includes(dataClass));
        assert.ok(classes.includes("unknown"));
        assert.notEqual(run.value.status, "resolved");
        assert.equal(run.value.constant, undefined);
        assert.equal(run.value.guards.length, 0);
        assert.ok(
          run.value.origins.some(
            ({ fieldPath, includesDescendants }) =>
              fieldPath === "/body/rows" && includesDescendants,
          ),
        );
        const rules = analyzeExtendedSinks(run.context, run.flow, evidence).map(
          (rule) => ruleResultSchema.parse(rule),
        );
        const findings = rules.flatMap((rule) => rule.findings);
        assert.ok(
          findings.some(({ evidence }) =>
            evidence.some(
              ({ code }) => code === "trusted_policy_transfer_disallowed",
            ),
          ),
        );
        const candidateCode =
          dataClass === "secret"
            ? "secret_candidate_transferred"
            : dataClass === "personal"
              ? "personal_data_candidate_transferred"
              : "data_field_transferred";
        assert.ok(
          findings.some(
            (finding) =>
              finding.claim === "candidate" &&
              finding.evidence.some(({ code }) => code === candidateCode),
          ),
        );
        assert.ok(!JSON.stringify(rules).includes("includesDescendants"));
        assert.ok(!JSON.stringify(rules).includes(field));
      }
    }
  }
});

test("collection subtree candidates do not pick up unrelated paths, escaped siblings or other node policies", () => {
  const run = analyze(
    "const rows=$json.body.rows; const kept=rows.filter(row=>row.keep); return {json:{result:kept[0].label}};",
    "/result",
    true,
  );
  const inputKey = run.context.nodeByName.get("Input").key;
  const sinkKey = run.context.nodeByName.get("Sink").key;
  for (const [nodeKey, field] of [
    [inputKey, "/body/rowsMore/0/label"],
    [inputKey, "/body/rows~1suffix/0/label"],
    [sinkKey, "/body/rows/0/label"],
  ]) {
    const classes = transferDataClasses(run.value, {
      classifications: [{ nodeKey, field, dataClass: "internal" }],
    });
    assert.ok(!classes.includes("internal"));
  }
  const clean = analyze(
    "const rows=[{label:'public'}]; const kept=rows.filter(row=>true); return {json:{result:kept[0].label}};",
    "/result",
    true,
  );
  assert.equal(clean.value.constant, undefined);
  assert.equal(clean.value.presence, "unknown");
  assert.equal(clean.value.status, "partial");
  assert.ok(clean.value.sensitivityClasses.includes("public_literal"));
  assert.ok(clean.value.origins.every(({ kind }) => kind === "literal"));
  assert.ok(
    !transferDataClasses(clean.value, {
      classifications: [
        {
          nodeKey: clean.context.nodeByName.get("Input").key,
          field: "/body/rows/0/label",
          dataClass: "secret",
        },
      ],
    }).includes("secret"),
  );
});

test("known selected members do not inherit explicit sensitive sibling classifications", () => {
  for (const predicate of ["row=>true", "row=>row.keep", "Boolean"]) {
    for (const annotation of [false, true]) {
      const field = "/body/rows/0/password";
      const run = analyze(
        `const rows=$json.body.rows; const kept=rows.filter(${predicate}); return {json:{result:kept[0].label}};`,
        "/result",
        true,
        annotation
          ? [{ fieldPath: field, sensitivity: "secret_candidate" }]
          : [],
      );
      const evidence = {
        classifications: [
          {
            nodeKey: run.context.nodeByName.get("Input").key,
            field,
            dataClass: "secret",
          },
        ],
        policy: {
          egress: [
            {
              id: "public-only",
              nodeKey: run.context.nodeByName.get("Sink").key,
              sink: "slack",
              mode: "allowlist",
              destinations: ["synthetic-channel"],
              allowedDataClasses: ["public"],
            },
          ],
        },
      };
      const classes = transferDataClasses(run.value, evidence);
      assert.ok(!classes.includes("secret"));
      assert.ok(classes.includes("unknown"));
      assert.notEqual(run.value.status, "resolved");
      const rules = analyzeExtendedSinks(run.context, run.flow, evidence).map(
        (rule) => ruleResultSchema.parse(rule),
      );
      const codes = rules.flatMap((rule) =>
        rule.findings.flatMap((finding) =>
          finding.evidence.map((item) => item.code),
        ),
      );
      assert.ok(!codes.includes("secret_candidate_transferred"));
      assert.ok(!codes.includes("trusted_policy_transfer_disallowed"));
      assert.ok(!JSON.stringify(rules).includes("descendantPath"));
    }
  }
});

test("candidate member paths preserve unknown indices, escaped keys and matching ancestor policies", () => {
  const run = analyze(
    "const rows=$json.body.rows; const kept=rows.filter(row=>true); return {json:{result:kept[0]['public/label']}};",
    "/result",
    true,
  );
  const nodeKey = run.context.nodeByName.get("Input").key;
  for (const field of [
    "/body/rows/99999/public~1label",
    "/body/rows/3",
    "/body/rows",
  ]) {
    assert.ok(
      transferDataClasses(run.value, {
        classifications: [{ nodeKey, field, dataClass: "internal" }],
      }).includes("internal"),
    );
  }
  for (const field of [
    "/body/rows/3/public/label",
    "/body/rows/3/public~1labelSuffix",
    "/body/rows/name/public~1label",
  ]) {
    assert.ok(
      !transferDataClasses(run.value, {
        classifications: [{ nodeKey, field, dataClass: "internal" }],
      }).includes("internal"),
    );
  }
});

test("every static output index uses the representative across Code and downstream connector projections", () => {
  for (const index of [0, 1, 7]) {
    for (const predicate of ["row=>true", "row=>row.keep", "Boolean"]) {
      for (const downstream of [false, true]) {
        for (const annotations of [
          [],
          [{ fieldPath: "/body/rows/0", sensitivity: "public_literal" }],
          [
            { fieldPath: "/body/rows/0", sensitivity: "public_literal" },
            { fieldPath: "/body/rows/1/label", sensitivity: "pii_candidate" },
          ],
        ]) {
          const run = analyze(
            `const rows=$json.body.rows; const kept=rows.filter(${predicate}); return {json:{result:${downstream ? "kept" : `kept[${index}].label`}}};`,
            downstream ? `/result/${index}/label` : "/result",
            true,
            annotations,
            downstream
              ? `={{ $json.result[${index}].label }}`
              : "={{ $json.result }}",
          );
          const inputKey = run.context.nodeByName.get("Input").key;
          const sinkKey = run.context.nodeByName.get("Sink").key;
          const evidence = {
            classifications: [
              { nodeKey: inputKey, field: "/body/rows/0", dataClass: "public" },
              {
                nodeKey: inputKey,
                field: "/body/rows/1/label",
                dataClass: "personal",
              },
              {
                nodeKey: inputKey,
                field: "/body/rows/2/label",
                dataClass: "internal",
              },
              {
                nodeKey: inputKey,
                field: "/body/rows/3/label",
                dataClass: "secret",
              },
            ],
            policy: {
              egress: [
                {
                  id: "public-only",
                  nodeKey: sinkKey,
                  sink: "slack",
                  mode: "allowlist",
                  destinations: ["synthetic-channel"],
                  allowedDataClasses: ["public"],
                },
              ],
            },
          };
          const classes = transferDataClasses(run.value, evidence);
          for (const expected of ["personal", "internal", "secret", "unknown"])
            assert.ok(classes.includes(expected));
          assert.equal(run.value.status, "partial");
          assert.equal(run.value.presence, "unknown");
          assert.equal(run.value.constant, undefined);
          assert.equal(run.value.guards.length, 0);
          assert.ok(
            run.value.origins.some(
              (origin) =>
                JSON.stringify(origin.descendantPath) === '[null,"label"]',
            ),
          );
          const rules = analyzeExtendedSinks(
            run.context,
            run.flow,
            evidence,
          ).map((rule) => ruleResultSchema.parse(rule));
          const codes = rules.flatMap((rule) =>
            rule.findings.flatMap((finding) =>
              finding.evidence.map((item) => item.code),
            ),
          );
          assert.ok(codes.includes("secret_candidate_transferred"));
          assert.ok(codes.includes("personal_data_candidate_transferred"));
          assert.ok(codes.includes("trusted_policy_transfer_disallowed"));
          assert.ok(!JSON.stringify(rules).includes("representativeElement"));
          assert.ok(!JSON.stringify(rules).includes("descendantPath"));
        }
      }
    }
  }
});

test("representative selections keep unrelated sibling policy fields excluded at every index", () => {
  for (const index of [0, 1, 7]) {
    const run = analyze(
      "const rows=$json.body.rows; const kept=rows.filter(row=>row.keep); return {json:{result:kept}};",
      `/result/${index}/label`,
      true,
      [
        { fieldPath: "/body/rows/0", sensitivity: "public_literal" },
        { fieldPath: "/body/rows/1/password", sensitivity: "secret_candidate" },
      ],
      `={{ $json.result[${index}].label }}`,
    );
    const evidence = {
      classifications: [
        {
          nodeKey: run.context.nodeByName.get("Input").key,
          field: "/body/rows/1/password",
          dataClass: "secret",
        },
      ],
    };
    assert.ok(!transferDataClasses(run.value, evidence).includes("secret"));
    assert.ok(
      run.value.origins.some(
        (origin) => JSON.stringify(origin.descendantPath) === '[null,"label"]',
      ),
    );
  }
});

test("different representative depths survive branch merging and output indices have distinct value identities", () => {
  const run = analyze(
    "const rows=$json.body.rows; const first=rows.filter(Boolean)[0]; if($json.body.flag){return {json:{result:first.label}};} else {return {json:{result:first.filter(Boolean)[0].label}};}",
    "/result",
    true,
  );
  const inputKey = run.context.nodeByName.get("Input").key;
  const classes = transferDataClasses(run.value, {
    classifications: [
      { nodeKey: inputKey, field: "/body/rows/0/label", dataClass: "internal" },
      { nodeKey: inputKey, field: "/body/rows/0/0/label", dataClass: "secret" },
    ],
  });
  assert.ok(classes.includes("internal"));
  assert.ok(classes.includes("secret"));
  assert.ok(classes.includes("unknown"));
  for (const path of [
    [null, "label"],
    [null, null, "label"],
  ])
    assert.ok(
      run.value.origins.some(
        (origin) =>
          JSON.stringify(origin.descendantPath) === JSON.stringify(path),
      ),
    );
  const list = analyze(
    "const kept=$json.body.rows.filter(Boolean); return {json:{result:kept}};",
  );
  const codeKey = list.context.nodeByName.get("Code").key;
  const selections = [0, 1, 7].map((index) =>
    list.flow.output(codeKey, `/result/${index}/label`),
  );
  assert.equal(new Set(selections.map((value) => value.valueId)).size, 3);
  assert.ok(selections.every((value) => value.guards.length === 0));
});

test("literal collections retain public candidates while selected positions and presence stay unknown", () => {
  const run = analyze(
    "const values=[{label:'public'}]; const kept=values.filter(row=>true); return {json:{result:kept}};",
  );
  const codeKey = run.context.nodeByName.get("Code").key;
  for (const index of [0, 1, 7]) {
    const value = run.flow.output(codeKey, `/result/${index}/label`);
    assert.equal(value.constant, undefined);
    assert.equal(value.status, "partial");
    assert.equal(value.presence, "unknown");
    assert.ok(value.sensitivityClasses.includes("public_literal"));
    assert.ok(!value.sensitivityClasses.includes("secret_candidate"));
    assert.ok(value.origins.every((origin) => origin.kind === "literal"));
  }
});

test("an IF check on one representative position cannot validate another position", () => {
  const node = (name, type, typeVersion, parameters = {}) => ({
    name,
    type: `n8n-nodes-base.${type}`,
    typeVersion,
    parameters,
  });
  const nodes = [
    node("Input", "webhook", 2.1),
    node("Code", "code", 2, {
      jsCode:
        "const kept=$json.body.rows.filter(Boolean); return {json:{result:kept}};",
    }),
    node("Guard", "if", 2.2, {
      conditions: {
        combinator: "and",
        options: { version: 2, typeValidation: "strict", caseSensitive: true },
        conditions: [
          {
            leftValue: "={{ $json.result[0].label }}",
            rightValue: 3,
            operator: { type: "number", operation: "equals" },
          },
        ],
      },
    }),
    node("Sink", "noOp", 1),
  ];
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes,
        connections: Object.fromEntries(
          nodes.slice(0, -1).map((entry, index) => [
            entry.name,
            {
              main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]],
            },
          ]),
        ),
      }),
    ),
  );
  const flow = buildValueFlow(context);
  const selected = [0, 1, 7].map((index) =>
    flow.resolve(
      context.nodeByName.get("Sink").key,
      `={{ $json.result[${index}].label }}`,
    ),
  );
  assert.equal(new Set(selected.map((value) => value.valueId)).size, 3);
  for (const value of selected) {
    assert.notEqual(value.status, "resolved");
    assert.equal(value.guards.length, 0);
    assert.equal(value.presence, "unknown");
  }
});

test("some/every model possible callback data without proving a validation guard", () => {
  for (const method of ["some", "every"]) {
    const { value, codes } = analyze(
      `const values = [$json.body]; const result = values.${method}(value => value.password); return {json:{result}};`,
    );
    sensitive(value);
    assert.equal(value.constant, undefined);
    assert.equal(value.fullObject, false);
    assert.ok(!codes.includes("code_call_effect_unresolved"));
    const clean = analyze(
      `const values = [1, 2]; return {json:{result:values.${method}(value => value > 0)}};`,
    );
    assert.equal(clean.value.constant, undefined);
    assert.ok(!clean.value.sensitivityClasses.includes("secret_candidate"));
  }
});

test("resolved primitive keys retain lexical meaning while unsafe and dynamic keys stay unknown", () => {
  const captured = analyze(
    "const key='password'; function read(value){return value[key];} function wrapper(key){const values=[$json.body]; return values.map(read)[0];} let result=wrapper('public'); return {json:{result}};",
  );
  sensitive(captured.value);
  for (const key of ["__proto__", "prototype", "constructor"]) {
    const { value, codes } = analyze(
      `const key='${key}'; const select=value=>value[key]; const values=[$json.body]; return {json:{result:values.map(select)[0]}};`,
    );
    assert.ok(codes.includes("unsafe_field_reference"));
    assert.notEqual(value.status, "resolved");
  }
  const dynamic = analyze(
    "const key=$json.body.key; const values=[$json.body]; return {json:{result:values.map(value=>value[key])[0]}};",
  );
  assert.notEqual(dynamic.value.status, "resolved");
  assert.ok(dynamic.codes.includes("code_closure_capture_unresolved"));
});

test("flatMap retains array and scalar callback possibilities with a shape limit", () => {
  for (const returned of ["[value.password]", "value.password"]) {
    const { value, codes } = analyze(
      `const values = [$json.body]; return {json:{result:values.flatMap(value => ${returned})}};`,
    );
    sensitive(value);
    assert.ok(codes.includes("code_flatmap_shape_unverified"));
    assert.ok(!codes.includes("code_call_effect_unresolved"));
    assert.notEqual(value.status, "resolved");
  }
});

test("callback array parameter preserves its classification while the index remains unknown", () => {
  const { value, codes } = analyze(
    "const values = [$json.body.password]; return {json:{result:values.map((value, index, array) => array[0])[0]}};",
  );
  sensitive(value);
  assert.ok(codes.includes("code_collection_index_unverified"));
});

test("new callback forms reject effects, captured mutation, unknown helpers and this arguments", () => {
  for (const source of [
    "const values=[$json.body.password]; return {json:{result:values.some(value => fetch(value))}};",
    "let total=''; const values=[$json.body.password]; return {json:{result:values.every(value => { total=value; return true; })}};",
    "const values=[$json.body.password]; return {json:{result:values.map(missing)}};",
    "const values=[$json.body.password]; return {json:{result:values.flatMap(value => value, {})}};",
    "const values=[$json.body.password]; return {json:{result:values.reduce((a,value) => a+value,'')}};",
    "const values=[$json.body.password]; return {json:{result:values.forEach(value => value)}};",
  ]) {
    const { value, codes } = analyze(source);
    sensitive(value);
    assert.ok(codes.includes("code_effects_partially_analyzed"));
    assert.notEqual(value.status, "resolved");
  }
});

test("isolated JSON parse and unused catch merge both values without blanket exception opacity", () => {
  for (const caught of ["(error)", ""]) {
    const { value, codes } = analyze(
      `const raw=$json.body.password; let result={}; try { result=JSON.parse(raw); } catch ${caught} { result={raw}; } return {json:{result}};`,
    );
    sensitive(value);
    assert.ok(codes.includes("json_parse_shape_unverified"));
    assert.ok(!codes.includes("code_exception_value_unverified"));
    assert.ok(!codes.includes("code_try_state_unresolved"));
    assert.ok(!codes.includes("code_effects_partially_analyzed"));
    assert.notEqual(value.status, "resolved");
  }
  const clean = analyze(
    'const raw="{}"; let result={}; try { result=JSON.parse(raw); } catch { result={message:"invalid"}; } return {json:{result}};',
  );
  assert.ok(!clean.value.sensitivityClasses.includes("secret_candidate"));
  assert.ok(!clean.codes.includes("code_try_state_unresolved"));
});

test("general try state, exception objects, revivers, mutation and finally remain opaque", () => {
  for (const body of [
    "try { result=JSON.parse(raw); } catch (e) { result=e.message; }",
    "try { result=raw; result=JSON.parse(raw); } catch { result='failed'; }",
    "try { result=JSON.parse(raw); } finally { result=raw; }",
    "try { result=JSON.parse(raw, value => value); } catch { result=raw; }",
    "try { result=JSON.parse(raw.trim()); } catch { result=raw; }",
    "try { result=JSON.parse(raw); } catch { fetch(raw); }",
  ]) {
    const { value, codes } = analyze(
      `const raw=$json.body.password; let result={}; ${body} return {json:{result}};`,
    );
    sensitive(value);
    assert.ok(codes.includes("code_effects_partially_analyzed"));
    assert.notEqual(value.status, "resolved");
  }
});

test("n8n top-level await parses without execution and retains unresolved sensitive data", () => {
  const { value, codes } = analyze(
    "const result=await $json.body.password; return {json:{result}};",
  );
  sensitive(value);
  assert.notEqual(value.status, "resolved");
  assert.equal(value.constant, undefined);
  assert.ok(codes.includes("code_await_result_unverified"));
  assert.ok(!codes.includes("code_parse_unavailable"));
  const effect = analyze(
    "const result=await unavailable($json.body.password); return {json:{result}};",
  );
  sensitive(effect.value);
  assert.ok(effect.codes.includes("code_call_effect_unresolved"));
  assert.ok(effect.codes.includes("code_effects_partially_analyzed"));
  assert.ok(!effect.codes.includes("code_parse_unavailable"));
  const invalid = analyze(
    "function sync(){await unavailable($json.body.password);} return {json:{result:'public'}};",
  );
  assert.ok(invalid.codes.includes("code_parse_unavailable"));
});

test("async local helpers remain in the unsupported effect profile", () => {
  const { value, codes } = analyze(
    "async function helper(value){return value;} const result=await helper($json.body.password); return {json:{result}};",
  );
  sensitive(value);
  assert.notEqual(value.status, "resolved");
  assert.ok(codes.includes("code_statement_profile_unresolved"));
  assert.ok(codes.includes("code_source_observations_only"));
});
