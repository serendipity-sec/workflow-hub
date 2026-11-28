import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/workflow/static-context.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";

function analyze(parameters = {}, raw = {}, extraSource = false, port = 0) {
  const document = {
    nodes: [
      {
        name: "Input",
        type: "n8n-nodes-base.webhook",
        typeVersion: 2.1,
        parameters: {},
      },
      {
        name: "Guard",
        type: "n8n-nodes-base.if",
        typeVersion: 2.2,
        parameters: {
          conditions: {
            combinator: "and",
            options: {
              version: 2,
              typeValidation: "strict",
              caseSensitive: true,
            },
            conditions: [
              {
                leftValue: "={{ $json.body.id }}",
                rightValue: 3,
                operator: { type: "number", operation: "equals" },
              },
            ],
          },
        },
      },
      {
        name: "Limit",
        type: "n8n-nodes-base.limit",
        typeVersion: 1,
        parameters,
        ...raw,
      },
    ],
    connections: {
      Input: {
        main: [
          [
            { node: "Guard", type: "main", index: 0 },
            ...(extraSource ? [{ node: "Limit", type: "main", index: 0 }] : []),
          ],
        ],
      },
      Guard: { main: [[{ node: "Limit", type: "main", index: 0 }]] },
    },
  };
  const context = createContext(Buffer.from(JSON.stringify(document)));
  const flow = buildValueFlow(context);
  const key = context.nodeByName.get("Limit").key;
  return {
    id: flow.output(key, "/body/id", port),
    password: flow.output(key, "/body/password", port),
    codes: flow.diagnostics.map((d) => d.code),
  };
}

test("fixed Limit first/last slices preserve each emitted item JSON and exact upstream guards", () => {
  for (const parameters of [
    {},
    { maxItems: 1 },
    { maxItems: 20, keep: "lastItems", options: {} },
    { keep: "firstItems" },
  ]) {
    const run = analyze(parameters);
    assert.equal(run.id.status, "resolved");
    assert.ok(run.id.guards.some((guard) => guard.kind === "number_type"));
    assert.ok(run.password.sensitivityClasses.includes("secret_candidate"));
    assert.equal(run.password.origins[0].fieldPath, "/body/password");
    assert.equal(run.password.guards.length, 0);
    assert.ok(!run.codes.includes("node_transform_unsupported"));
  }
});

test("Limit dynamic options nonpositive sizes unknown versions bypass inputs and unusual execution stay unresolved", () => {
  for (const parameters of [
    { maxItems: 0 },
    { maxItems: -1 },
    { maxItems: 1.5 },
    { maxItems: "2" },
    { maxItems: "={{ $json.count }}" },
    { maxItems: 1000001 },
    { keep: "={{ $json.keep }}" },
    { keep: "other" },
    { options: { unreviewed: true } },
    { unreviewed: true },
  ]) {
    const run = analyze(parameters);
    assert.notEqual(run.id.status, "resolved");
    assert.equal(run.id.guards.length, 0);
  }
  for (const raw of [
    { typeVersion: 2 },
    { alwaysOutputData: true },
    { executeOnce: true },
    { disabled: true },
    { onError: "continueRegularOutput" },
  ])
    assert.notEqual(analyze({}, raw).id.status, "resolved");
  assert.equal(analyze({}, {}, true).id.guards.length, 0);
  assert.notEqual(analyze({}, {}, false, 1).id.status, "resolved");
});
