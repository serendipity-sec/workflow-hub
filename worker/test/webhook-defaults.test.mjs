import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseWorkflow } from "../dist/workflow/n8n.js";

function input() {
  return JSON.parse(
    readFileSync(
      new URL("../fixtures/workflows/interpolated.json", import.meta.url),
    ),
  );
}

test("omitted multi-method default retains both GET and POST output ports", () => {
  const workflow = input();
  workflow.nodes[0].parameters.multipleMethods = true;
  delete workflow.nodes[0].parameters.httpMethod;
  workflow.connections.Webhook.main.unshift(null);
  const graph = parseWorkflow(Buffer.from(JSON.stringify(workflow)));
  assert.equal(graph.edges[0].output, 1);
  assert.ok(
    graph.diagnostics.some((item) => item.code === "unsupported_config"),
  );
});

test("single-method Webhook still rejects an extra output", () => {
  const workflow = input();
  workflow.connections.Webhook.main.unshift(null);
  assert.throws(
    () => parseWorkflow(Buffer.from(JSON.stringify(workflow))),
    /broken_connection/,
  );
});
