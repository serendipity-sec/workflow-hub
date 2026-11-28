import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { analyzeWorkflow } from "../dist/analysis/analysis.js";
import { compareAnalysis, compareResults } from "../dist/analysis/compare.js";
import { limits, resultSchema, versions } from "../dist/contracts/contract.js";

const fixtures = new URL("../fixtures/", import.meta.url);
const load = (name) => readFile(new URL(name, fixtures));
const manifest = JSON.parse(await load("cases-0.1.2.json"));
const samples = new Map(
  await Promise.all(
    manifest.cases.map(async (entry) => [entry.id, await load(entry.file)]),
  ),
);
const identity = JSON.parse(await load("task.json"));
const evalBytes = (bytes, versionId = "synthetic-version") =>
  resultSchema.parse(
    analyzeWorkflow(bytes, {
      taskId: identity.taskId,
      attemptId: identity.attemptId,
      workflowVersionId: versionId,
      inputSha256: createHash("sha256").update(bytes).digest("hex"),
    }),
  );
const example = (id, version) => evalBytes(samples.get(id), version);
const editable = (id) => JSON.parse(samples.get(id));
const edited = (object) =>
  evalBytes(Buffer.from(JSON.stringify(object)), "candidate");

test("analysis matches the pinned expected result and every predefined case", async () => {
  const captured = JSON.parse(await load("result.json"));
  assert.equal(captured.engineVersion, "0.1.0");
  assert.deepEqual(example("interpolated"), {
    ...captured,
    engineVersion: versions.engine,
  });
  for (const entry of manifest.cases) {
    const result = example(entry.id);
    assert.equal(result.status, entry.status, entry.id);
    assert.equal(
      result.coverage[0]?.disposition ?? null,
      entry.disposition,
      entry.id,
    );
    if (entry.label === "risk") {
      assert.equal(result.findings.length, 1, entry.id);
      const [finding] = result.findings;
      assert.equal(finding.reference, entry.reference, entry.id);
      assert.equal(finding.guard, entry.guard, entry.id);
      assert.equal(finding.source.pointer, entry.sourcePointer, entry.id);
      assert.equal(finding.sink.pointer, entry.sinkPointer, entry.id);
      assert.deepEqual(
        finding.path.map(({ pointer }) => pointer),
        entry.pathPointers,
        entry.id,
      );
    } else {
      assert.deepEqual(result.findings, [], entry.id);
    }
  }
});

test("a direct original reference to the same field retains a dominating strict guard", () => {
  const file = editable("direct-origin");
  file.nodes[1].parameters.conditions.conditions[0].leftValue =
    "={{ $json.body.id }}";
  assert.equal(edited(file).coverage[0].disposition, "guarded");
  file.nodes[1].parameters.looseTypeValidation = true;
  assert.equal(edited(file).status, "unsupported");
  file.nodes[1].parameters.looseTypeValidation = false;
  file.nodes[1].continueOnFail = true;
  assert.equal(edited(file).status, "unsupported");
  file.nodes[1].continueOnFail = false;
  file.nodes[1].rewireOutputLogTo = "ai_tool";
  assert.equal(edited(file).status, "unsupported");
});

test("binding options cannot protect query interpolation and quoted placeholders remain unknown", () => {
  const risk = editable("interpolated");
  risk.nodes[1].parameters.options =
    editable("bound").nodes[1].parameters.options;
  assert.equal(edited(risk).findings.length, 1);
  const bound = editable("bound");
  bound.nodes[1].parameters.query = bound.nodes[1].parameters.query.replace(
    "$1",
    "'$1'",
  );
  assert.equal(edited(bound).status, "unsupported");
  const missing = editable("bound");
  missing.nodes[1].parameters.options = {};
  assert.equal(edited(missing).status, "unsupported");
  const inactiveQuery = editable("interpolated");
  inactiveQuery.nodes[1].parameters.operation = "select";
  const inactiveResult = edited(inactiveQuery);
  assert.equal(inactiveResult.status, "unsupported");
  assert.deepEqual(inactiveResult.coverage, []);
});

test("retains scoped unknown coverage within the worker output limit", () => {
  const nodes = Array.from({ length: limits.nodes }, (_, index) => ({
    id: "node-" + index,
    name: "Node " + index,
    type: "n8n-nodes-base.code",
    typeVersion: 2,
    parameters: {},
  }));
  const connections = Object.fromEntries(
    nodes.map(({ name }, index) => [
      name,
      {
        main: [
          [
            {
              node: nodes[(index + 1) % nodes.length].name,
              type: "main",
              index: 0,
            },
          ],
        ],
      },
    ]),
  );
  const result = edited({ nodes, connections });
  assert.equal(result.status, "unsupported");
  assert.equal(result.diagnostics.length, limits.nodes);
  assert.equal(result.affectedNodeKeys.length, limits.nodes);
  for (const { affected } of result.diagnostics) {
    assert.equal(
      new Set(affected.map((index) => result.affectedNodeKeys[index])).size,
      limits.nodes,
    );
  }
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < limits.resultBytes);
});

test(
  "handles a bounded operand containing long runs of SQL whitespace",
  { timeout: 2_000 },
  () => {
    const file = editable("interpolated");
    file.nodes[1].parameters.query = file.nodes[1].parameters.query.replace(
      "{{ ",
      "{{" + " ".repeat(120_000),
    );
    file.nodes[1].parameters.query += " ".repeat(10_000);
    assert.equal(edited(file).coverage[0].disposition, "interpolated");
  },
);

test("file data or node names do not appear in evidence; array order preserves identity", () => {
  const baseline = example("direct-origin");
  const moved = editable("direct-origin");
  const [source, , sink] = moved.nodes;
  source.name = "privateLabel";
  moved.connections.privateLabel = moved.connections.Webhook;
  delete moved.connections.Webhook;
  sink.parameters.query = sink.parameters.query.replace(
    "Webhook",
    "privateLabel",
  );
  const leak = "privateCredentialMetadata";
  sink.credentials = { postgres: { id: leak } };
  moved.nodes.reverse();
  const result = edited(moved);
  assert.equal(result.findings[0].id, baseline.findings[0].id);
  assert.equal(result.findings[0].source.pointer, "/nodes/2");
  assert.equal(result.findings[0].sink.pointer, "/nodes/0/parameters/query");
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes(source.name) && !serialized.includes(leak));
});

test("recheck requires supported equivalent shape, source and versions", () => {
  for (const { baseline, candidate, expected } of manifest.rechecks) {
    const [comparison] = compareResults(
      example(baseline),
      example(candidate, "candidate"),
    );
    assert.equal(comparison.status, expected);
  }
  const baseline = example("interpolated");
  const credentialBefore = editable("interpolated");
  credentialBefore.nodes[1].credentials = {
    postgres: { id: "synthetic-reference" },
  };
  const withReference = evalBytes(
    Buffer.from(JSON.stringify(credentialBefore)),
    "baseline",
  );
  assert.equal(
    compareResults(withReference, example("bound", "candidate"))[0].status,
    "inconclusive",
  );
  const bound = editable("bound");
  bound.nodes[1].id = "replaced-sink";
  assert.equal(
    compareResults(baseline, edited(bound))[0].status,
    "inconclusive",
  );

  const changed = editable("bound");
  changed.nodes[1].parameters.query = changed.nodes[1].parameters.query.replace(
    "demo_items",
    "other_table",
  );
  assert.equal(
    compareResults(baseline, edited(changed))[0].status,
    "inconclusive",
  );
  const movedTrigger = editable("bound");
  movedTrigger.nodes[0].parameters.path = "different-lookup";
  assert.equal(
    compareResults(baseline, edited(movedTrigger))[0].status,
    "inconclusive",
  );
  const olderRules = {
    ...example("bound", "candidate"),
    rulesVersion: "older",
  };
  assert.equal(compareResults(baseline, olderRules)[0].status, "inconclusive");
  const same = editable("interpolated");
  same.nodes[0].position[0] += 50;
  const movedRisk = structuredClone(same);
  movedRisk.nodes[0].parameters.path = "different-route";
  assert.equal(
    compareResults(baseline, edited(movedRisk))[0].status,
    "inconclusive",
  );
  assert.equal(compareResults(baseline, edited(same))[0].status, "persisting");
  assert.equal(
    compareResults(baseline, evalBytes(Buffer.from("{"), "candidate"))[0]
      .status,
    "inconclusive",
  );
});

test("recheck follows the registered Webhook route", () => {
  const original = editable("interpolated");
  original.nodes[0].webhookId = "original-registration";
  const baseline = evalBytes(Buffer.from(JSON.stringify(original)), "baseline");
  const bound = editable("bound");
  bound.nodes[0].webhookId = "replacement-registration";
  const unchanged = compareAnalysis(baseline, edited(bound));
  assert.equal(unchanged.coverage.change, "unchanged");
  assert.equal(unchanged.rechecks[0].status, "binding_verified");

  bound.nodes[0].parameters.path = "different-lookup";
  assert.equal(
    compareResults(baseline, edited(bound))[0].status,
    "inconclusive",
  );
  delete bound.nodes[0].webhookId;
  bound.nodes[0].parameters.path = original.nodes[0].parameters.path;
  assert.equal(
    compareResults(baseline, edited(bound))[0].status,
    "inconclusive",
  );
});

test("recheck accepts relocated query locations and rejects unrelated locations", () => {
  const baseline = example("interpolated");
  const movedBound = editable("bound");
  movedBound.nodes.reverse();
  const candidate = edited(movedBound);
  assert.notEqual(
    candidate.coverage[0].sink.pointer,
    baseline.coverage[0].sink.pointer,
  );
  assert.equal(
    compareResults(baseline, candidate)[0].status,
    "binding_verified",
  );

  candidate.coverage[0].sink.pointer = "/settings";
  assert.equal(resultSchema.safeParse(candidate).success, false);
  const comparison = compareAnalysis(baseline, candidate);
  assert.equal(comparison.basis, "invalid_result");
  assert.deepEqual(comparison.rechecks, [
    { id: baseline.findings[0].id, status: "inconclusive" },
  ]);
});

test("a clean baseline exposes new risks and lost coverage", () => {
  const clean = example("bound");
  const risk = example("interpolated", "candidate");
  const missing = example("removed-sink", "candidate");
  assert.deepEqual(compareAnalysis(clean, risk), {
    basis: "matched",
    coverage: {
      baseline: "analyzed",
      candidate: "analyzed",
      change: "unchanged",
    },
    rechecks: [],
    newFindings: [{ id: risk.findings[0].id, status: "introduced" }],
  });
  assert.deepEqual(compareAnalysis(clean, missing), {
    basis: "matched",
    coverage: {
      baseline: "analyzed",
      candidate: "unsupported",
      change: "reduced",
    },
    rechecks: [],
    newFindings: [],
  });
  assert.equal(compareAnalysis(missing, clean).coverage.change, "expanded");
  const failure = evalBytes(Buffer.from("{"), "candidate");
  assert.deepEqual(compareAnalysis(clean, failure).coverage, {
    baseline: "analyzed",
    candidate: "error",
    change: "unknown",
  });
});

test("a changed lookup or analysis basis cannot prove introduction or persistence", () => {
  const earlier = example("interpolated");
  const changed = editable("interpolated");
  changed.nodes[1].parameters.query = changed.nodes[1].parameters.query.replace(
    "demo_items",
    "other_table",
  );
  const later = edited(changed);
  const report = compareAnalysis(earlier, later);
  assert.equal(earlier.findings[0].id, later.findings[0].id);
  assert.equal(report.coverage.change, "changed");
  assert.deepEqual(report.rechecks, [
    { id: earlier.findings[0].id, status: "inconclusive" },
  ]);
  assert.deepEqual(report.newFindings, [
    { id: later.findings[0].id, status: "inconclusive" },
  ]);

  const differentBasis = compareAnalysis(example("bound"), {
    ...later,
    rulesVersion: "older",
  });
  assert.equal(differentBasis.basis, "different_analysis_versions");
  assert.equal(differentBasis.coverage.change, "unknown");
  assert.deepEqual(differentBasis.newFindings, [
    { id: later.findings[0].id, status: "inconclusive" },
  ]);
});

test("a malformed stored result leaves valid baseline findings inconclusive", () => {
  const before = example("interpolated");
  const after = { ...example("bound", "candidate"), coverage: undefined };
  const expected = [{ id: before.findings[0].id, status: "inconclusive" }];
  assert.deepEqual(compareResults(before, after), expected);
  assert.deepEqual(compareAnalysis(before, after), {
    basis: "invalid_result",
    coverage: { baseline: "analyzed", candidate: "unknown", change: "unknown" },
    rechecks: expected,
    newFindings: [],
  });
  assert.deepEqual(
    compareAnalysis(before, { ...after, rulesVersion: "older" }),
    {
      basis: "invalid_result",
      coverage: {
        baseline: "analyzed",
        candidate: "unknown",
        change: "unknown",
      },
      rechecks: expected,
      newFindings: [],
    },
  );
});

test("compatible historical results retain warnings without adopting their analysis basis", () => {
  const before = { ...example("interpolated"), rulesVersion: "historical" };
  const after = {
    ...example("bound", "candidate"),
    rulesVersion: "historical",
  };
  const expected = [{ id: before.findings[0].id, status: "inconclusive" }];
  assert.deepEqual(compareAnalysis(before, after), {
    basis: "unsupported_analysis_versions",
    coverage: {
      baseline: "analyzed",
      candidate: "analyzed",
      change: "unknown",
    },
    rechecks: expected,
    newFindings: [],
  });
  assert.deepEqual(compareResults(before, after), expected);
});

test("missing or malformed version stamps do not supply candidate evidence", () => {
  const before = example("interpolated");
  const after = example("bound", "candidate");
  for (const rulesVersion of [undefined, 91, " "]) {
    assert.deepEqual(compareAnalysis(before, { ...after, rulesVersion }), {
      basis: "invalid_result",
      coverage: {
        baseline: "analyzed",
        candidate: "unknown",
        change: "unknown",
      },
      rechecks: [{ id: before.findings[0].id, status: "inconclusive" }],
      newFindings: [],
    });
  }
});
