import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import { analyzeWorkflow } from "../dist/analysis/analysis.js";
import { compareAnalysis } from "../dist/analysis/compare.js";
import { resultSchema, versions } from "../dist/contracts/contract.js";
import { summarizeExternal } from "../validation/baselines.mjs";
import {
  frozenCorpus,
  metrics,
  readJson,
  root,
} from "../validation/corpus.mjs";

test("frozen corpus verifies raw evidence and exact case counts", () => {
  const observed = summarizeExternal(
    frozenCorpus(),
    resolve(root, "validation/raw"),
  );
  assert.deepEqual(
    observed,
    readJson(resolve(root, "validation/external-results.json")),
  );
  assert.equal(observed.n8nPositiveControl.passed, true);
  assert.equal(
    observed.n8nQueryExpression.observations[
      observed.n8nPositiveControl.caseId
    ],
    "positive",
  );
});

test("captured worker results preserve corpus identities and denominators", () => {
  const corpus = frozenCorpus();
  const evidence = readJson(resolve(root, "validation/worker-results.json"));
  const observations = {};
  for (const entry of corpus.cases) {
    const captured = evidence.results[entry.id];
    assert.equal(captured.engineVersion, "0.1.0");
    const result = resultSchema.parse({
      ...captured,
      engineVersion: versions.engine,
    });
    assert.equal(result.taskId, "validation-" + entry.id);
    assert.equal(result.attemptId, "validation-attempt");
    assert.equal(result.workflowVersionId, "workflow-" + entry.id);
    assert.equal(result.inputSha256, entry.inputSha256);
    assert.equal(result.status, entry.status);
    observations[entry.id] =
      result.status === "unsupported"
        ? "unsupported"
        : result.status === "error"
          ? "failure"
          : result.findings.length
            ? "positive"
            : "negative";
  }
  assert.deepEqual(observations, evidence.observations);
  assert.deepEqual(metrics(corpus.cases, observations), evidence.metrics);
  assert.deepEqual(evidence.mismatches, []);
});

test("captured version comparisons preserve new findings and changes in coverage", () => {
  const { results, analysisComparisons } = readJson(
    resolve(root, "validation/worker-results.json"),
  );
  const current = Object.fromEntries(
    frozenCorpus().cases.map(({ id, path }) => [
      id,
      analyzeWorkflow(readFileSync(path), results[id]),
    ]),
  );
  assert.deepEqual(
    analysisComparisons.map(({ baseline, candidate, alteration }) => [
      baseline,
      candidate,
      alteration,
    ]),
    [
      ["bound", "interpolated", undefined],
      ["bound", "removed-sink", undefined],
      ["bound", "interpolated", "rule_version_changed"],
    ],
  );
  for (const {
    baseline,
    candidate,
    alteration,
    observed,
  } of analysisComparisons) {
    const before = current[baseline];
    const after = alteration
      ? { ...current[candidate], rulesVersion: "99.0.0" }
      : current[candidate];
    assert.deepEqual(observed, compareAnalysis(before, after));
  }
  assert.deepEqual(
    analysisComparisons.map(({ observed }) => [
      observed.basis,
      observed.coverage.change,
      observed.newFindings.map(({ status }) => status),
    ]),
    [
      ["matched", "unchanged", ["introduced"]],
      ["matched", "reduced", []],
      ["different_analysis_versions", "unknown", ["inconclusive"]],
    ],
  );
  for (const [bound, basis] of [
    [results.bound, "unsupported_analysis_versions"],
    [current.bound, "different_analysis_versions"],
  ]) {
    assert.deepEqual(compareAnalysis(results.interpolated, bound), {
      basis,
      coverage: {
        baseline: "analyzed",
        candidate: "analyzed",
        change: "unknown",
      },
      rechecks: [
        { id: results.interpolated.findings[0].id, status: "inconclusive" },
      ],
      newFindings: [],
    });
  }
});

test("supported positives stay in the denominator after failures and unsupported outcomes", () => {
  const cases = [
    { id: "risk-one", label: "risk", split: "validation" },
    { id: "risk-two", label: "risk", split: "validation" },
    { id: "clean", label: "negative", split: "validation" },
    { id: "unknown", label: "unsupported", split: "validation" },
  ];
  const totals = metrics(cases, {
    "risk-one": "failure",
    "risk-two": "unsupported",
    clean: "negative",
    unknown: "positive",
  });
  assert.deepEqual(totals.validation, {
    positive: 2,
    negative: 1,
    tp: 0,
    fp: 0,
    fn: 2,
    tn: 1,
    failed: 1,
    unsupported: 1,
  });
});

test("native evidence preserves the wrong route and the corrected route's distinct HTTP outcomes", () => {
  const wrongRoute = readJson(
    resolve(root, "validation/native-bound/report.json"),
  );
  const native = readJson(
    resolve(root, "validation/native-bound-correct-route/report.json"),
  );
  assert.equal(wrongRoute.outcome, "error");
  assert.deepEqual(
    wrongRoute.responses.map(({ status }) => status),
    [404, 404, 404],
  );
  assert.equal(
    native.route,
    "/webhook/W18BoundFixture1/webhook/synthetic-lookup",
  );
  assert.equal(native.outcome, "passed");
  assert.deepEqual(
    native.responses.map(({ id, status, body }) => ({
      id,
      status,
      body: JSON.parse(body),
    })),
    [
      { id: 7, status: 200, body: { label: "book" } },
      { id: 9, status: 200, body: { label: "pen" } },
      {
        id: 13,
        status: 500,
        body: { code: 0, message: "No item to return was found" },
      },
    ],
  );
  assert.match(native.before, /^[a-f0-9]{64}$/);
  assert.equal(native.before, native.after);
  assert.deepEqual(native.postgresDataMount, {
    target: "/var/lib/postgresql",
    type: "tmpfs",
    attachedVolumes: 0,
  });
  assert.deepEqual(native.cleanup, {
    containers: 0,
    network: 0,
    verifiedRemoved: true,
    postgresDataRemoved: true,
  });
});

test("isolated native evidence shows identical normal responses for both frozen workflows", () => {
  const corpus = frozenCorpus();
  const native = readJson(
    resolve(root, "validation/native-normal-parity.json"),
  );
  assert.equal(native.outcome, "passed");
  assert.deepEqual(
    native.fixtures.map(({ role, caseId, inputSha256 }) => ({
      role,
      caseId,
      inputSha256,
    })),
    [
      { role: "original", caseId: "interpolated" },
      { role: "repaired", caseId: "bound" },
    ].map(({ role, caseId }) => ({
      role,
      caseId,
      inputSha256: corpus.cases.find(({ id }) => id === caseId).inputSha256,
    })),
  );
  const { addresses, ...isolation } = native.isolation;
  assert.deepEqual(isolation, {
    databaseNetwork: "none",
    sharedNamespace: true,
    publishedPorts: 0,
  });
  assert.ok(addresses.includes("127.0.0.1"));
  assert.ok(
    addresses.every((address) => ["127.0.0.1", "::1"].includes(address)),
  );
  assert.deepEqual(native.reader, {
    transactionReadOnly: true,
    select: true,
    writes: false,
  });
  assert.deepEqual(native.versions, {
    n8n: corpus.n8nVersion,
    postgres: "18.7",
  });
  for (const { role, route, workflowId } of native.fixtures) {
    assert.equal(route, `/webhook/${workflowId}/webhook/synthetic-lookup`);
    assert.deepEqual(
      native.publication[role],
      ["import", "publish", "export", "inspect"].map(
        (stage) => `BOOTSTRAP ${stage}-${role} exit=0`,
      ),
    );
    const responses = native.responses[role].map(
      ({ id, status, contentType, body }) => {
        assert.match(contentType, /^application\/json\b/);
        return { id, status, body: JSON.parse(body) };
      },
    );
    assert.deepEqual(responses, [
      { id: 7, status: 200, body: { label: "book" } },
      { id: 9, status: 200, body: { label: "pen" } },
      {
        id: 13,
        status: 500,
        body: { code: 0, message: "No item to return was found" },
      },
    ]);
  }
  const { before } = native.digests;
  assert.match(before, /^[a-f0-9]{64}$/);
  assert.deepEqual(native.digests, {
    before,
    original: before,
    repaired: before,
  });
  assert.deepEqual(native.cleanup, {
    n8n: 0,
    postgres: 0,
    verifiedRemoved: true,
    postgresDataRemoved: true,
  });
});
