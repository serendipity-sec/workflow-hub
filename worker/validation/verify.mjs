import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { runExternal, summarizeExternal } from "./baselines.mjs";
import { frozenCorpus, metrics, readJson, root } from "./corpus.mjs";

const historical = frozenCorpus();
const current = readJson(
  new URL("../fixtures/cases-0.1.2.json", import.meta.url),
);
const corpus =
  process.argv[2] === "worker"
    ? {
        ...historical,
        cases: historical.cases.map((entry) => ({
          ...entry,
          ...current.cases.find(({ id }) => id === entry.id),
        })),
      }
    : historical;
const [mode, first, second] = process.argv.slice(2);

async function runWorker(directory) {
  const { compareAnalysis, compareResults } =
    await import("../dist/analysis/compare.js");
  const { resultSchema, versions } =
    await import("../dist/contracts/contract.js");
  const results = new Map();
  const observations = {};
  mkdirSync(directory, { recursive: true });
  const save = (name, value) =>
    writeFileSync(
      resolve(directory, `${name}.json`),
      JSON.stringify(value, null, 2) + "\n",
    );
  const mismatches = [];
  for (const example of corpus.cases) {
    const task = {
      contractVersion: versions.contract,
      taskId: `validation-${example.id}`,
      attemptId: "validation-attempt",
      workflowVersionId: `workflow-${example.id}`,
      inputSha256: example.inputSha256,
      leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      file: { kind: "local", path: `fixtures/${example.file}` },
    };
    const taskName = `task-${example.id}`;
    save(taskName, task);
    const execution = spawnSync(
      process.execPath,
      ["dist/cli.js", "local", resolve(directory, `${taskName}.json`)],
      { cwd: root, timeout: 10_000, maxBuffer: 256 * 1024, windowsHide: true },
    );
    writeFileSync(
      resolve(directory, `${example.id}.stdout.txt`),
      execution.stdout ?? "",
    );
    writeFileSync(
      resolve(directory, `${example.id}.stderr.txt`),
      execution.stderr ?? "",
    );
    let result;
    try {
      assert.ok(!execution.error);
      result = resultSchema.parse(JSON.parse(execution.stdout));
      assert.equal(execution.status, result.status === "error" ? 1 : 0);
      save(example.id, result);
      results.set(example.id, result);
    } catch {
      observations[example.id] = "failure";
      mismatches.push(`${example.id}: analysis or contract failed`);
      continue;
    }
    observations[example.id] =
      result.status === "error"
        ? "failure"
        : result.status === "unsupported"
          ? "unsupported"
          : result.findings.length
            ? "positive"
            : "negative";
    try {
      assert.equal(result.status, example.status);
      for (const key of [
        "taskId",
        "attemptId",
        "workflowVersionId",
        "inputSha256",
        "contractVersion",
      ]) {
        assert.equal(result[key], task[key], key);
      }
      assert.equal(
        result.coverage[0]?.disposition ?? null,
        example.disposition,
      );
      assert.equal(result.findings.length, example.label === "risk" ? 1 : 0);
      if (example.label === "risk") {
        const [finding] = result.findings;
        assert.equal(finding.reference, example.reference);
        assert.equal(finding.guard, example.guard);
        assert.equal(finding.source.pointer, example.sourcePointer);
        assert.equal(finding.sink.pointer, example.sinkPointer);
        assert.deepEqual(
          finding.path.map(({ pointer }) => pointer),
          example.pathPointers,
        );
      }
    } catch (error) {
      mismatches.push(`${example.id}: ${error.message}`);
    }
  }

  const checks = [
    ...corpus.rechecks,
    {
      baseline: corpus.behavior.baseline,
      candidate: corpus.behavior.candidate,
      expected: "inconclusive",
      alteration: "rule_version_changed",
    },
  ];
  const rechecks = [];
  for (const check of checks) {
    const before = results.get(check.baseline);
    const after = results.get(check.candidate);
    try {
      const candidate = check.alteration
        ? { ...after, rulesVersion: "99.0.0" }
        : after;
      const observed = compareResults(before, candidate);
      rechecks.push({ ...check, observed });
      assert.deepEqual(observed, [
        { id: before.findings[0].id, status: check.expected },
      ]);
    } catch (error) {
      mismatches.push(
        `${check.baseline} → ${check.candidate}: ${error.message}`,
      );
    }
  }

  const comparisonChecks = [
    {
      baseline: "bound",
      candidate: "interpolated",
      basis: "matched",
      coverage: "unchanged",
      finding: "introduced",
    },
    {
      baseline: "bound",
      candidate: "removed-sink",
      basis: "matched",
      coverage: "reduced",
    },
    {
      baseline: "bound",
      candidate: "interpolated",
      alteration: "rule_version_changed",
      basis: "different_analysis_versions",
      coverage: "unknown",
      finding: "inconclusive",
    },
  ];
  const analysisComparisons = [];
  for (const { basis, coverage, finding, ...check } of comparisonChecks) {
    const before = results.get(check.baseline);
    const after = results.get(check.candidate);
    try {
      assert.ok(before && after, "comparison inputs were not captured");
      const candidate = check.alteration
        ? { ...after, rulesVersion: "99.0.0" }
        : after;
      const observed = compareAnalysis(before, candidate);
      analysisComparisons.push({ ...check, observed });
      assert.deepEqual(observed, {
        basis,
        coverage: {
          baseline: before.status,
          candidate: after.status,
          change: coverage,
        },
        rechecks: [],
        newFindings: finding
          ? [{ id: after.findings[0].id, status: finding }]
          : [],
      });
    } catch (error) {
      mismatches.push(
        `${check.baseline} → ${check.candidate} analysis comparison: ${error.message}`,
      );
    }
  }
  const summary = {
    observations,
    metrics: metrics(corpus.cases, observations),
    rechecks,
    analysisComparisons,
    mismatches,
  };
  save("summary", summary);
  save("worker-results", { ...summary, results: Object.fromEntries(results) });
  console.log(JSON.stringify(summary, null, 2));
  assert.deepEqual(mismatches, []);
}

if (mode === "captured") {
  const summary = summarizeExternal(corpus, resolve(root, "validation/raw"));
  assert.deepEqual(
    summary,
    readJson(resolve(root, "validation/external-results.json")),
  );
  console.log(JSON.stringify(summary, null, 2));
} else if (mode === "external" && first) {
  const directory = resolve(second ?? "evidence-local/external");
  const summary = runExternal(corpus, resolve(first), directory);
  const json = JSON.stringify(summary, null, 2) + "\n";
  writeFileSync(resolve(directory, "summary.json"), json);
  console.log(json);
  for (const key of [
    "n8nQueryExpression",
    "n8nUnusedParametersProxy",
    "flowguardPostgresInputValidationProxy",
  ]) {
    assert.equal(summary[key].metrics.all.failed, 0, key);
  }
  assert.equal(summary.postgresControl.passed, true);
} else if (mode === "worker") {
  await runWorker(resolve(first ?? "evidence-local/worker"));
} else {
  console.error(
    "Usage: node validation/verify.mjs captured | worker [output-dir] | external <flowguard-dir> [output-dir]",
  );
  process.exitCode = 2;
}
