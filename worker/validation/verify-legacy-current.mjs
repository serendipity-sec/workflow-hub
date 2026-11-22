import assert from "node:assert/strict";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { analyzeWorkflow } from "../dist/analysis.js";
import { versions } from "../dist/contract.js";
import { frozenCorpus, metrics, sha256 } from "./corpus.mjs";

const historical = frozenCorpus();
const manifestBytes = await readFile(
  new URL("../fixtures/cases-0.1.2.json", import.meta.url),
);
const current = JSON.parse(manifestBytes);
assert.deepEqual(
  current.cases.map(({ id, file }) => ({ id, file })),
  historical.cases.map(({ id, file }) => ({ id, file })),
);
const observations = {};
const results = [];
for (const expected of current.cases) {
  const prior = historical.cases.find(({ id }) => id === expected.id);
  const bytes = await readFile(prior.path);
  assert.equal(sha256(bytes), prior.inputSha256);
  const result = analyzeWorkflow(bytes, {
    taskId: "validation-" + expected.id,
    attemptId: "validation-attempt",
    workflowVersionId: "workflow-" + expected.id,
    inputSha256: prior.inputSha256,
  });
  assert.equal(result.status, expected.status, expected.id);
  assert.equal(result.coverage[0]?.disposition ?? null, expected.disposition);
  assert.equal(result.findings.length, expected.label === "risk" ? 1 : 0);
  observations[expected.id] =
    result.status === "unsupported"
      ? "unsupported"
      : result.findings.length
        ? "positive"
        : "negative";
  results.push({ id: expected.id, inputSha256: prior.inputSha256, result });
}
const changedLabels = current.cases
  .filter(
    (expected) =>
      expected.label !==
      historical.cases.find(({ id }) => id === expected.id).label,
  )
  .map(({ id }) => id);
assert.deepEqual(changedLabels, ["type-constrained-false"]);
const output = {
  outcome: "passed",
  scope: "fixed_synthetic_static_candidates_not_exploitability",
  engineVersion: versions.engine,
  currentManifestSha256: sha256(manifestBytes),
  correctedHistoricalLabels: changedLabels,
  correction:
    "false_equals_does_not_prove_number_type_due_to_null_and_undefined",
  originalInputsAndHistoricalResultsPreserved: true,
  workflowExecution: "not_run",
  metrics: metrics(current.cases, observations),
  results,
  verificationScriptSha256: sha256(await readFile(new URL(import.meta.url))),
};
const target = resolve(
  process.argv[2] ?? "evidence-local/legacy-current-results.json",
);
await mkdir(dirname(target), { recursive: true });
await writeFile(target, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    outcome: output.outcome,
    cases: results.length,
    metrics: output.metrics,
  }) + "\n",
);
