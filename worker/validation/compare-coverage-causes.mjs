import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  buildCoverageExplanation,
  causeKinds,
} from "../dist/service/coverage-causes.js";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { newOutputPath } from "./output-files.mjs";

const [output, ...directories] = process.argv.slice(2);
assert.ok(
  output && directories.length >= 2 && directories.length % 2 === 0,
  "Supply output and one or more pairs of frozen before/after directories",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const outputPath = await newOutputPath(output, directories);
const artifactsDirectory = outputPath + ".artifacts";
let artifactsCreated = false;
const samples = [];
const seen = new Set();
for (let pair = 0; pair < directories.length; pair += 2) {
  const beforeDir = await realpath(resolve(directories[pair]));
  const afterDir = await realpath(resolve(directories[pair + 1]));
  const canonical = (path) =>
    process.platform === "win32" ? path.toLowerCase() : path;
  assert.notEqual(
    canonical(beforeDir),
    canonical(afterDir),
    "Before and after must be different directories; frozen baseline must not be modified",
  );
  const manifest = async (dir) => {
    const data = JSON.parse(
      await readFile(join(dir, "downloads.json"), "utf8"),
    );
    assert.ok(
      data.samples?.length > 0 &&
        data.samples.length <= 30 &&
        !data.failures?.length,
      "Require nonempty complete acquisition manifests",
    );
    assert.equal(
      new Set(data.samples.map((sample) => sample.id)).size,
      data.samples.length,
    );
    return data;
  };
  const beforeManifest = await manifest(beforeDir);
  const afterManifest = await manifest(afterDir);
  assert.deepEqual(
    beforeManifest.samples.map((s) => [s.id, s.sha256]).sort(),
    afterManifest.samples.map((s) => [s.id, s.sha256]).sort(),
    "Do not silently drop, add or replace comparison samples",
  );
  for (const sample of beforeManifest.samples) {
    assert.ok(
      Number.isSafeInteger(sample.id) && sample.id > 0 && !seen.has(sample.id),
    );
    seen.add(sample.id);
    const rows = [];
    for (const directory of [beforeDir, afterDir]) {
      const bytes = await readFile(
        join(directory, `${sample.id}.workflow.json`),
      );
      assert.equal(hash(bytes), sample.sha256);
      const raw = await readFile(
        join(directory, `${sample.id}.assessment.json`),
      );
      const report = assessmentReportSchema.parse(JSON.parse(raw));
      assert.equal(report.inputSha256, sample.sha256);
      const explanation = buildCoverageExplanation(report);
      assert.equal(
        explanation.truncated,
        false,
        "Comparison requires every diagnostic code in the explanation",
      );
      const artifact = Buffer.from(JSON.stringify(explanation, null, 2) + "\n");
      if (!artifactsCreated) {
        await mkdir(artifactsDirectory);
        artifactsCreated = true;
      }
      // Each comparison gets its own derived artifacts; both frozen inputs stay untouched.
      const label = directory === beforeDir ? "before" : "after";
      await writeFile(
        join(artifactsDirectory, `${sample.id}.coverage.${label}.json`),
        artifact,
        { flag: "wx" },
      );
      rows.push({
        engineVersion: report.engineVersion,
        image:
          report.boundary.kind === "docker"
            ? report.boundary.imageSha256
            : null,
        assessmentSha256: hash(raw),
        coverageExplanationSha256: hash(artifact),
        status: report.status,
        counts: explanation.counts,
        diagnosticOccurrences: explanation.diagnosticOccurrences,
        scopeNoteOccurrences: explanation.scopeNoteOccurrences,
        toolFailures: explanation.toolFailures,
        fileFailures: explanation.fileFailures,
        error: explanation.error,
        codes: Object.fromEntries(
          explanation.reasons.map((reason) => [
            reason.code,
            reason.occurrences,
          ]),
        ),
      });
    }
    samples.push({
      id: sample.id,
      inputSha256: sample.sha256,
      before: rows[0],
      after: rows[1],
    });
  }
}
const aggregate = (phase) => ({
  statuses: Object.fromEntries(
    ["analyzed", "partial", "unsupported", "error"].map((status) => [
      status,
      samples.filter((s) => s[phase].status === status).length,
    ]),
  ),
  counts: Object.fromEntries(
    causeKinds.map((kind) => [
      kind,
      samples.reduce((n, s) => n + s[phase].counts[kind], 0),
    ]),
  ),
  affectedSamples: Object.fromEntries(
    causeKinds.map((kind) => [
      kind,
      samples.filter((s) => s[phase].counts[kind] > 0).length,
    ]),
  ),
  diagnosticOccurrences: samples.reduce(
    (n, s) => n + s[phase].diagnosticOccurrences,
    0,
  ),
  toolFailures: samples.reduce((n, s) => n + s[phase].toolFailures, 0),
  fileFailures: samples.reduce((n, s) => n + s[phase].fileFailures, 0),
});
const before = aggregate("before"),
  after = aggregate("after");
const codes = [
  ...new Set(
    samples.flatMap((s) => [
      ...Object.keys(s.before.codes),
      ...Object.keys(s.after.codes),
    ]),
  ),
]
  .sort()
  .map((code) => ({
    code,
    before: samples.reduce((n, s) => n + (s.before.codes[code] ?? 0), 0),
    after: samples.reduce((n, s) => n + (s.after.codes[code] ?? 0), 0),
    beforeSamples: samples.filter((s) => s.before.codes[code] > 0).length,
    afterSamples: samples.filter((s) => s.after.codes[code] > 0).length,
  }));
const receipt = {
  schemaVersion: "1.0.0",
  outcome:
    after.statuses.error || after.toolFailures || after.fileFailures
      ? "failed"
      : "passed",
  workflowExecution: "not_run",
  actualTeamApiIntegration: "not_run",
  modelCalls: 0,
  meaning: "diagnostic_occurrences_not_vulnerabilities",
  classificationComplete:
    before.counts.unclassified === 0 && after.counts.unclassified === 0,
  sampleCount: samples.length,
  before,
  after,
  codes,
  samples,
};
await writeFile(outputPath, JSON.stringify(receipt, null, 2) + "\n", {
  flag: "wx",
});
console.log(
  JSON.stringify({
    outcome: receipt.outcome,
    sampleCount: samples.length,
    classificationComplete: receipt.classificationComplete,
    before,
    after,
    changedCodes: codes.filter((c) => c.before !== c.after),
  }),
);
if (receipt.outcome !== "passed" || !receipt.classificationComplete)
  process.exitCode = 1;
