import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join, dirname } from "node:path";
import { presentInspection, inspectionSchema } from "../dist/inspection.js";
import { llmDefaults } from "../dist/llm-review.js";

assert.ok(
  process.argv[2] && process.argv[3],
  "Supply frozen report directory and new summary path",
);
const directory = resolve(process.argv[2]);
const limit = Number(process.argv[4] ?? 15);
assert.ok(Number.isSafeInteger(limit) && limit > 0 && limit <= 30);
const manifest = JSON.parse(
  await readFile(join(directory, "downloads.json"), "utf8"),
);
assert.ok(
  Array.isArray(manifest.samples) &&
    manifest.samples.length > 0 &&
    manifest.samples.length <= 30,
  "A nonempty collected sample set is required",
);
assert.ok(
  manifest.samples.every(
    (sample) => Number.isSafeInteger(sample.id) && sample.id > 0,
  ),
);
assert.ok(
  !manifest.failures?.length,
  "Collection failures must be resolved or recorded separately before LLM verification",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const samples = [];
for (const sample of manifest.samples.slice(0, limit)) {
  const input = await readFile(join(directory, `${sample.id}.workflow.json`));
  assert.equal(hash(input), sample.sha256);
  const bytes = await readFile(join(directory, `${sample.id}.assessment.json`));
  const report = JSON.parse(bytes.toString("utf8"));
  assert.equal(report.inputSha256, sample.sha256);
  const inspection = inspectionSchema.parse(
    await presentInspection(report, {
      enabled: true,
      apiKey: process.env.OPENROUTER_API_KEY,
      model: process.env.WORKER_LLM_MODEL,
      maxOutputTokens:
        process.env.WORKER_LLM_MAX_OUTPUT_TOKENS === undefined
          ? undefined
          : Number(process.env.WORKER_LLM_MAX_OUTPUT_TOKENS),
    }),
  );
  assert.deepEqual(inspection.assessment, report);
  const output = Buffer.from(JSON.stringify(inspection, null, 2) + "\n");
  await writeFile(join(directory, `${sample.id}.inspection.json`), output, {
    mode: 0o600,
  });
  const result = {
    id: sample.id,
    inputSha256: sample.sha256,
    assessmentSha256: hash(bytes),
    inspectionSha256: hash(output),
    inspectionArtifact: `${sample.id}.inspection.json`,
    engineVersion: report.engineVersion,
    assessmentStatus: report.status,
    executionStatus: inspection.serviceReport.executionStatus,
    analysisStatus: inspection.serviceReport.analysisStatus,
    counts: inspection.serviceReport.counts,
    omitted: inspection.serviceReport.omitted,
    llmStatus: inspection.llm.status,
    llmCode:
      inspection.llm.status === "unavailable" ? inspection.llm.code : null,
    llmContextSha256: inspection.llm.contextSha256,
    availableReferences: inspection.llm.context.references.length,
    selectedReferences:
      inspection.llm.status === "generated"
        ? inspection.llm.selection.focusReferenceIds.length
        : 0,
    omittedReferences: inspection.llm.context.omittedReferences,
    usage: inspection.llm.status === "generated" ? inspection.llm.usage : null,
  };
  samples.push(result);
  console.log(
    JSON.stringify({
      id: sample.id,
      status: result.llmStatus,
      code: result.llmCode,
    }),
  );
  // Do not keep spending or retrying when account/auth or route is unavailable.
  if (inspection.llm.status === "unavailable") break;
}
const summary = {
  schemaVersion: "1.0.0",
  outcome:
    samples.length === Math.min(limit, manifest.samples.length) &&
    samples.every((s) => s.llmStatus === "generated")
      ? "passed"
      : "incomplete",
  model: process.env.WORKER_LLM_MODEL ?? llmDefaults.model,
  provider: "openrouter",
  maxPriceUsdPerMillionTokens: llmDefaults.maxPrice,
  workflowExecution: "not_run",
  actualTeamApiIntegration: "not_run",
  modelAuthority: "explanation_only",
  staticVerdictsUnchanged: true,
  sourceContentSent: false,
  modelSelectionReviewed: "separate_manual_review_required",
  renderedText: "deterministic_original_evidence",
  totalReportedCostUsd: samples.reduce(
    (sum, s) => sum + (s.usage?.costUsd ?? 0),
    0,
  ),
  samples,
};
await mkdir(dirname(resolve(process.argv[3])), { recursive: true });
await writeFile(
  resolve(process.argv[3]),
  JSON.stringify(summary, null, 2) + "\n",
  { mode: 0o600 },
);
console.log(
  JSON.stringify({
    outcome: summary.outcome,
    samples: samples.length,
    totalReportedCostUsd: summary.totalReportedCostUsd,
  }),
);
if (summary.outcome !== "passed") process.exitCode = 1;
