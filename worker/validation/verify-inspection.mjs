import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { resolve, join, dirname } from "node:path";
import { presentInspection, inspectionSchema } from "../dist/inspection.js";
import {
  createLlmContext,
  providerContext,
  llmDefaults,
} from "../dist/llm-review.js";

assert.ok(
  process.argv[2] && process.argv[3],
  "Supply summary path and one or more frozen report directories",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const samples = [];
for (const argument of process.argv.slice(3)) {
  const directory = resolve(argument);
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
    "Collection failures must not disappear from the validation denominator",
  );
  for (const sample of manifest.samples) {
    const input = await readFile(join(directory, `${sample.id}.workflow.json`));
    assert.equal(hash(input), sample.sha256);
    const report = JSON.parse(
      await readFile(join(directory, `${sample.id}.assessment.json`), "utf8"),
    );
    assert.equal(report.inputSha256, sample.sha256);
    const inspection = inspectionSchema.parse(await presentInspection(report));
    assert.deepEqual(inspection.assessment, report);
    assert.equal(inspection.llm.status, "unavailable");
    assert.equal(inspection.llm.code, "disabled");
    const encoded = Buffer.from(JSON.stringify(inspection, null, 2) + "\n");
    await writeFile(
      join(directory, `${sample.id}.inspection.offline.json`),
      encoded,
      {
        mode: 0o600,
      },
    );
    const context = createLlmContext(report);
    const payload = Buffer.from(
      JSON.stringify(
        {
          destination: llmDefaults.endpoint,
          model: llmDefaults.model,
          context: providerContext(context),
        },
        null,
        2,
      ) + "\n",
    );
    await writeFile(join(directory, `${sample.id}.llm-context.json`), payload, {
      mode: 0o600,
    });
    samples.push({
      id: sample.id,
      inputSha256: sample.sha256,
      engineVersion: report.engineVersion,
      inspectionVersion: inspection.inspectionVersion,
      serviceReportVersion: inspection.serviceReport.serviceReportVersion,
      ...(inspection.serviceReport.serviceScope
        ? { serviceScope: inspection.serviceReport.serviceScope }
        : {}),
      assessmentStatus: report.status,
      executionStatus: inspection.serviceReport.executionStatus,
      analysisStatus: inspection.serviceReport.analysisStatus,
      staticCoverageStatus: inspection.serviceReport.staticCoverageStatus,
      counts: inspection.serviceReport.counts,
      omitted: inspection.serviceReport.omitted,
      truncated: inspection.serviceReport.truncated,
      inspectionSha256: hash(encoded),
      inspectionArtifact: `${sample.id}.inspection.offline.json`,
      preparedLlmContextSha256: hash(payload),
      preparedLlmContextBytes: payload.length,
      llmTransmission: "not_run",
      verdictUnchanged: true,
    });
  }
}
const receipt = {
  schemaVersion: "1.0.0",
  outcome: "passed",
  scope: "offline_service_presentation_and_payload_preparation",
  workflowExecution: "not_run",
  modelCalls: 0,
  actualTeamApiIntegration: "not_run",
  samples,
};
await mkdir(dirname(resolve(process.argv[2])), { recursive: true });
await writeFile(
  resolve(process.argv[2]),
  JSON.stringify(receipt, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    outcome: receipt.outcome,
    samples: samples.length,
    failedScans: samples.filter((s) => s.executionStatus !== "completed")
      .length,
    modelCalls: 0,
  }),
);
