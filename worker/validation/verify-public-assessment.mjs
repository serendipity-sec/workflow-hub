import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, readdir, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { runAssessment } from "../dist/runtime/assessment-runner.js";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { newOutputPath } from "./output-files.mjs";

assert.ok(
  process.argv[2],
  "Usage: node validation/verify-public-assessment.mjs <download-dir> [summary-path]",
);
const directory = await realpath(resolve(process.argv[2]));

const dockerExecutable = process.env.WORKER_DOCKER_PATH;
const image = process.env.WORKER_ASSESSMENT_IMAGE;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const manifestBytes = await readFile(join(directory, "downloads.json"));
assert.ok(manifestBytes.length <= 128 * 1024);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
assert.ok(
  Array.isArray(manifest.samples) &&
    manifest.samples.length > 0 &&
    manifest.samples.length <= 30,
  "A nonempty collected sample set is required",
);
assert.ok(
  !manifest.failures?.length,
  "Collection failures must not disappear from the validation denominator",
);
assert.equal(
  new Set(manifest.samples.map((sample) => sample.id)).size,
  manifest.samples.length,
);
const outputPath = await newOutputPath(
  process.argv[3] ?? "evidence-local/public-assessment-results.json",
  [directory],
);
assert.ok(dockerExecutable && isAbsolute(dockerExecutable));
assert.match(image ?? "", /^sha256:[a-f0-9]{64}$/);
const artifactHashes = {};
for (const name of (
  await readdir(new URL("../dist/", import.meta.url), { recursive: true })
)
  .map((name) => name.replaceAll("\\", "/"))
  .filter((name) => name.endsWith(".js"))
  .sort())
  artifactHashes[`dist/${name}`] = hash(
    await readFile(new URL(`../dist/${name}`, import.meta.url)),
  );
artifactHashes["package-lock.json"] = hash(
  await readFile(new URL("../package-lock.json", import.meta.url)),
);
const runtimeReceipt = JSON.parse(
  await readFile(
    resolve(
      process.env.WORKER_ASSESSMENT_RUNTIME_RECEIPT ??
        "validation/assessment-runtime-results.json",
    ),
    "utf8",
  ),
);
assert.equal(runtimeReceipt.outcome, "passed");
assert.equal(
  image,
  runtimeReceipt.image,
  "First verify the selected image with verify-assessment-runtime.mjs",
);
const expectedImageArtifacts = Object.fromEntries(
  Object.entries(runtimeReceipt.isolationProbe.artifactHashes).filter(
    ([path]) => path.startsWith("dist/") || path === "package-lock.json",
  ),
);
assert.deepEqual(
  artifactHashes,
  expectedImageArtifacts,
  "Current runtime differs from the image verified by the isolation receipt",
);
const results = [];
for (const sample of manifest.samples) {
  assert.ok(Number.isSafeInteger(sample.id) && sample.id > 0);
  assert.equal(
    sample.source,
    `https://api.n8n.io/templates/workflows/${sample.id}`,
  );
  assert.match(sample.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(sample.bytes) && sample.bytes > 0);
  const inputPath = await realpath(
    join(directory, `${sample.id}.workflow.json`),
  );
  assert.equal(dirname(inputPath), directory);
  const bytes = await readFile(inputPath);
  assert.equal(bytes.length, sample.bytes);
  assert.equal(hash(bytes), sample.sha256);
  const startedAt = performance.now();
  const report = assessmentReportSchema.parse(
    await runAssessment(bytes, undefined, { dockerExecutable, image }),
  );
  assert.equal(report.inputSha256, sample.sha256);
  assert.equal(report.execution, "not_run");
  const reportBytes = Buffer.from(JSON.stringify(report, null, 2) + "\n");
  await writeFile(
    join(directory, `${sample.id}.assessment.json`),
    reportBytes,
    { mode: 0o600, flag: "wx" },
  );
  const entry = {
    id: sample.id,
    sourceUrl: sample.source,
    inputSha256: sample.sha256,
    assessmentSha256: hash(reportBytes),
    sourceBytes: bytes.length,
    acquisition: sample.acquisition,
    responseSha256: sample.responseSha256 ?? null,
    originalRedistributed: false,
    license: "not_verified",
    status: report.status,
    engineVersion: report.engineVersion,
    elapsedMs: Math.round(performance.now() - startedAt),
    decision: report.status === "error" ? "inconclusive" : report.decision,
    categories: [],
    tools: [],
    automaticPlans: 0,
    manualPlans: 0,
  };
  if (report.status === "error") entry.errorCode = report.code;
  else {
    const rules = report.files.flatMap((file) => [
      ...(file.base.status === "error" ? [] : file.base.rules),
      ...file.extensionRules,
    ]);
    for (const category of [
      ...new Set(rules.map((rule) => rule.category)),
    ].sort()) {
      const selected = rules.filter((rule) => rule.category === category);
      const findings = selected.flatMap((rule) => rule.findings);
      const coverage = selected.flatMap((rule) => rule.coverage);
      entry.categories.push({
        category,
        observations: findings.length,
        claims: Object.fromEntries(
          ["configuration", "candidate", "supported_path"].map((claim) => [
            claim,
            findings.filter((finding) => finding.claim === claim).length,
          ]),
        ),
        severity: Object.fromEntries(
          ["info", "low", "medium", "high"].map((severity) => [
            severity,
            findings.filter((finding) => finding.severity === severity).length,
          ]),
        ),
        coverage: Object.fromEntries(
          ["checked", "partial", "unsupported", "not_applicable"].map(
            (status) => [
              status,
              coverage.filter((item) => item.status === status).length,
            ],
          ),
        ),
        evidenceCodes: [
          ...new Set(
            findings.flatMap((finding) =>
              finding.evidence.map((item) => item.code),
            ),
          ),
        ].sort(),
        diagnosticCodes: [
          ...new Set(
            selected.flatMap((rule) =>
              rule.diagnostics.map((item) => item.code),
            ),
          ),
        ].sort(),
      });
    }
    entry.tools = report.files.flatMap((file) => [
      {
        tool: "gitleaks",
        status: file.tools.gitleaks.status,
        version: file.tools.gitleaks.version,
        code: file.tools.gitleaks.reason ?? null,
      },
      ...file.tools.native.modes.map((mode) => ({
        tool: mode.mode,
        status: mode.status,
        versions: mode.versions,
      })),
    ]);
    const plans = report.files.flatMap((file) => file.remediation);
    entry.automaticPlans = plans.filter((plan) => plan.automatic).length;
    entry.manualPlans = plans.filter((plan) => !plan.automatic).length;
    entry.automaticKinds = [
      ...new Set(
        plans.filter((plan) => plan.automatic).map((plan) => plan.kind),
      ),
    ];
  }
  results.push(entry);
  process.stdout.write(
    JSON.stringify({
      id: entry.id,
      status: entry.status,
      error: entry.errorCode ?? null,
      observations: entry.categories.reduce(
        (sum, item) => sum + item.observations,
        0,
      ),
      auto: entry.automaticPlans,
      ms: entry.elapsedMs,
    }) + "\n",
  );
}
for (const [path, digest] of Object.entries(artifactHashes))
  assert.equal(
    hash(await readFile(new URL(`../${path}`, import.meta.url))),
    digest,
    "Runtime artifacts changed during collection",
  );
const output = {
  schemaVersion: "1.0.0",
  generatedAt: new Date().toISOString(),
  engineVersion: [
    ...new Set(results.map((result) => result.engineVersion)),
  ].join(","),
  image,
  workflowExecution: "not_run",
  datasetKind: "purposive_public_compatibility_and_service_fit_sample",
  generalAccuracy: "not_measured",
  manifestSha256: hash(manifestBytes),
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
  artifacts: Object.entries(artifactHashes).map(([path, sha256]) => ({
    path,
    sha256,
  })),
  summary: {
    samples: results.length,
    statuses: Object.fromEntries(
      ["analyzed", "partial", "unsupported", "error"].map((status) => [
        status,
        results.filter((result) => result.status === status).length,
      ]),
    ),
    toolErrors: results
      .flatMap((result) => result.tools)
      .filter((tool) => tool.status !== "completed").length,
    toolInvocations: results.flatMap((result) => result.tools).length,
    filesRejectedBeforeToolInspection: results.filter(
      (result) =>
        result.status === "error" && result.errorCode === "invalid_input",
    ).length,
    otherAssessmentFailures: results.filter(
      (result) =>
        result.status === "error" && result.errorCode !== "invalid_input",
    ).length,
    toolInvocationCountBasis:
      "returned_per_file_statuses_excludes_unavailable_reports",
    automaticPlans: results.reduce(
      (sum, result) => sum + result.automaticPlans,
      0,
    ),
  },
  results,
};
await writeFile(outputPath, JSON.stringify(output, null, 2) + "\n", {
  flag: "wx",
});
process.stdout.write(JSON.stringify(output.summary) + "\n");
