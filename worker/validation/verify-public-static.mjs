import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { limits } from "../dist/contract.js";
import { runGitleaks, gitleaksVersion } from "../dist/gitleaks.js";
import {
  categories,
  staticReportSchema,
  staticResultVersions,
} from "../dist/static-contract.js";
import { runStaticFile } from "../dist/static-runner.js";
import { readLocalFile } from "../dist/worker-io.js";

const executable = process.env.WORKER_GITLEAKS_PATH;
assert.ok(
  executable && isAbsolute(executable),
  "Set WORKER_GITLEAKS_PATH to a trusted absolute Gitleaks 8.30.1 path",
);
assert.ok(
  process.argv[2],
  "Usage: node validation/verify-public-static.mjs <download directory> [report path]",
);
const directory = await realpath(resolve(process.argv[2]));
const hash = (value) => createHash("sha256").update(value).digest("hex");
async function runtimeHashes() {
  const runtimeDirectory = new URL("../dist/", import.meta.url);
  const hashes = {};
  for (const name of (await readdir(runtimeDirectory))
    .filter((name) => name.endsWith(".js"))
    .sort())
    hashes[`dist/${name}`] = hash(
      await readFile(new URL(name, runtimeDirectory)),
    );
  return hashes;
}
const runtimeModuleSha256 = await runtimeHashes();
const manifestBytes = await readLocalFile(
  join(directory, "downloads.json"),
  65536,
);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
assert.ok(Array.isArray(manifest.samples));
assert.ok(manifest.samples.length > 0 && manifest.samples.length <= 100);
const seen = new Set();
for (const sample of manifest.samples) {
  assert.ok(Number.isSafeInteger(sample.id) && sample.id > 0);
  assert.ok(!seen.has(sample.id), "Duplicate public template id");
  seen.add(sample.id);
  assert.match(sample.sha256, /^[a-f0-9]{64}$/);
  assert.ok(Number.isSafeInteger(sample.bytes) && sample.bytes > 0);
  assert.equal(
    sample.source,
    `https://api.n8n.io/templates/workflows/${sample.id}`,
    "Only declared official n8n template sources are recorded",
  );
}

// A real, version-checked invocation must succeed; missing tools never mean clean.
const probe = await runGitleaks([], { executable });
assert.equal(probe.status, "completed", probe.reason);
assert.deepEqual(probe.findings, []);
const results = [];
for (const sample of manifest.samples) {
  // Process originals named only by numeric id, never modified/task/result files.
  const path = await realpath(join(directory, `${sample.id}.workflow.json`));
  assert.equal(
    dirname(path),
    directory,
    "Template must remain in the dataset directory",
  );
  const bytes = await readLocalFile(path, limits.fileBytes);
  assert.equal(
    hash(bytes),
    sample.sha256,
    `Template ${sample.id}: hash mismatch`,
  );
  assert.equal(
    bytes.length,
    sample.bytes,
    `Template ${sample.id}: byte mismatch`,
  );
  const report = staticReportSchema.parse(
    await runStaticFile(path, { executable }),
  );
  // runStaticFile reads independently: verify it scanned the exact hashed bytes.
  assert.equal(report.inputSha256, sample.sha256);
  assert.equal(report.execution, "not_run");
  const entry = {
    id: sample.id,
    sourceUrl: sample.source,
    inputSha256: sample.sha256,
    bytes: bytes.length,
    reportStatus: report.status,
    execution: report.execution,
    categories: [],
  };
  if (report.status === "error") {
    entry.errorCode = report.code;
  } else {
    assert.deepEqual(
      [...new Set(report.rules.map((rule) => rule.category))].sort(),
      [...categories].sort(),
    );
    entry.categories = categories.map((category) => {
      const rules = report.rules.filter((rule) => rule.category === category);
      const diagnostics = rules.flatMap((rule) => rule.diagnostics);
      const counts = Object.fromEntries(
        ["checked", "partial", "unsupported", "not_applicable"].map(
          (status) => [status, 0],
        ),
      );
      for (const coverage of rules.flatMap((rule) => rule.coverage))
        counts[coverage.status]++;
      return {
        category,
        ruleCount: rules.length,
        findingCount: rules.reduce(
          (total, rule) => total + rule.findings.length,
          0,
        ),
        diagnosticCount: diagnostics.length,
        diagnosticCodes: Object.fromEntries(
          [...new Set(diagnostics.map(({ code }) => code))]
            .sort()
            .map((code) => [
              code,
              diagnostics.filter((diagnostic) => diagnostic.code === code)
                .length,
            ]),
        ),
        coverageCounts: counts,
      };
    });
  }
  results.push(entry);
}

assert.deepEqual(
  await runtimeHashes(),
  runtimeModuleSha256,
  "Compiled worker modules changed during validation; rebuild and rerun",
);
const failures = results.filter(
  (result) =>
    result.reportStatus === "error" ||
    result.categories.some((category) =>
      Object.keys(category.diagnosticCodes).some((code) =>
        code.startsWith("tool_"),
      ),
    ),
);
const output = resolve(
  process.argv[3] ?? "evidence-local/public-static-results.json",
);
await mkdir(dirname(output), { recursive: true });
await writeFile(
  output,
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      scope: "public_template_static_compatibility_only",
      groundTruthAccuracyEvaluated: false,
      workflowExecution: "not_run",
      nodeVersion: process.version,
      platform: process.platform,
      ...staticResultVersions,
      gitleaksVersion,
      gitleaksBinarySha256: hash(await readFile(executable)),
      manifestSha256: hash(manifestBytes),
      runtimeModuleSha256,
      packageLockSha256: hash(
        await readFile(new URL("../package-lock.json", import.meta.url)),
      ),
      verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
      command:
        "WORKER_GITLEAKS_PATH=<trusted path> node validation/verify-public-static.mjs <download directory> [report path]",
      samples: results.length,
      completed: results.length - failures.length,
      failures: failures.map(({ id }) => id),
      results,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  JSON.stringify({
    samples: results.length,
    completed: results.length - failures.length,
    failures: failures.map(({ id, reportStatus, errorCode }) => ({
      id,
      reportStatus,
      errorCode,
    })),
    categoriesPerSample: categories.length,
    execution: "not_run",
  }),
);
if (failures.length) process.exitCode = 1;
