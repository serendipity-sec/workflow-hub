import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { runAssessment } from "../dist/assessment-runner.js";
import { compareDefinitions } from "../dist/assessment-change.js";
import { compareStatic } from "../dist/static-compare.js";
import { compareAssessment } from "../dist/assessment-compare.js";
import { assessmentReportSchema } from "../dist/assessment-contract.js";

assert.ok(
  process.argv[2],
  "Usage: node validation/verify-public-service-paths.mjs <frozen-download-dir> [result-path]",
);
const directory = resolve(process.argv[2]);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const options = {
  dockerExecutable: process.env.WORKER_DOCKER_PATH,
  image: process.env.WORKER_ASSESSMENT_IMAGE,
};
const manifest = JSON.parse(
  await readFile(join(directory, "downloads.json"), "utf8"),
);
const publicReceipt = JSON.parse(
  await readFile(
    process.env.WORKER_PUBLIC_ASSESSMENT_RECEIPT ??
      new URL("./public-assessment-results.json", import.meta.url),
    "utf8",
  ),
);
assert.equal(
  options.image,
  publicReceipt.image,
  "Comparison must use the same measured image as the original reports",
);
for (const artifact of publicReceipt.artifacts)
  assert.equal(
    hash(await readFile(new URL(`../${artifact.path}`, import.meta.url))),
    artifact.sha256,
    "Current runtime differs from original assessment runtime",
  );
const results = [];
const hasCode = (report, code) =>
  report.status !== "error" &&
  report.files.some((file) =>
    [
      ...(file.base.status === "error" ? [] : file.base.rules),
      ...file.extensionRules,
    ].some((rule) =>
      rule.findings.some((finding) =>
        finding.evidence.some((item) => item.code === code),
      ),
    ),
  );
async function variant(id, label, edit, check) {
  const sample = manifest.samples.find((sample) => sample.id === id);
  assert.ok(sample);
  const inputPath = join(directory, `${id}.workflow.json`);
  const beforeBytes = await readFile(inputPath);
  assert.equal(hash(beforeBytes), sample.sha256);
  const before = assessmentReportSchema.parse(
    JSON.parse(
      await readFile(join(directory, `${id}.assessment.json`), "utf8"),
    ),
  );
  assert.equal(before.inputSha256, sample.sha256);
  assert.notEqual(before.status, "error");
  assert.equal(before.boundary.kind, "docker");
  assert.equal(
    `sha256:${before.boundary.imageSha256}`,
    options.image,
    "Baseline image does not match the measured comparison image",
  );
  const modified = JSON.parse(beforeBytes.toString());
  edit(modified);
  const afterBytes = Buffer.from(JSON.stringify(modified));
  const after = assessmentReportSchema.parse(
    await runAssessment(afterBytes, undefined, options),
  );
  assert.notEqual(after.status, "error", `${label}: ${JSON.stringify(after)}`);
  const declarations = compareDefinitions(beforeBytes, afterBytes);
  assert.equal(declarations.beforeSha256, before.inputSha256);
  assert.equal(declarations.afterSha256, after.inputSha256);
  const findingComparison = compareStatic(
    before.files[0].base,
    after.files[0].base,
  );
  const assessmentComparison = compareAssessment(before, after);
  assert.equal(assessmentComparison.basis, "same_assessment_contract");
  assert.equal(assessmentComparison.scope, "all_reported_static_findings");
  const findingCount = (report) =>
    report.files.reduce(
      (count, file) =>
        count +
        [
          ...(file.base.status === "error" ? [] : file.base.rules),
          ...file.extensionRules,
        ].reduce((total, rule) => total + rule.findings.length, 0),
      0,
    );
  assert.equal(
    assessmentComparison.counts.beforeFindings,
    findingCount(before),
  );
  assert.equal(assessmentComparison.counts.afterFindings, findingCount(after));
  const extra = check(before, after, declarations, findingComparison);
  await writeFile(join(directory, `${id}.${label}.workflow.json`), afterBytes, {
    mode: 0o600,
  });
  await writeFile(
    join(directory, `${id}.${label}.assessment.json`),
    JSON.stringify(after, null, 2) + "\n",
    { mode: 0o600 },
  );
  assert.equal(hash(await readFile(inputPath)), sample.sha256);
  const comparisonCounts = (items) =>
    Object.fromEntries(
      [...new Set(items.map((item) => item.status))]
        .sort()
        .map((status) => [
          status,
          items.filter((item) => item.status === status).length,
        ]),
    );
  results.push({
    id,
    label,
    variantKind: "controlled_edit_of_public_original",
    originalSha256: sample.sha256,
    revisedSha256: hash(afterBytes),
    originalPreserved: true,
    workflowExecution: "not_run",
    behaviorPreserved: "not_verified",
    revisedStatus: after.status,
    declarationChanges: [
      ...new Set(declarations.changes.map((change) => change.kind)),
    ],
    baseFindingComparison: {
      basis: findingComparison.basis,
      rechecks: comparisonCounts(findingComparison.rechecks),
      newFindings: comparisonCounts(findingComparison.newFindings),
    },
    assessmentFindingComparison: {
      basis: assessmentComparison.basis,
      rechecks: comparisonCounts(assessmentComparison.rechecks),
      newFindings: comparisonCounts(assessmentComparison.newFindings),
    },
    ...extra,
  });
}
await variant(
  10111,
  "authentication_config",
  (document) => {
    const webhook = document.nodes.find(
      (node) => node.type === "n8n-nodes-base.webhook",
    );
    assert.ok(
      webhook &&
        (webhook.parameters.authentication === undefined ||
          webhook.parameters.authentication === "none"),
    );
    webhook.parameters.authentication = "headerAuth";
  },
  (before, after, declarations) => {
    assert.ok(hasCode(before, "webhook_authentication_default_none"));
    assert.ok(!hasCode(after, "webhook_authentication_none"));
    assert.ok(!hasCode(after, "webhook_authentication_default_none"));
    assert.ok(hasCode(after, "webhook_authentication_configured"));
    assert.ok(
      declarations.changes.some(
        (change) => change.kind === "authentication_changed",
      ),
    );
    return {
      observed: "authentication_declaration_changed_and_rechecked",
      runtimeAuthentication: "not_verified",
      credentialsProvided: false,
    };
  },
);
await variant(
  7643,
  "recipient_change",
  (document) => {
    const slack = document.nodes.find(
      (node) => node.type === "n8n-nodes-base.slack",
    );
    assert.ok(slack && slack.parameters.select === "user");
    slack.parameters.user = {
      __rl: true,
      mode: "id",
      value: "SYNTHETIC_REVIEW_USER",
    };
  },
  (_before, _after, declarations) => {
    assert.ok(
      declarations.changes.some(
        (change) => change.kind === "recipient_changed",
      ),
    );
    return {
      observed: "recipient_semantic_change_detected",
      recipientValueInPublicResult: false,
    };
  },
);
await variant(
  7643,
  "disable_delivery",
  (document) => {
    const slack = document.nodes.find(
      (node) => node.type === "n8n-nodes-base.slack",
    );
    assert.ok(slack);
    slack.disabled = true;
  },
  (_before, _after, declarations) => {
    assert.ok(
      declarations.changes.some((change) => change.kind === "node_disabled"),
    );
    assert.equal(declarations.behaviorPreserved, "not_verified");
    return {
      observed: "functional_removal_requires_recheck",
      securityFixClaim: "not_made",
    };
  },
);
const output = {
  schemaVersion: "1.0.0",
  generatedAt: new Date().toISOString(),
  image: options.image,
  purpose: "public_original_manual_revision_recheck_and_compare",
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
  automaticRepairOfPublicOriginals:
    publicReceipt.summary.automaticPlans === 0
      ? "none_eligible_in_sample"
      : "plans_available_not_applied_in_this_test",
  results,
  limitations: [
    "controlled_edits_are_not_naturally_observed_user_uploads",
    "no_original_or_modified_workflow_execution",
    "no_general_functional_equivalence",
    "comparison_is_observation_change_not_proof_of_security_fix",
  ],
};
const outputPath = resolve(
  process.argv[3] ?? "evidence-local/public-service-path-results.json",
);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    passed: results.length,
    originalPreserved: true,
    behaviorPreserved: "not_verified",
  }) + "\n",
);
