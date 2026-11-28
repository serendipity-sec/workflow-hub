import { WorkerApiClient } from "./runtime/api-client.js";
import { runLocal, runRemoteOnce } from "./runtime/runner.js";
import { runStaticFile } from "./runtime/static-runner.js";
import { compareStatic } from "./analysis/static-compare.js";
import { compareAssessment } from "./assessment/assessment-compare.js";
import { limits } from "./contracts/contract.js";
import { staticLimits } from "./contracts/static-contract.js";
import { writeFile } from "node:fs/promises";
import {
  runAssessment,
  runAssessmentFile,
} from "./runtime/assessment-runner.js";
import {
  assessmentLimits,
  assessmentReportSchema,
} from "./contracts/assessment-contract.js";
import {
  compareDefinitions,
  applyRemediation,
} from "./assessment/assessment-change.js";
import { parseEvidenceBytes } from "./assessment/assessment-evidence.js";
import { sha256 } from "./runtime/worker-io.js";
import {
  inspectFile,
  inspectionSchema,
  presentInspection,
} from "./service/inspection.js";
import { buildCoverageExplanation } from "./service/coverage-causes.js";
import { buildServiceReport } from "./service/service-report.js";
import {
  parseTask,
  readLocalFile,
  taskBytes,
  WorkerFailure,
} from "./runtime/worker-io.js";

async function main(args: string[], signal: AbortSignal): Promise<void> {
  const assessmentOptions = {
    dockerExecutable: process.env.WORKER_DOCKER_PATH,
    image: process.env.WORKER_ASSESSMENT_IMAGE,
    signal,
  };
  if (
    args[0] === "coverage" &&
    (args.length === 2 || args.length === 3) &&
    args[1]
  ) {
    const report = JSON.parse(
      (await readLocalFile(args[1], assessmentLimits.resultBytes)).toString(
        "utf8",
      ),
    );
    const inspection = args[2]
      ? inspectionSchema.parse(
          JSON.parse(
            (await readLocalFile(args[2], 6 * 1024 * 1024)).toString("utf8"),
          ),
        )
      : undefined;
    const result = buildCoverageExplanation(report, inspection?.llm);
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.error || result.fileFailures || result.toolFailures)
      process.exitCode = 1;
    return;
  }
  if (
    args[0] === "inspect" &&
    args.length >= 2 &&
    args.length <= 4 &&
    args[1]
  ) {
    const llm = args.at(-1) === "--llm";
    const positional = llm ? args.slice(1, -1) : args.slice(1);
    if (
      positional.length < 1 ||
      positional.length > 2 ||
      positional.some((arg) => arg.startsWith("--"))
    )
      throw new WorkerFailure("invalid_configuration");
    const result = await inspectFile(positional[0]!, {
      ...assessmentOptions,
      evidencePath: positional[1],
      llm: {
        enabled: llm,
        apiKey: process.env.OPENROUTER_API_KEY,
        model: process.env.WORKER_LLM_MODEL,
        maxOutputTokens:
          process.env.WORKER_LLM_MAX_OUTPUT_TOKENS === undefined
            ? undefined
            : Number(process.env.WORKER_LLM_MAX_OUTPUT_TOKENS),
      },
    });
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.serviceReport.executionStatus !== "completed")
      process.exitCode = 1;
    return;
  }
  if (
    (args[0] === "present" || args[0] === "explain") &&
    args.length === 2 &&
    args[1]
  ) {
    const report = JSON.parse(
      (await readLocalFile(args[1], assessmentLimits.resultBytes)).toString(
        "utf8",
      ),
    );
    const result = await presentInspection(report, {
      enabled: args[0] === "explain",
      apiKey: process.env.OPENROUTER_API_KEY,
      model: process.env.WORKER_LLM_MODEL,
      maxOutputTokens:
        process.env.WORKER_LLM_MAX_OUTPUT_TOKENS === undefined
          ? undefined
          : Number(process.env.WORKER_LLM_MAX_OUTPUT_TOKENS),
      signal,
    });
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.serviceReport.executionStatus !== "completed")
      process.exitCode = 1;
    return;
  }
  if (
    args[0] === "assess" &&
    (args.length === 2 || args.length === 3) &&
    args[1]
  ) {
    const report = await runAssessmentFile(args[1], {
      ...assessmentOptions,
      evidencePath: args[2],
    });
    process.stdout.write(JSON.stringify(report) + "\n");
    if (report.status === "error") process.exitCode = 1;
    return;
  }
  if (
    args[0] === "diff-definitions" &&
    (args.length === 3 || args.length === 5) &&
    args[1] &&
    args[2]
  ) {
    const before = await readLocalFile(args[1], limits.fileBytes);
    const after = await readLocalFile(args[2], limits.fileBytes);
    const beforeEvidence = args[3]
      ? parseEvidenceBytes(
          await readLocalFile(args[3], 1024 * 1024),
          sha256(before),
        )
      : undefined;
    const afterEvidence = args[4]
      ? parseEvidenceBytes(
          await readLocalFile(args[4], 1024 * 1024),
          sha256(after),
        )
      : undefined;
    const comparison = compareDefinitions(
      before,
      after,
      beforeEvidence,
      afterEvidence,
    );
    process.stdout.write(JSON.stringify(comparison) + "\n");
    if (comparison.status === "inconclusive") process.exitCode = 1;
    return;
  }
  if (
    args[0] === "apply-remediation" &&
    args.length === 5 &&
    args[1] &&
    args[2] &&
    args[3] &&
    args[4]
  ) {
    const bytes = await readLocalFile(args[1], limits.fileBytes);
    const report = assessmentReportSchema.parse(
      JSON.parse(
        (await readLocalFile(args[2], assessmentLimits.resultBytes)).toString(
          "utf8",
        ),
      ),
    );
    if (report.status === "error" || report.inputSha256 !== sha256(bytes))
      throw new WorkerFailure("invalid_result");
    const plan = report.files[0]?.remediation.find(
      (plan) => plan.id === args[3],
    );
    if (!plan) throw new WorkerFailure("invalid_result");
    const revised = applyRemediation(bytes, plan);
    // Changed bytes invalidate earlier evidence. Do not silently carry policy approvals forward.
    const recheck = await runAssessment(revised, undefined, assessmentOptions);
    if (recheck.status === "error") {
      process.stdout.write(JSON.stringify(recheck) + "\n");
      process.exitCode = 1;
      return;
    }
    await writeFile(args[4], revised, { flag: "wx", mode: 0o600 });
    process.stdout.write(
      JSON.stringify({
        status: "revised_file_created",
        beforeSha256: sha256(bytes),
        afterSha256: sha256(revised),
        originalModified: false,
        behaviorPreserved: "not_verified",
        comparison: compareAssessment(report, recheck),
        definitionChanges: compareDefinitions(bytes, revised),
        recheck,
        serviceReport: buildServiceReport(recheck),
      }) + "\n",
    );
    return;
  }
  if (
    args[0] === "compare-assessment" &&
    args.length === 3 &&
    args[1] &&
    args[2]
  ) {
    const before = JSON.parse(
      (await readLocalFile(args[1], assessmentLimits.resultBytes)).toString(
        "utf8",
      ),
    );
    const after = JSON.parse(
      (await readLocalFile(args[2], assessmentLimits.resultBytes)).toString(
        "utf8",
      ),
    );
    const comparison = compareAssessment(before, after);
    process.stdout.write(JSON.stringify(comparison) + "\n");
    if (comparison.basis === "incompatible_or_failed") process.exitCode = 1;
    return;
  }
  if (args[0] === "compare-static" && args.length === 3 && args[1] && args[2]) {
    const before = JSON.parse(
      (await readLocalFile(args[1], staticLimits.resultBytes)).toString("utf8"),
    );
    const after = JSON.parse(
      (await readLocalFile(args[2], staticLimits.resultBytes)).toString("utf8"),
    );
    const comparison = compareStatic(before, after);
    process.stdout.write(JSON.stringify(comparison) + "\n");
    if (comparison.basis === "incompatible_or_failed") process.exitCode = 1;
    return;
  }

  if (args[0] === "scan" && args.length === 2 && args[1]) {
    const report = await runStaticFile(args[1], {
      executable: process.env.WORKER_GITLEAKS_PATH,
      signal,
    });
    process.stdout.write(JSON.stringify(report) + "\n");
    if (report.status === "error") process.exitCode = 1;
    return;
  }

  if (args[0] === "local" && args.length === 2 && args[1]) {
    const task = parseTask(await readLocalFile(args[1], taskBytes));
    const result = await runLocal(task, signal);
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.status === "error") process.exitCode = 1;
    return;
  }

  if (args[0] === "mock-once" && args.length === 1) {
    const api = new WorkerApiClient({
      mode: "mock",
      apiOrigin: process.env.WORKER_API_ORIGIN ?? "",
      fileOrigin: process.env.WORKER_FILE_ORIGIN ?? "",
      token: process.env.WORKER_API_TOKEN ?? "",
    });
    const outcome = await runRemoteOnce(api, { signal });
    process.stdout.write(JSON.stringify(outcome) + "\n");
    if (outcome.status !== "idle" && outcome.result.status === "error")
      process.exitCode = 1;
    return;
  }

  throw new WorkerFailure("invalid_configuration");
}

const abort = new AbortController();
const cancel = () => abort.abort();
process.on("SIGINT", cancel);
process.on("SIGTERM", cancel);
try {
  await main(process.argv.slice(2), abort.signal);
} catch (error) {
  const code = error instanceof WorkerFailure ? error.code : "worker_error";
  process.stderr.write(JSON.stringify({ status: "error", code }) + "\n");
  process.exitCode = code === "cancelled" ? 130 : 1;
} finally {
  process.off("SIGINT", cancel);
  process.off("SIGTERM", cancel);
}
