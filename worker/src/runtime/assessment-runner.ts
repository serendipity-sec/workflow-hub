import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import { limits } from "../contracts/contract.js";
import { readLocalFile, sha256 } from "./worker-io.js";
import {
  assessmentError,
  assessmentLimits,
  assessmentReportSchema,
} from "../contracts/assessment-contract.js";
import type {
  AssessmentBoundary,
  AssessmentFailureCode,
  AssessmentReport,
} from "../contracts/assessment-contract.js";

export interface AssessmentRunOptions {
  dockerExecutable?: string;
  image?: string;
  evidencePath?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
}
export function sandboxArguments(image: string, name: string): string[] {
  if (
    !/^sha256:[a-f0-9]{64}$/.test(image) ||
    !/^worker-assess-[a-f0-9-]{36}$/.test(name)
  )
    throw new Error("invalid_configuration");
  return [
    "run",
    "--rm",
    "--interactive",
    "--pull=never",
    "--name",
    name,
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user=65532:65532",
    "--memory=1g",
    "--memory-swap=1g",
    "--pids-limit=96",
    "--cpus=1",
    "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
    image,
  ];
}
function dockerEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of [
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
  ])
    if (process.env[name]) environment[name] = process.env[name];
  return environment;
}
async function createContainer(
  executable: string,
  image: string,
  name: string,
): Promise<"created" | "failed" | "uncertain"> {
  const args = sandboxArguments(image, name);
  args[0] = "create";
  return new Promise((resolve) => {
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      env: dockerEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    let uncertain = false;
    // Let the daemon acknowledge creation before acting on caller cancellation.
    // A killed `docker run` can finish creating a container after an early rm.
    const timer = setTimeout(() => {
      uncertain = true;
      child.kill("SIGKILL");
    }, 10_000);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 8192) {
        uncertain = true;
        child.kill("SIGKILL");
      } else chunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 8192) {
        uncertain = true;
        child.kill("SIGKILL");
      }
    });
    child.on("error", () => {
      /* close follows; no raw daemon messages escape */
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(
        uncertain
          ? "uncertain"
          : code === 0 &&
              /^[a-f0-9]{64}$/.test(
                Buffer.concat(chunks).toString("utf8").trim(),
              )
            ? "created"
            : "failed",
      );
    });
  });
}
async function cleanup(executable: string, name: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn(executable, ["rm", "--force", name], {
      shell: false,
      windowsHide: true,
      env: dockerEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    let failed = false;
    const timer = setTimeout(() => {
      failed = true;
      child.kill("SIGKILL");
    }, 10_000);
    const consume = (chunk: Buffer) => {
      size += chunk.length;
      if (size > 8192) {
        failed = true;
        child.kill("SIGKILL");
      } else chunks.push(chunk);
    };
    child.stdout.on("data", consume);
    child.stderr.on("data", consume);
    child.on("error", () => {
      failed = true;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const output = Buffer.concat(chunks).toString("utf8").trim();
      resolve(
        !failed &&
          (code === 0 ||
            (code === 1 &&
              output ===
                `Error response from daemon: No such container: ${name}`)),
      );
    });
  });
}

/** Fixed immutable image and fixed Docker flags. No host mounts, workflow URLs or configurable commands. */
export async function runAssessment(
  bytes: Buffer,
  evidence: Buffer | undefined,
  options: AssessmentRunOptions,
): Promise<AssessmentReport> {
  const inputSha256 = sha256(bytes);
  const executable = options.dockerExecutable;
  const image = options.image;
  if (
    !executable ||
    !isAbsolute(executable) ||
    !image ||
    !/^sha256:[a-f0-9]{64}$/.test(image)
  )
    return assessmentError(inputSha256, "invalid_configuration");
  if (bytes.length > limits.fileBytes || (evidence?.length ?? 0) > 1024 * 1024)
    return assessmentError(inputSha256, "invalid_input");
  if (options.signal?.aborted) return assessmentError(inputSha256, "cancelled");
  const timeout = options.timeoutMs ?? assessmentLimits.timeoutMs;
  if (
    !Number.isInteger(timeout) ||
    timeout < 1 ||
    timeout > assessmentLimits.timeoutMs
  )
    return assessmentError(inputSha256, "invalid_configuration");
  const name = `worker-assess-${randomUUID()}`;
  const startedAt = performance.now();
  const created = await createContainer(executable, image, name);
  const remaining = timeout - (performance.now() - startedAt);
  if (created !== "created" || options.signal?.aborted || remaining <= 0) {
    const cleaned = await cleanup(executable, name);
    // A daemon request killed before its acknowledgement may still create a
    // stopped container later. Never claim cleanup succeeded in that case.
    if (!cleaned || created === "uncertain")
      return assessmentError(inputSha256, "sandbox_cleanup_failed");
    return assessmentError(
      inputSha256,
      options.signal?.aborted
        ? "cancelled"
        : remaining <= 0
          ? "assessment_timeout"
          : "sandbox_unavailable",
    );
  }
  const boundary: AssessmentBoundary = {
    kind: "docker",
    isolationVerified: true,
    imageSha256: image.slice(7),
    network: "none",
    readOnlyRoot: true,
    uid: 65532,
    memoryMiB: 1024,
    pids: 96,
    cpus: 1,
  };
  const payload = JSON.stringify({
    workflow: bytes.toString("base64"),
    ...(evidence ? { evidence: evidence.toString("base64") } : {}),
  });
  return new Promise((resolve) => {
    const child = spawn(
      executable,
      ["start", "--attach", "--interactive", name],
      {
        env: dockerEnvironment(),
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let failure: AssessmentFailureCode | undefined;
    let size = 0;
    const chunks: Buffer[] = [];
    function stop(code: AssessmentFailureCode) {
      failure ??= code;
      child.kill("SIGKILL");
    }
    const timer = setTimeout(() => stop("assessment_timeout"), remaining);
    const abort = () => stop("cancelled");
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();
    const consume = (chunk: Buffer, keep: boolean) => {
      size += chunk.length;
      if (size > assessmentLimits.resultBytes) stop("assessment_output_limit");
      else if (keep && !failure) chunks.push(chunk);
    };
    child.stdout.on("data", (chunk: Buffer) => consume(chunk, true));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, false));
    child.on("error", () => stop("sandbox_unavailable"));
    child.stdin.on("error", () => stop("sandbox_failed"));
    child.on("close", (code) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      void (async () => {
        // Killing a Docker CLI alone does NOT stop its daemon-managed container.
        // Also covers normal exit: --rm must have removed it, or rm removes it now.
        const cleaned = await cleanup(executable, name);
        if (!cleaned) {
          resolve(assessmentError(inputSha256, "sandbox_cleanup_failed"));
          return;
        }
        if (failure || code !== 0) {
          resolve(assessmentError(inputSha256, failure ?? "sandbox_failed"));
          return;
        }
        try {
          const report = assessmentReportSchema.parse(
            JSON.parse(Buffer.concat(chunks).toString("utf8")),
          );
          if (
            report.inputSha256 !== inputSha256 ||
            report.boundary.kind !== "caller_managed"
          )
            throw new Error("invalid_result");
          resolve(assessmentReportSchema.parse({ ...report, boundary }));
        } catch {
          resolve(assessmentError(inputSha256, "invalid_result", boundary));
        }
      })().catch(() =>
        resolve(assessmentError(inputSha256, "sandbox_cleanup_failed")),
      );
    });
    child.stdin.end(payload);
  });
}
export async function runAssessmentFile(
  path: string,
  options: AssessmentRunOptions,
): Promise<AssessmentReport> {
  const bytes = await readLocalFile(path, limits.fileBytes);
  const evidence = options.evidencePath
    ? await readLocalFile(options.evidencePath, 1024 * 1024)
    : undefined;
  return runAssessment(bytes, evidence, options);
}
