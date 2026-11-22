import type { WorkerApiClient, Submission } from "./api-client.js";
import {
  errorCodes,
  identityOf,
  limits,
  resultVersions,
  taskSchema,
} from "./contract.js";
import type { ErrorCode, Identity, Result, Task } from "./contract.js";
import { runLocalChild } from "./subprocess.js";
import {
  checkActive,
  readLocalFile,
  sha256,
  validateResult,
  WorkerFailure,
} from "./worker-io.js";

type LaunchControls = {
  limits: typeof limits;
  signal?: AbortSignal;
};

type Analyzer = (
  bytes: Buffer,
  identity: Identity,
  controls: LaunchControls,
) => Promise<Result>;

const localLauncher: Analyzer = (bytes, identity, { signal }) =>
  runLocalChild(bytes, identity, signal);

function resultError(identity: Identity, code: ErrorCode): Result {
  return { ...identity, ...resultVersions, status: "error", code };
}

function knownFailure(error: unknown, fallback: ErrorCode): ErrorCode {
  return error instanceof WorkerFailure
    ? (errorCodes.find((code) => code === error.code) ?? fallback)
    : fallback;
}

function guardMockAnalyzer(launch: Analyzer): Analyzer {
  return async (bytes, identity, controls) => {
    const { signal } = controls;
    if (!signal) return launch(bytes, identity, controls);
    checkActive(signal);
    let cancel: () => void = () => undefined;
    const interrupted = new Promise<never>((_, reject) => {
      cancel = () => reject(new WorkerFailure("cancelled"));
      signal.addEventListener("abort", cancel, { once: true });
    });
    try {
      const analysis = Promise.resolve().then(() =>
        launch(bytes, identity, controls),
      );
      return await Promise.race([analysis, interrupted]);
    } finally {
      signal.removeEventListener("abort", cancel);
    }
  };
}

async function execute(
  task: Task,
  fetchBytes: () => Promise<Buffer>,
  analyze: Analyzer,
  signal?: AbortSignal,
): Promise<Result> {
  const identity = identityOf(task);
  const leaseEnd = Date.parse(task.leaseExpiresAt);
  checkActive(signal, leaseEnd);

  let bytes: Buffer;
  try {
    bytes = await fetchBytes();
  } catch (error) {
    checkActive(signal, leaseEnd);
    return resultError(identity, knownFailure(error, "file_access"));
  }
  checkActive(signal, leaseEnd);
  if (sha256(bytes) !== identity.inputSha256)
    return resultError(identity, "hash_mismatch");

  const budgetMs = Math.max(
    1,
    Math.min(limits.analysisTimeoutMs, leaseEnd - Date.now()),
  );
  const started = performance.now();
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), budgetMs);
  const analysisSignal = signal
    ? AbortSignal.any([deadline.signal, signal])
    : deadline.signal;
  const timedOut = () =>
    deadline.signal.aborted || performance.now() - started >= budgetMs;
  try {
    const output = await analyze(bytes, identity, {
      limits,
      signal: analysisSignal,
    });
    checkActive(signal, leaseEnd);
    if (timedOut()) return resultError(identity, "analyzer_timeout");
    const result = validateResult(output, identity);
    if (Buffer.byteLength(JSON.stringify(result)) > limits.resultBytes) {
      return resultError(identity, "analyzer_output_limit");
    }
    return result;
  } catch (error) {
    checkActive(signal, leaseEnd);
    if (timedOut()) return resultError(identity, "analyzer_timeout");
    return resultError(identity, knownFailure(error, "analyzer_exit"));
  } finally {
    clearTimeout(timer);
  }
}

export async function runLocal(
  value: unknown,
  signal?: AbortSignal,
): Promise<Result> {
  const task = taskSchema.safeParse(value);
  if (!task.success || task.data.file.kind !== "local")
    throw new WorkerFailure("invalid_task");
  const { path } = task.data.file;
  return execute(
    task.data,
    () => readLocalFile(path, limits.fileBytes),
    localLauncher,
    signal,
  );
}

export async function runRemoteOnce(
  api: WorkerApiClient,
  options: { analyzer?: Analyzer; signal?: AbortSignal } = {},
): Promise<{ status: "idle" } | { status: Submission; result: Result }> {
  if (!api.mockOnly) throw new WorkerFailure("isolation_unverified");
  const analyze = options.analyzer
    ? guardMockAnalyzer(options.analyzer)
    : localLauncher;

  const { signal } = options;
  const task = await api.claim(signal);
  if (!task) return { status: "idle" };
  const result = await execute(
    task,
    () => api.download(task, signal),
    analyze,
    signal,
  );
  const status = await api.submit(task, result, signal);
  return { status, result };
}
