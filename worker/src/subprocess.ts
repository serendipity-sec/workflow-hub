import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { identityOf, limits } from "./contract.js";
import type { Identity, Result } from "./contract.js";
import {
  checkActive,
  parseJson,
  validateResult,
  WorkerFailure,
} from "./worker-io.js";

const analyzerEntry = new URL("./analyzer.js", import.meta.url);

export async function runLocalChild(
  bytes: Buffer,
  identity: Identity,
  signal?: AbortSignal,
  entry = analyzerEntry,
): Promise<Result> {
  checkActive(signal);
  const child = spawn(
    process.execPath,
    [
      "--permission",
      `--allow-fs-read=${fileURLToPath(new URL(".", entry))}`,
      `--allow-fs-read=${fileURLToPath(new URL("../package.json", import.meta.url))}`,
      `--allow-fs-read=${fileURLToPath(new URL("../node_modules/zod/", import.meta.url))}`,
      `--max-old-space-size=${limits.subprocessHeapMiB}`,
      fileURLToPath(entry),
    ],
    {
      env: {},
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );

  const output = await new Promise<Buffer>((resolve, reject) => {
    let firstFailure: WorkerFailure | undefined;
    let total = 0;
    const stdout: Buffer[] = [];

    function terminate(
      code:
        | "cancelled"
        | "analyzer_timeout"
        | "analyzer_output_limit"
        | "analyzer_exit",
    ): void {
      if (firstFailure) return;
      firstFailure = new WorkerFailure(code);
      child.kill("SIGKILL");
    }

    function consume(chunk: Buffer, retain: boolean): void {
      if (firstFailure) return;
      total += chunk.length;
      if (total > limits.resultBytes) terminate("analyzer_output_limit");
      else if (retain) stdout.push(chunk);
    }

    const onAbort = () => terminate("cancelled");
    const timer = setTimeout(
      () => terminate("analyzer_timeout"),
      limits.analysisTimeoutMs,
    );
    child.stdout.on("data", (chunk: Buffer) => consume(chunk, true));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, false));
    child.on("error", () => terminate("analyzer_exit"));
    child.stdin.on("error", () => terminate("analyzer_exit"));
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      if (firstFailure) reject(firstFailure);
      else if (code !== 0) reject(new WorkerFailure("analyzer_exit"));
      else resolve(Buffer.concat(stdout));
    });

    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    child.stdin.end(
      Buffer.concat([
        Buffer.from(JSON.stringify(identityOf(identity)) + "\n"),
        bytes,
      ]),
    );
  });

  checkActive(signal);
  try {
    return validateResult(parseJson(output), identity);
  } catch {
    throw new WorkerFailure("invalid_result");
  }
}
