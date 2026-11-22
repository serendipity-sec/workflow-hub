import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { limits } from "./contract.js";
import { runGitleaks } from "./gitleaks.js";
import type { GitleaksOptions, GitleaksResult } from "./gitleaks.js";
import { WorkflowError } from "./n8n.js";
import { createContext } from "./static-context.js";
import { staticError } from "./static-engine.js";
import { staticReportSchema } from "./static-contract.js";
import type { StaticReport } from "./static-contract.js";
import {
  checkActive,
  readLocalFile,
  sha256,
  WorkerFailure,
} from "./worker-io.js";

export async function runStaticChild(
  bytes: Buffer,
  scanner: GitleaksResult,
  signal?: AbortSignal,
): Promise<StaticReport> {
  const inputSha256 = sha256(bytes);
  checkActive(signal);
  const header = JSON.stringify({ inputSha256, scanner }) + "\n";
  if (Buffer.byteLength(header) > limits.resultBytes)
    return staticError(inputSha256, "analyzer_output_limit");
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [
        "--permission",
        `--allow-fs-read=${fileURLToPath(new URL(".", import.meta.url))}`,
        `--allow-fs-read=${fileURLToPath(new URL("../package.json", import.meta.url))}`,
        `--allow-fs-read=${fileURLToPath(new URL("../node_modules/", import.meta.url))}`,
        `--max-old-space-size=${limits.subprocessHeapMiB}`,
        fileURLToPath(new URL("./static-analyzer.js", import.meta.url)),
      ],
      {
        env: {},
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let failure:
      | "cancelled"
      | "analyzer_timeout"
      | "analyzer_output_limit"
      | "analyzer_exit"
      | undefined;
    let total = 0;
    const chunks: Buffer[] = [];
    function stop(code: NonNullable<typeof failure>) {
      failure ??= code;
      child.kill("SIGKILL");
    }
    const abort = () => stop("cancelled");
    const timer = setTimeout(
      () => stop("analyzer_timeout"),
      limits.analysisTimeoutMs,
    );
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    const consume = (chunk: Buffer, keep: boolean) => {
      total += chunk.length;
      if (total > limits.resultBytes) stop("analyzer_output_limit");
      else if (keep && !failure) chunks.push(chunk);
    };
    child.stdout.on("data", (chunk: Buffer) => consume(chunk, true));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, false));
    child.on("error", () => stop("analyzer_exit"));
    child.stdin.on("error", () => stop("analyzer_exit"));
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (failure || code !== 0) {
        resolve(staticError(inputSha256, failure ?? "analyzer_exit"));
        return;
      }
      try {
        const result = staticReportSchema.parse(
          JSON.parse(Buffer.concat(chunks).toString("utf8")),
        );
        resolve(
          result.inputSha256 === inputSha256
            ? result
            : staticError(inputSha256, "invalid_result"),
        );
      } catch {
        resolve(staticError(inputSha256, "invalid_result"));
      }
    });
    child.stdin.end(Buffer.concat([Buffer.from(header), bytes]));
  });
}

/** Local static scan. Production/API isolation and transport remain a later adapter. */
export async function runStaticFile(
  path: string,
  options: GitleaksOptions = {},
): Promise<StaticReport> {
  checkActive(options.signal);
  const bytes = await readLocalFile(path, limits.fileBytes);
  const inputSha256 = sha256(bytes);
  try {
    const context = createContext(bytes);
    const scanner = await runGitleaks(context.fields, options);
    checkActive(options.signal);
    return await runStaticChild(bytes, scanner, options.signal);
  } catch (error) {
    if (error instanceof WorkerFailure) throw error;
    return staticError(
      inputSha256,
      error instanceof WorkflowError ? error.code : "analyzer_exit",
    );
  }
}
