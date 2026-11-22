import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { ScalarField } from "./static-context.js";

export const gitleaksVersion = "8.30.1" as const;
export type GitleaksReason =
  | "tool_unavailable"
  | "tool_version_mismatch"
  | "tool_failed"
  | "tool_timeout"
  | "tool_cancelled"
  | "tool_output_limit"
  | "tool_input_limit"
  | "tool_invalid_report"
  | "tool_cleanup_failed";
export type GitleaksResult = {
  tool: "gitleaks";
  version: typeof gitleaksVersion;
  status: "completed" | "error";
  findings: { fieldIndex: number; ruleId: string }[];
  reason?: GitleaksReason;
};
export type GitleaksOptions = {
  executable?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxOutputBytes?: number;
};
type ProcessResult = {
  code: number | null;
  stdout: string;
  reason?: GitleaksReason;
};

function toolEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"])
    if (process.env[name]) env[name] = process.env[name];
  return env;
}

function runProcess(
  executable: string,
  args: string[],
  input: string,
  cwd: string,
  timeoutMs: number,
  maxOutputBytes: number,
  signal?: AbortSignal,
): Promise<ProcessResult> {
  if (signal?.aborted)
    return Promise.resolve({
      code: null,
      stdout: "",
      reason: "tool_cancelled",
    });
  return new Promise((resolve) => {
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      cwd,
      env: toolEnvironment(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let reason: GitleaksReason | undefined;
    const stop = (why: GitleaksReason) => {
      reason ??= why;
      child.kill("SIGKILL");
    };
    const timer = setTimeout(() => stop("tool_timeout"), timeoutMs);
    const cancel = () => stop("tool_cancelled");
    signal?.addEventListener("abort", cancel, { once: true });
    child.stdout.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) stop("tool_output_limit");
      else if (!reason) chunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) stop("tool_output_limit");
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      reason ??= error.code === "ENOENT" ? "tool_unavailable" : "tool_failed";
    });
    child.stdin.on("error", () => stop("tool_failed"));
    child.on("close", (code) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancel);
      resolve({
        code,
        stdout: reason ? "" : Buffer.concat(chunks).toString("utf8"),
        reason,
      });
    });
    child.stdin.end(input);
  });
}

/** Trusted controller only: never called from the restricted analysis child. */
export async function runGitleaks(
  fields: readonly Pick<ScalarField, "index" | "value">[],
  options: GitleaksOptions = {},
): Promise<GitleaksResult> {
  const fail = (reason: GitleaksReason): GitleaksResult => ({
    tool: "gitleaks",
    version: gitleaksVersion,
    status: "error",
    findings: [],
    reason,
  });
  if (!options.executable || !isAbsolute(options.executable))
    return fail("tool_unavailable");
  if (options.signal?.aborted) return fail("tool_cancelled");
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxOutputBytes = options.maxOutputBytes ?? 512 * 1024;
  if (
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000 ||
    !Number.isInteger(maxOutputBytes) ||
    maxOutputBytes < 1 ||
    maxOutputBytes > 2 * 1024 * 1024
  )
    return fail("tool_input_limit");
  if (fields.length > 16_384) return fail("tool_input_limit");
  const ranges: { first: number; last: number; fieldIndex: number }[] = [];
  const parts: string[] = [];
  let nextLine = 1;
  let totalBytes = 0;
  const seen = new Set<number>();
  for (const field of fields) {
    if (
      !Number.isSafeInteger(field.index) ||
      field.index < 0 ||
      seen.has(field.index) ||
      typeof field.value !== "string"
    )
      return fail("tool_input_limit");
    seen.add(field.index);
    totalBytes += Buffer.byteLength(field.value) + 32;
    if (totalBytes > 2 * 1024 * 1024) return fail("tool_input_limit");
    const text = field.value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const lines = text.split("\n").length;
    ranges.push({
      first: nextLine,
      last: nextLine + lines - 1,
      fieldIndex: field.index,
    });
    parts.push(text, "\n__WORKFLOW_FIELD_BOUNDARY__\n");
    nextLine += lines + 1;
  }
  let directory: string | undefined;
  let result: GitleaksResult = fail("tool_failed");
  try {
    directory = await mkdtemp(join(tmpdir(), "workflow-secret-scan-"));
    const version = await runProcess(
      options.executable,
      ["version"],
      "",
      directory,
      timeoutMs,
      4096,
      options.signal,
    );
    if (version.reason) result = fail(version.reason);
    else if (version.code !== 0) result = fail("tool_failed");
    // Official OCI releases prefix the same pinned version with "v"; the
    // release executable and CI's Go build may omit it. No other versions pass.
    else if (
      ![gitleaksVersion, `v${gitleaksVersion}`].includes(version.stdout.trim())
    )
      result = fail("tool_version_mismatch");
    else {
      const config = join(directory, "trusted.toml");
      const ignore = join(directory, "empty.ignore");
      await writeFile(config, "[extend]\nuseDefault = true\n", { mode: 0o600 });
      await writeFile(ignore, "", { mode: 0o600 });
      const scan = await runProcess(
        options.executable,
        [
          "stdin",
          "--config",
          config,
          "--gitleaks-ignore-path",
          ignore,
          "--redact=100",
          "--report-format=json",
          "--report-path=-",
          "--exit-code=2",
          "--ignore-gitleaks-allow",
          "--max-decode-depth=0",
          "--no-banner",
          "--no-color",
          "--log-level=fatal",
          "--timeout",
          String(Math.max(1, Math.ceil(timeoutMs / 1000))),
        ],
        parts.join(""),
        directory,
        timeoutMs,
        maxOutputBytes,
        options.signal,
      );
      if (scan.reason) result = fail(scan.reason);
      else if (scan.code !== 0 && scan.code !== 2) result = fail("tool_failed");
      else {
        let report: unknown;
        try {
          report = JSON.parse(scan.stdout);
        } catch {
          report = null;
        }
        if (
          !Array.isArray(report) ||
          report.length > 4096 ||
          (scan.code === 2) !== report.length > 0
        )
          result = fail("tool_invalid_report");
        else {
          const findings: GitleaksResult["findings"] = [];
          let valid = true;
          for (const entry of report) {
            if (
              entry === null ||
              typeof entry !== "object" ||
              typeof entry.RuleID !== "string" ||
              !/^[a-z0-9][a-z0-9_-]{0,127}$/.test(entry.RuleID) ||
              !Number.isSafeInteger(entry.StartLine) ||
              !Number.isSafeInteger(entry.EndLine) ||
              entry.StartLine < 1 ||
              entry.EndLine < entry.StartLine ||
              entry.Secret !== "REDACTED"
            ) {
              valid = false;
              break;
            }
            const field = ranges.find(
              (range) =>
                entry.StartLine >= range.first && entry.EndLine <= range.last,
            );
            if (!field) {
              valid = false;
              break;
            }
            if (
              !findings.some(
                (item) =>
                  item.fieldIndex === field.fieldIndex &&
                  item.ruleId === entry.RuleID,
              )
            )
              findings.push({
                fieldIndex: field.fieldIndex,
                ruleId: entry.RuleID,
              });
          }
          result = valid
            ? {
                tool: "gitleaks",
                version: gitleaksVersion,
                status: "completed",
                findings,
              }
            : fail("tool_invalid_report");
        }
      }
    }
  } catch {
    result = fail("tool_failed");
  } finally {
    if (directory) {
      try {
        const target = resolve(directory);
        if (
          dirname(target) !== resolve(tmpdir()) ||
          !basename(target).startsWith("workflow-secret-scan-")
        )
          throw Error("Unexpected cleanup target");
        await rm(target, { recursive: true, force: true });
      } catch {
        result = fail("tool_cleanup_failed");
      }
    }
  }
  return result;
}
