import { z } from "zod";
import { limits } from "./contract.js";
import type { ErrorCode } from "./contract.js";
import type { GitleaksResult } from "./gitleaks.js";
import { WorkflowError } from "./n8n.js";
import { analyzeContent } from "./static-content.js";
import { createContext } from "./static-context.js";
import { analyzeFlow } from "./static-flow.js";
import { analyzeSettings } from "./static-settings.js";
import {
  reportStatus,
  staticReportSchema,
  staticResultVersions,
} from "./static-contract.js";
import type { StaticReport } from "./static-contract.js";
import { sha256 } from "./worker-io.js";

// Only the trusted controller runs an external scanner. The child receives
// indices and rule identifiers, never scanner excerpts or environment values.
export const scannerResultSchema = z
  .strictObject({
    tool: z.literal("gitleaks"),
    version: z.literal("8.30.1"),
    status: z.enum(["completed", "error"]),
    findings: z
      .array(
        z.strictObject({
          fieldIndex: z.int().min(0).max(limits.fileBytes),
          ruleId: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,127}$/),
        }),
      )
      .max(4096),
    reason: z
      .enum([
        "tool_unavailable",
        "tool_version_mismatch",
        "tool_failed",
        "tool_timeout",
        "tool_cancelled",
        "tool_output_limit",
        "tool_input_limit",
        "tool_invalid_report",
        "tool_cleanup_failed",
      ])
      .optional(),
  })
  .refine((result) =>
    result.status === "completed"
      ? result.reason === undefined
      : result.reason !== undefined && result.findings.length === 0,
  );

export function staticError(
  inputSha256: string,
  code: ErrorCode,
): StaticReport {
  return {
    ...staticResultVersions,
    inputSha256,
    execution: "not_run",
    status: "error",
    code,
  };
}

export function analyzeStatic(
  bytes: Buffer,
  scanner: GitleaksResult,
): StaticReport {
  const inputSha256 = sha256(bytes);
  try {
    const context = createContext(bytes);
    const tool = scannerResultSchema.parse(scanner);
    if (
      tool.findings.some(
        ({ fieldIndex }) => fieldIndex >= context.fields.length,
      )
    )
      return staticError(inputSha256, "invalid_result");
    const rules = [
      ...analyzeContent(context, tool),
      ...analyzeSettings(context),
      ...analyzeFlow(context),
    ];
    const report = {
      ...staticResultVersions,
      inputSha256,
      execution: "not_run" as const,
      status: reportStatus(rules),
      rules,
    };
    if (Buffer.byteLength(JSON.stringify(report)) > limits.resultBytes)
      return staticError(inputSha256, "analyzer_output_limit");
    const validated = staticReportSchema.safeParse(report);
    return validated.success
      ? validated.data
      : staticError(inputSha256, "invalid_result");
  } catch (error) {
    return staticError(
      inputSha256,
      error instanceof WorkflowError ? error.code : "invalid_result",
    );
  }
}
