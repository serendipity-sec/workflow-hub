import { z } from "zod";
import { assessmentReportSchema } from "./assessment-contract.js";
import { runAssessmentFile } from "./assessment-runner.js";
import type { AssessmentRunOptions } from "./assessment-runner.js";
import { buildServiceReport, serviceReportSchema } from "./service-report.js";
import {
  createLlmContext,
  llmReviewSchema,
  reviewWithLlm,
} from "./llm-review.js";
import type { LlmOptions } from "./llm-review.js";

export const inspectionSchema = z
  .strictObject({
    inspectionVersion: z.literal("1.0.0"),
    inputSha256: z.string().regex(/^[a-f0-9]{64}$/),
    assessment: assessmentReportSchema,
    serviceReport: serviceReportSchema,
    llm: llmReviewSchema,
  })
  .refine(
    (value) =>
      value.inputSha256 === value.assessment.inputSha256 &&
      value.serviceReport.inputSha256 === value.inputSha256 &&
      value.llm.inputSha256 === value.inputSha256 &&
      JSON.stringify(value.serviceReport) ===
        JSON.stringify(buildServiceReport(value.assessment)) &&
      JSON.stringify(value.llm.context) ===
        JSON.stringify(createLlmContext(value.assessment)),
    {
      message:
        "Inspection components must be bound to the same unmodified assessment",
    },
  );
export type Inspection = z.infer<typeof inspectionSchema>;

/** One versioned worker artifact. It is not an HTTP API or publication approval. */
export async function presentInspection(
  input: unknown,
  options: LlmOptions = {},
): Promise<Inspection> {
  const assessment = assessmentReportSchema.parse(input);
  const serviceReport = buildServiceReport(assessment);
  const llm = await reviewWithLlm(assessment, options);
  return inspectionSchema.parse({
    inspectionVersion: "1.0.0",
    inputSha256: assessment.inputSha256,
    assessment,
    serviceReport,
    llm,
  });
}
export async function inspectFile(
  path: string,
  options: AssessmentRunOptions & { llm?: LlmOptions } = {},
): Promise<Inspection> {
  return presentInspection(await runAssessmentFile(path, options), {
    ...options.llm,
    signal:
      options.signal && options.llm?.signal
        ? AbortSignal.any([options.signal, options.llm.signal])
        : (options.signal ?? options.llm?.signal),
  });
}
