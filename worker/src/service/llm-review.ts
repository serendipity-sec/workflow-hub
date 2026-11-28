import { createHash } from "node:crypto";
import { z } from "zod";
import { assessmentReportSchema } from "../contracts/assessment-contract.js";
import { categories } from "../contracts/static-contract.js";
import { buildServiceReport } from "./service-report.js";

export const llmDefaults = {
  model: "z-ai/glm-5.3-flash",
  endpoint: "https://openrouter.ai/api/v1/chat/completions",
  maxOutputTokens: 1800,
  timeoutMs: 45_000,
  inputBytes: 24 * 1024,
  responseBytes: 96 * 1024,
  maxReferences: 48,
  // USD per million tokens. No silent escalation to more expensive routes.
  maxPrice: { prompt: 0.04, completion: 0.08, request: 0 },
} as const;
const hash = (text: string) => createHash("sha256").update(text).digest("hex");
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const referenceId = z.string().regex(/^r[1-9][0-9]{0,2}$/);
const prose = z
  .string()
  .min(1)
  .max(1000)
  .refine(
    (text) =>
      !/[<>\u0000-\u0008\u000b\u000c\u000e-\u001f]|https?:\/\/|\bsk-[A-Za-z0-9_-]+|[\w.+-]+@[\w.-]+\.[a-z]{2,}/i.test(
        text,
      ),
    "Only plain explanatory text without addresses or credentials is accepted",
  )
  .refine(
    (text) =>
      !/(?:안전합니다|안전하다|안전한\s*워크플로|문제가?\s*없|위험이?\s*없|모든.{0,20}(?:통과|해결|확인했)|공개.{0,8}가능|실제.{0,16}(?:실행했|검증했|확인했)|완전히?\s*(?:해결|검증)|\bsafe\s+to\b|\bno\s+(?:security\s+)?(?:risks?|vulnerabilities)\b|\ball\s+.{0,20}(?:passed|verified)\b)/i.test(
        text,
      ),
    "Unsupported success or safety claim",
  );
const adviceSchema = z.strictObject({
  summary: prose,
  items: z
    .array(
      z.strictObject({
        referenceIds: z.array(referenceId).min(1).max(4),
        explanation: prose,
        nextSteps: z.array(prose).min(1).max(3),
      }),
    )
    .max(12),
});
const referenceSchema = z.strictObject({
  id: referenceId,
  analysisKey: digest,
  fileSha256: digest,
  evidenceIds: z.array(digest).min(1).max(4),
  category: z.enum(categories),
  kind: z.enum(["finding", "analysis_gap", "environment_check", "scope_note"]),
  description: z.string().max(2048),
  severity: z.enum(["info", "low", "medium", "high"]).nullable(),
  claim: z.enum(["configuration", "candidate", "supported_path"]).nullable(),
  nodeIndex: z.int().min(0).max(255).nullable(),
});
const contextSchema = z.strictObject({
  inputSha256: digest,
  engineVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
  assessmentStatus: z.enum(["analyzed", "partial", "unsupported", "error"]),
  execution: z.literal("not_run"),
  decision: z.enum(["allow", "review", "block", "inconclusive"]),
  functions: z
    .array(
      z.strictObject({
        kind: z.enum([
          "webhook",
          "schedule",
          "manual",
          "email",
          "http",
          "database",
          "condition",
          "mapping",
          "merge",
          "code",
          "command",
          "ssh",
          "file",
          "message",
          "document",
          "ai",
          "subworkflow",
          "response",
          "note",
          "unknown",
        ]),
        count: z.int().min(1).max(4096),
      }),
    )
    .max(21),
  references: z.array(referenceSchema).max(llmDefaults.maxReferences),
  omittedReferences: z.int().min(0),
  instructions: z.literal(
    "explain_observed_categories_only_no_new_findings_no_safety_verdict",
  ),
});
export type LlmContext = z.infer<typeof contextSchema>;
export function createLlmContext(input: unknown): LlmContext {
  const report = assessmentReportSchema.parse(input);
  const presentation = buildServiceReport(report);
  const descriptions = new Map<
    string,
    { kind: LlmContext["references"][number]["kind"]; description: string }
  >([
    ...presentation.findings.map(
      (card) =>
        [
          `${card.reference.analysisKey}:${card.reference.id}`,
          {
            kind: "finding" as const,
            description: `${card.title} ${card.explanation} ${card.action}`,
          },
        ] as const,
    ),
    ...presentation.analysisGaps.map(
      (card) =>
        [
          `${card.reference.analysisKey}:${card.reference.id}`,
          {
            kind: "analysis_gap" as const,
            description: `${card.title} ${card.explanation} ${card.action}`,
          },
        ] as const,
    ),
    ...presentation.environmentChecks.map(
      (card) =>
        [
          `${card.reference.analysisKey}:${card.reference.id}`,
          {
            kind: "environment_check" as const,
            description: `${card.title} ${card.explanation} ${card.action}`,
          },
        ] as const,
    ),
    ...presentation.scopeNotes.map(
      (card) =>
        [
          `${card.reference.analysisKey}:${card.reference.id}`,
          {
            kind: "scope_note" as const,
            description: `${card.title} ${card.explanation} ${card.action}`,
          },
        ] as const,
    ),
  ]);
  const functions = new Map<LlmContext["functions"][number]["kind"], number>();
  const references: LlmContext["references"] = [];
  let total = 0;
  if (report.status !== "error") {
    for (const file of report.files) {
      for (const node of file.functionSummary?.nodes ?? []) {
        if (!node.disabled)
          functions.set(node.kind, (functions.get(node.kind) ?? 0) + 1);
      }
    }
    const rows = report.files.flatMap((file) =>
      [
        ...(file.base.status === "error" ? [] : file.base.rules),
        ...file.extensionRules,
      ].flatMap((rule) => [
        ...rule.findings
          .filter((f) => f.severity !== "info")
          .map((finding) => ({
            fileSha256: file.inputSha256,
            analysisKey: file.analysisKey,
            evidenceIds: [finding.id],
            category: finding.category,
            kind: "finding" as const,
            severity: finding.severity,
            claim: finding.claim,
            description:
              descriptions.get(`${file.analysisKey}:${finding.id}`)
                ?.description ??
              "검토 후보의 상세 근거와 조치를 원래 검사 결과에서 확인하세요.",
            nodeIndex: /\/nodes\/(\d+)/.test(finding.location.pointer)
              ? Number(/\/nodes\/(\d+)/.exec(finding.location.pointer)![1])
              : null,
          })),
        ...rule.diagnostics
          .map((diagnostic) => ({
            fileSha256: file.inputSha256,
            analysisKey: file.analysisKey,
            evidenceIds: [diagnostic.id],
            category: rule.category,
            kind: "analysis_gap" as const,
            severity: null,
            claim: null,
            description:
              descriptions.get(`${file.analysisKey}:${diagnostic.id}`)
                ?.description ??
              "해당 검사 범위의 미확인 내용을 원래 검사 결과에서 확인하세요.",
            nodeIndex: /\/nodes\/(\d+)/.test(diagnostic.location.pointer)
              ? Number(/\/nodes\/(\d+)/.exec(diagnostic.location.pointer)![1])
              : null,
          }))
          .map((row) => ({
            ...row,
            kind:
              descriptions.get(`${file.analysisKey}:${row.evidenceIds[0]!}`)
                ?.kind ?? ("analysis_gap" as const),
          })),
      ]),
    );
    // Category diversity before repeated locations; higher severity first.
    const score = (row: (typeof rows)[number]) =>
      row.kind !== "finding"
        ? 4
        : ["high", "medium", "low", "info"].indexOf(row.severity!);
    rows.sort((a, b) => score(a) - score(b));
    const groups = new Map<string, typeof rows>();
    for (const row of rows) {
      const key = `${row.kind}:${row.category}`;
      groups.set(key, [...(groups.get(key) ?? []), row]);
    }
    total = rows.length;
    for (
      let n = 0;
      references.length < Math.min(total, llmDefaults.maxReferences);
      n++
    ) {
      for (const group of groups.values()) {
        if (group[n] && references.length < llmDefaults.maxReferences)
          references.push({ id: `r${references.length + 1}`, ...group[n]! });
      }
    }
  }
  // Do not forward source strings, code, parameter values, diagnostic text,
  // pointers, package names, recipients, titles, arbitrary evidence or policy IDs.
  const context = contextSchema.parse({
    inputSha256: report.inputSha256,
    engineVersion: report.engineVersion,
    assessmentStatus: report.status,
    execution: "not_run",
    decision: report.status === "error" ? "inconclusive" : report.decision,
    functions: [...functions].map(([kind, count]) => ({ kind, count })),
    references,
    omittedReferences: total - references.length,
    instructions:
      "explain_observed_categories_only_no_new_findings_no_safety_verdict",
  });
  while (
    Buffer.byteLength(JSON.stringify(context)) > llmDefaults.inputBytes &&
    context.references.length
  ) {
    context.references.pop();
    context.omittedReferences++;
  }
  return context;
}

/** Local aliases keep exact analysis identity. Providers receive no hashes or source IDs. */
export function providerContext(context: LlmContext) {
  return {
    assessmentStatus: context.assessmentStatus,
    execution: context.execution,
    functions: context.functions,
    omittedReferences: context.omittedReferences,
    references: context.references.map(
      ({ id, category, kind, description, severity, claim, nodeIndex }) => ({
        id,
        category,
        kind,
        description,
        severity,
        claim,
        nodeIndex,
      }),
    ),
  };
}
const selectionSchema = z.strictObject({
  focusReferenceIds: z.array(referenceId).max(8),
});
type Selection = z.infer<typeof selectionSchema>;
function validSelection(context: LlmContext, selection: Selection): boolean {
  return (
    (!context.references.length || selection.focusReferenceIds.length > 0) &&
    new Set(selection.focusReferenceIds).size ===
      selection.focusReferenceIds.length &&
    selection.focusReferenceIds.every((id) =>
      context.references.some((ref) => ref.id === id),
    )
  );
}
const functionLabels: Record<LlmContext["functions"][number]["kind"], string> =
  {
    webhook: "웹 요청",
    schedule: "일정 실행",
    manual: "수동 시작",
    email: "이메일",
    http: "HTTP 요청",
    database: "DB 처리",
    condition: "조건 분기",
    mapping: "데이터 처리",
    merge: "병합",
    code: "코드 처리",
    command: "명령",
    ssh: "SSH",
    file: "파일",
    message: "메시지",
    document: "문서·시트",
    ai: "AI",
    subworkflow: "하위 워크플로",
    response: "응답",
    note: "메모",
    unknown: "미확인 노드",
  };
function renderAdvice(
  context: LlmContext,
  selection: Selection,
): z.infer<typeof adviceSchema> {
  return {
    summary: `정의에 ${context.functions.map(({ kind }) => functionLabels[kind]).join(", ") || "분류할 수 없는"} 기능이 있습니다. ${context.assessmentStatus === "analyzed" ? "지원 범위에서 정적 검사를 마쳤습니다." : "미확인 분석 범위와 사용 조건을 함께 확인해야 합니다."} 실제 워크플로는 실행하지 않았습니다.`,
    items: selection.focusReferenceIds.map((id) => ({
      referenceIds: [id],
      explanation: context.references.find((ref) => ref.id === id)!.description,
      nextSteps: [
        "원래 검사 결과에서 해당 근거의 위치와 수정 조건을 확인하세요.",
      ],
    })),
  };
}

const llmCodes = [
  "disabled",
  "missing_key",
  "invalid_configuration",
  "analysis_failed",
  "cancelled",
  "timeout",
  "network_error",
  "authentication_failed",
  "credit_required",
  "rate_limited",
  "provider_unavailable",
  "response_too_large",
  "invalid_response",
  "invalid_references",
  "incomplete_response",
] as const;
const resultBase = {
  schemaVersion: z.literal("1.0.0"),
  authority: z.literal("explanation_only"),
  affectsVerdict: z.literal(false),
  requiresHumanReview: z.literal(true),
  workflowExecution: z.literal("not_run"),
  inputSha256: digest,
  contextSha256: digest,
  model: z.string().max(100),
  context: contextSchema,
};
export const llmReviewSchema = z
  .discriminatedUnion("status", [
    z.strictObject({
      ...resultBase,
      status: z.literal("unavailable"),
      code: z.enum(llmCodes),
    }),
    z.strictObject({
      ...resultBase,
      status: z.literal("generated"),
      method: z.literal("model_selection_with_deterministic_text"),
      selection: selectionSchema,
      advice: adviceSchema,
      usage: z.strictObject({
        promptTokens: z.int().min(0).nullable(),
        completionTokens: z.int().min(0).nullable(),
        costUsd: z.number().nonnegative().nullable(),
      }),
    }),
  ])
  .refine(
    (value) =>
      value.contextSha256 === hash(JSON.stringify(value.context)) &&
      value.inputSha256 === value.context.inputSha256 &&
      (value.status !== "generated" ||
        (validSelection(value.context, value.selection) &&
          JSON.stringify(value.advice) ===
            JSON.stringify(renderAdvice(value.context, value.selection)))),
  );
export type LlmReview = z.infer<typeof llmReviewSchema>;
export interface LlmOptions {
  enabled?: boolean;
  apiKey?: string;
  model?: string;
  maxOutputTokens?: number;
  signal?: AbortSignal;
  // Injection exists for deterministic transport tests, never supplied by workflows.
  fetch?: typeof fetch;
  timeoutMs?: number;
}

const systemPrompt = `n8n 정적 검사 결과에서 사용자가 먼저 읽어야 할 근거를 최대 8개 선택하라.
높은 위험 후보와 실제 분석 공백을 우선하고, 같은 설명은 중복하지 말고 중요한 환경 확인도 포함하라.
입력에 있는 r 식별자만 사용해 focusReferenceIds 배열을 반환하라. 근거가 있으면 최소 하나를 선택하라.
문장, 판정, 분석 결과, 수정 코드, 추가 필드를 생성하지 마라. 설명 문장은 서버가 원래 근거로 작성한다.`;
export async function reviewWithLlm(
  input: unknown,
  options: LlmOptions = {},
): Promise<LlmReview> {
  const context = createLlmContext(input);
  const model = options.model ?? llmDefaults.model;
  const header = {
    schemaVersion: "1.0.0" as const,
    authority: "explanation_only" as const,
    affectsVerdict: false as const,
    requiresHumanReview: true as const,
    workflowExecution: "not_run" as const,
    inputSha256: context.inputSha256,
    contextSha256: hash(JSON.stringify(context)),
    model: /^[a-z0-9~][a-z0-9/._:-]{1,98}$/.test(model) ? model : "invalid",
    context,
  };
  const failure = (code: (typeof llmCodes)[number]): LlmReview =>
    llmReviewSchema.parse({ ...header, status: "unavailable", code });
  if (!options.enabled) return failure("disabled");
  if (!options.apiKey) return failure("missing_key");
  const maxTokens = options.maxOutputTokens ?? llmDefaults.maxOutputTokens;
  const timeoutMs = options.timeoutMs ?? llmDefaults.timeoutMs;
  if (
    header.model === "invalid" ||
    !Number.isSafeInteger(maxTokens) ||
    maxTokens < 256 ||
    maxTokens > 4096 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 60_000 ||
    /[\r\n]/.test(options.apiKey)
  )
    return failure("invalid_configuration");
  if (context.assessmentStatus === "error") return failure("analysis_failed");
  if (options.signal?.aborted) return failure("cancelled");
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const cancel = () => controller.abort();
  options.signal?.addEventListener("abort", cancel, { once: true });
  let receivedResponse = false;
  try {
    const response = await (options.fetch ?? fetch)(llmDefaults.endpoint, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${options.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        stream: false,
        temperature: 0,
        max_tokens: maxTokens,
        reasoning: { effort: "low", exclude: true },
        provider: {
          sort: "price",
          require_parameters: true,
          data_collection: "deny",
          max_price: llmDefaults.maxPrice,
        },
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: JSON.stringify(providerContext(context)) },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "workflow_explanation",
            strict: true,
            schema: {
              type: "object",
              additionalProperties: false,
              required: ["focusReferenceIds"],
              properties: {
                focusReferenceIds: {
                  type: "array",
                  items: { type: "string" },
                },
              },
            },
          },
        },
      }),
    });
    receivedResponse = true;
    if (!response.ok) {
      await response.body?.cancel();
      return failure(
        response.status === 401 || response.status === 403
          ? "authentication_failed"
          : response.status === 402
            ? "credit_required"
            : response.status === 429
              ? "rate_limited"
              : "provider_unavailable",
      );
    }
    const chunks: Uint8Array[] = [];
    let count = 0;
    if (!response.body) return failure("invalid_response");
    const reader = response.body.getReader();
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        count += part.value.byteLength;
        if (count > llmDefaults.responseBytes) {
          await reader.cancel();
          return failure("response_too_large");
        }
        chunks.push(part.value);
      }
    } finally {
      reader.releaseLock();
    }
    if (options.signal?.aborted) return failure("cancelled");
    if (timedOut) return failure("timeout");
    const envelope = z
      .object({
        model: z.string(),
        choices: z
          .array(
            z.object({
              finish_reason: z.string().nullable(),
              message: z.object({
                content: z.string().nullable(),
                refusal: z.unknown().optional(),
              }),
            }),
          )
          .length(1),
        usage: z
          .object({
            prompt_tokens: z.number().int().nonnegative().optional(),
            completion_tokens: z.number().int().nonnegative().optional(),
            cost: z.number().nonnegative().optional(),
          })
          .optional(),
      })
      .safeParse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    if (!envelope.success || envelope.data.model !== model)
      return failure("invalid_response");
    const choice = envelope.data.choices[0]!;
    if (
      choice.finish_reason !== "stop" ||
      choice.message.refusal ||
      !choice.message.content
    )
      return failure("incomplete_response");
    const selection = selectionSchema.safeParse(
      JSON.parse(choice.message.content),
    );
    if (!selection.success) return failure("invalid_response");
    if (!validSelection(context, selection.data))
      return failure("invalid_references");
    return llmReviewSchema.parse({
      ...header,
      status: "generated",
      method: "model_selection_with_deterministic_text",
      selection: selection.data,
      advice: renderAdvice(context, selection.data),
      usage: {
        promptTokens: envelope.data.usage?.prompt_tokens ?? null,
        completionTokens: envelope.data.usage?.completion_tokens ?? null,
        costUsd: envelope.data.usage?.cost ?? null,
      },
    });
  } catch {
    return failure(
      options.signal?.aborted
        ? "cancelled"
        : timedOut
          ? "timeout"
          : receivedResponse
            ? "invalid_response"
            : "network_error",
    );
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", cancel);
  }
}
