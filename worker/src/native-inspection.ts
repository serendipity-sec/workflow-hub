import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { Context, ScalarField } from "./static-context.js";
import type { Finding, RuleResult, StaticLocation } from "./static-contract.js";
import { stableId } from "./static-contract.js";

const modeSchema = z.enum(["nlp", "python"]);
const findingCode = z.enum([
  "nlp_person_candidate",
  "nlp_location_candidate",
  "nlp_email_candidate",
  "nlp_phone_candidate",
  "nlp_payment_card_candidate",
  "nlp_ip_address_candidate",
  "python_process_execution_call",
  "python_external_input_shell_call",
  "python_external_input_process_argument",
  "python_dynamic_evaluation_call",
  "python_external_input_evaluation",
  "python_outbound_request_call",
  "python_external_input_request_call",
  "python_log_call",
  "python_external_input_log_call",
  "python_file_access_call",
]);
const diagnosticCode = z.enum([
  "native_tool_unavailable",
  "native_failed",
  "native_timeout",
  "native_cancelled",
  "native_output_limit",
  "native_invalid_report",
  "native_invalid_input",
  "native_model_or_dependency_unavailable",
  "native_finding_limit",
  "native_input_scope_limit",
  "native_field_size_limit",
  "native_python_source_missing",
  "nlp_english_model_profile",
  "nlp_language_outside_profile",
  "nlp_field_analysis_failed",
  "nlp_metadata_formats_only",
  "nlp_program_formats_only",
  "nlp_template_literal_text_only",
  "nlp_json_string_values_only",
  "nlp_json_text_unresolved",
  "nlp_technical_entity_filtered",
  "nlp_chunked_text_profile",
  "python_static_profile_limited",
  "python_ast_limit",
  "python_wildcard_import_unresolved",
  "python_alias_analysis_limit",
  "python_dynamic_import_unresolved",
  "python_parse_unavailable",
  "python_analysis_failed",
]);
export const nativeModeResultSchema = z
  .strictObject({
    mode: modeSchema,
    status: z.enum(["completed", "error"]),
    findings: z
      .array(
        z
          .strictObject({
            fieldIndex: z.int().nonnegative(),
            code: findingCode,
            start: z.int().nonnegative().nullable(),
            end: z.int().nonnegative().nullable(),
            line: z.int().positive().nullable(),
          })
          .refine(
            (item) =>
              (item.start === null && item.end === null) ||
              (item.start !== null &&
                item.end !== null &&
                item.end > item.start),
          ),
      )
      .max(256),
    diagnostics: z
      .array(
        z.strictObject({
          fieldIndex: z.int().nonnegative().nullable(),
          code: diagnosticCode,
        }),
      )
      .max(256),
    versions: z.strictObject({
      python: z
        .string()
        .regex(/^\d{1,2}\.\d{1,2}\.\d{1,3}$/)
        .nullable(),
      presidio: z.literal("2.2.366").nullable(),
      spacy: z.literal("3.8.18").nullable(),
      model: z.literal("en_core_web_sm@3.8.0").nullable(),
    }),
  })
  .refine((result) =>
    result.status === "error"
      ? result.findings.length === 0 && result.diagnostics.length > 0
      : result.versions.python !== null &&
        (result.mode !== "nlp" ||
          (result.versions.presidio !== null &&
            result.versions.spacy !== null &&
            result.versions.model !== null)),
  )
  .refine((result) =>
    result.findings.every(
      (item) =>
        item.code.startsWith("nlp_") === (result.mode === "nlp") &&
        (result.mode !== "nlp" || (item.start !== null && item.end !== null)),
    ),
  );
export const nativeInspectionResultSchema = z
  .strictObject({
    tool: z.literal("native_inspection"),
    version: z.literal("1.0.0"),
    modes: z.array(nativeModeResultSchema).min(1).max(2),
  })
  .refine(
    (result) =>
      new Set(result.modes.map((mode) => mode.mode)).size ===
      result.modes.length,
  );
export type NativeInspectionResult = z.infer<
  typeof nativeInspectionResultSchema
>;
export type NativeModeResult = z.infer<typeof nativeModeResultSchema>;
export type NativeInspectionOptions = {
  pythonExecutable?: string;
  signal?: AbortSignal;
  modes?: ("nlp" | "python")[];
  timeoutMs?: number;
  maxOutputBytes?: number;
};
const helper = fileURLToPath(
  new URL("../tools/native-inspection.py", import.meta.url),
);

function failure(
  mode: "nlp" | "python",
  code: z.infer<typeof diagnosticCode>,
): NativeModeResult {
  return {
    mode,
    status: "error",
    findings: [],
    diagnostics: [{ fieldIndex: null, code }],
    versions: { python: null, presidio: null, spacy: null, model: null },
  };
}

function pythonNode(node: Context["nodes"][number]): boolean {
  return (
    !node.disabled &&
    ((node.type === "n8n-nodes-base.code" &&
      node.typeVersion === 2 &&
      ["python", "pythonNative"].includes(String(node.parameters.language))) ||
      (node.type === "@n8n/n8n-nodes-langchain.toolCode" &&
        [1, 1.1, 1.2, 1.3].includes(node.typeVersion) &&
        node.parameters.language === "python"))
  );
}
function fieldsFor(context: Context, mode: "nlp" | "python"): ScalarField[] {
  if (mode === "nlp") return context.fields;
  const pointers = new Set(
    context.nodes
      .filter(pythonNode)
      .map((node) => node.pointer + "/parameters/pythonCode"),
  );
  return context.fields.filter(
    (field) => field.kind === "value" && pointers.has(field.pointer),
  );
}

type NamedEntityScope =
  "metadata" | "program" | "prose" | "data" | "template" | "json";

/** Format recognizers still receive every key/value. NER sees data/prose, not schema syntax. */
export function nativeNlpScope(field: ScalarField): NamedEntityScope {
  if (field.kind === "key") return "metadata";
  const path = field.pointer;
  if (/^\/pinData(?:\/|$)/.test(path)) return "data";
  if (
    /^\/(?:id|name|versionId|versionCounter|tags|connections|settings|meta)(?:\/|$)/.test(
      path,
    ) ||
    /^\/nodes\/\d+\/(?:id|name|type|typeVersion|position|credentials|webhookId|retryOnFail|onError)(?:\/|$)/.test(
      path,
    ) ||
    /^\/nodes\/\d+\/parameters\/(?:resource|operation|mode|language|authentication|specifyBody|specifyQuery|specifyHeaders|respondWith|responseMode|contentType|httpMethod|messageType|emailFormat|select|rule)(?:\/|$)/.test(
      path,
    ) ||
    /^\/nodes\/\d+\/parameters\/assignments\/assignments\/\d+\/(?:id|type|name)$/.test(
      path,
    ) ||
    /^\/nodes\/\d+\/parameters\/conditions\/conditions\/\d+\/operator\/(?:type|operation)$/.test(
      path,
    ) ||
    /^\/nodes\/\d+\/parameters\/[^/]+\/(?:cachedResultName|cachedResultUrl)$/.test(
      path,
    )
  )
    return "metadata";
  if (
    /\/(?:jsCode|pythonCode|query|queryReplacement|command)$/.test(path) ||
    /^\/nodes\/\d+\/parameters\/options\/customEmailConfig$/.test(path)
  )
    return "program";
  if (field.value.trimStart().startsWith("=") || field.value.includes("{{"))
    return "template";
  if (/^\s*[\[{]/.test(field.value)) {
    try {
      const decoded: unknown = JSON.parse(field.value);
      if (decoded !== null && typeof decoded === "object") return "json";
    } catch {
      /* Bracketed prose remains prose, not an unparsed JSON blind spot. */
    }
  }
  return "prose";
}

async function runMode(
  context: Context,
  mode: "nlp" | "python",
  options: NativeInspectionOptions,
): Promise<NativeModeResult> {
  const executable = options.pythonExecutable;
  if (!executable || !isAbsolute(executable))
    return failure(mode, "native_tool_unavailable");
  if (options.signal?.aborted) return failure(mode, "native_cancelled");
  const timeout = options.timeoutMs ?? 60000;
  const maximum = options.maxOutputBytes ?? 256 * 1024;
  if (
    !Number.isInteger(timeout) ||
    timeout < 1 ||
    timeout > 120000 ||
    !Number.isInteger(maximum) ||
    maximum < 1 ||
    maximum > 1024 * 1024
  )
    return failure(mode, "native_invalid_input");
  const fields = fieldsFor(context, mode);
  const input = JSON.stringify({
    fields: fields.map((field) => ({
      index: field.index,
      value: field.value,
      ...(mode === "nlp"
        ? { namedEntities: nativeNlpScope(field) }
        : {
            inputProfile: context.nodes.some(
              (node) =>
                node.type === "@n8n/n8n-nodes-langchain.toolCode" &&
                field.pointer === node.pointer + "/parameters/pythonCode",
            )
              ? "model_tool"
              : "code",
          }),
    })),
  });
  if (Buffer.byteLength(input) > 2 * 1024 * 1024)
    return failure(mode, "native_invalid_input");
  const environment: NodeJS.ProcessEnv = {
    OMP_NUM_THREADS: "1",
    OPENBLAS_NUM_THREADS: "1",
    MKL_NUM_THREADS: "1",
  };
  for (const key of ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"])
    if (process.env[key]) environment[key] = process.env[key];
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(executable, ["-I", "-B", helper, mode], {
        shell: false,
        windowsHide: true,
        env: environment,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      resolve(failure(mode, "native_failed"));
      return;
    }
    let reason: z.infer<typeof diagnosticCode> | undefined;
    let total = 0;
    const chunks: Buffer[] = [];
    const stop = (code: z.infer<typeof diagnosticCode>) => {
      reason ??= code;
      child.kill("SIGKILL");
    };
    const cancel = () => stop("native_cancelled");
    const timer = setTimeout(() => stop("native_timeout"), timeout);
    options.signal?.addEventListener("abort", cancel, { once: true });
    if (options.signal?.aborted) cancel();
    const consume = (chunk: Buffer, keep: boolean) => {
      total += chunk.length;
      if (total > maximum) stop("native_output_limit");
      else if (keep && !reason) chunks.push(chunk);
    };
    child.stdout!.on("data", (chunk: Buffer) => consume(chunk, true));
    child.stderr!.on("data", (chunk: Buffer) => consume(chunk, false));
    child.stdin!.on("error", () => stop("native_failed"));
    child.on("error", (error: NodeJS.ErrnoException) => {
      reason ??=
        error.code === "ENOENT" ? "native_tool_unavailable" : "native_failed";
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", cancel);
      if (reason || code !== 0) {
        resolve(failure(mode, reason ?? "native_failed"));
        return;
      }
      try {
        const result = nativeModeResultSchema.parse(
          JSON.parse(Buffer.concat(chunks).toString("utf8")),
        );
        const indices = new Map(fields.map((field) => [field.index, field]));
        if (
          result.mode !== mode ||
          result.findings.some(
            (item) =>
              !indices.has(item.fieldIndex) ||
              (item.end !== null &&
                item.end >
                  Array.from(indices.get(item.fieldIndex)!.value).length) ||
              item.code.startsWith("nlp_") !== (mode === "nlp"),
          ) ||
          result.diagnostics.some(
            (item) => item.fieldIndex !== null && !indices.has(item.fieldIndex),
          )
        )
          throw Error("Invalid native mapping");
        resolve(result);
      } catch {
        resolve(failure(mode, "native_invalid_report"));
      }
    });
    child.stdin!.end(input);
  });
}

/** Trusted controller only; uploaded Python and n8n expressions never execute. */
export async function runNativeInspection(
  context: Context,
  options: NativeInspectionOptions = {},
): Promise<NativeInspectionResult> {
  const requested = options.modes ?? ["nlp", "python"];
  if (
    !requested.length ||
    requested.some((mode) => mode !== "nlp" && mode !== "python")
  )
    return {
      tool: "native_inspection",
      version: "1.0.0",
      modes: [
        failure("nlp", "native_invalid_input"),
        failure("python", "native_invalid_input"),
      ],
    };
  const modes: NativeModeResult[] = [];
  for (const mode of [...new Set(requested)])
    modes.push(await runMode(context, mode, options));
  return { tool: "native_inspection", version: "1.0.0", modes };
}

const root: StaticLocation = { nodeKey: null, pointer: "" };
function rule(ruleId: string, category: RuleResult["category"]): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: category === "pii" ? "1.2.0" : "1.1.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}

export function analyzeNativeInspection(
  context: Context,
  input: NativeInspectionResult,
): RuleResult[] {
  const parsed = nativeInspectionResultSchema.safeParse(input);
  const results: RuleResult[] = [];
  const modes = parsed.success
    ? parsed.data.modes
    : [
        failure("nlp", "native_invalid_report"),
        failure("python", "native_invalid_report"),
      ];
  const fields = new Map(context.fields.map((field) => [field.index, field]));
  for (const mode of modes) {
    const rules =
      mode.mode === "nlp"
        ? [rule("PRESIDIO_PII_CANDIDATES", "pii")]
        : [
            rule("PYTHON_STATIC_CAPABILITIES", "code_execution"),
            rule("PYTHON_STATIC_OUTPUT", "output"),
          ];
    const addDiagnostic = (
      target: RuleResult,
      code: string,
      fieldIndex: number | null,
    ) => {
      const location =
        fieldIndex === null ? root : (fields.get(fieldIndex)?.location ?? root);
      const id = stableId(target.ruleId, location, code);
      if (
        !target.diagnostics.some((item) => item.id === id) &&
        target.diagnostics.length < 128
      )
        target.diagnostics.push({ id, code, location });
    };
    for (const item of mode.diagnostics)
      for (const target of rules)
        addDiagnostic(target, item.code, item.fieldIndex);
    const selectedIndices = new Set(
      fieldsFor(context, mode.mode).map((field) => field.index),
    );
    if (
      mode.mode === "python" &&
      context.nodes.some(
        (node) =>
          pythonNode(node) && typeof node.parameters.pythonCode !== "string",
      )
    )
      for (const target of rules)
        addDiagnostic(target, "native_python_source_missing", null);
    for (const item of mode.findings) {
      const target =
        mode.mode === "nlp" || !item.code.includes("log_call")
          ? rules[0]!
          : rules[1]!;
      const field = fields.get(item.fieldIndex);
      if (
        !field ||
        !selectedIndices.has(item.fieldIndex) ||
        (item.end !== null && item.end > Array.from(field.value).length) ||
        (item.line !== null && item.line > field.value.split(/\r?\n/).length)
      ) {
        addDiagnostic(target, "native_invalid_report", null);
        continue;
      }
      if (
        mode.mode === "nlp" &&
        ["nlp_person_candidate", "nlp_location_candidate"].includes(
          item.code,
        ) &&
        ["metadata", "program"].includes(nativeNlpScope(field))
      ) {
        addDiagnostic(
          target,
          nativeNlpScope(field) === "metadata"
            ? "nlp_metadata_formats_only"
            : "nlp_program_formats_only",
          field.index,
        );
        continue;
      }
      const id = stableId(target.ruleId, field.location, item.code);
      if (target.findings.some((finding) => finding.id === id)) continue;
      if (target.findings.length >= 128) {
        addDiagnostic(target, "native_finding_limit", null);
        continue;
      }
      const finding: Finding = {
        id,
        ruleId: target.ruleId,
        category: target.category,
        severity:
          mode.mode === "nlp" || target.category === "output"
            ? "medium"
            : "high",
        claim: "candidate",
        location: field.location,
        evidence: [{ code: item.code, location: field.location }],
        assumptions: [
          "static_definition_only",
          "candidate_not_verified",
          mode.mode === "nlp"
            ? "english_model_only"
            : "bounded_python_ast_only",
        ],
        remediation: {
          code:
            mode.mode === "nlp"
              ? "review_and_minimize_personal_data"
              : "review_code_permissions_and_data",
          checks: [
            "review_original_field_privately",
            "preserve_required_behavior",
            "rescan_changed_file",
          ],
        },
      };
      if (mode.mode === "nlp" && nativeNlpScope(field) === "program") {
        finding.evidence.push({
          code: "format_candidate_in_program_text",
          location: field.location,
        });
        finding.assumptions.push("program_text_is_not_runtime_output");
      }
      target.findings.push(finding);
    }
    for (const target of rules) {
      const applicable =
        mode.mode === "nlp" ||
        fieldsFor(context, "python").length > 0 ||
        mode.status === "error";
      target.coverage.push({
        location: root,
        status: target.diagnostics.length
          ? "partial"
          : applicable
            ? "checked"
            : "not_applicable",
        findingIds: target.findings.map(({ id }) => id),
        diagnosticIds: target.diagnostics.map(({ id }) => id),
      });
      results.push(target);
    }
  }
  return results;
}
