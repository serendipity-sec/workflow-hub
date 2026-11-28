import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { createContext } from "../dist/workflow/static-context.js";
import {
  analyzeNativeInspection,
  runNativeInspection,
} from "../dist/runtime/native-inspection.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";

const executable = process.env.WORKER_PYTHON_PATH;
assert.ok(
  executable && isAbsolute(executable),
  "Set WORKER_PYTHON_PATH to the trusted Python environment",
);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const marker = resolve("evidence-local/native-inspection-must-not-execute.txt");
await assert.rejects(stat(marker), { code: "ENOENT" });
const person = ["John", "Smith"].join(" ");
const city = ["Lon", "don"].join("");
const positive = `${person} lives in ${city}. Contact person@example.invalid.`;
const negative = "The status is complete and the total is forty.";
const formats =
  "Email: person@example.com. Payment card: " +
  [4111, 1111, 1111, 1111].join(" ");
const sources = [
  [
    "positive",
    "import os as operating\nfrom subprocess import run as launch\nimport requests as network\ncommand = _json['command']\nlaunch(command, shell=True)\noperating.system(command)\nrunner = eval\nrunner(_json['code'])\nnetwork.post(_json['url'], data=_items)\nprint(_items)\nopen(" +
      JSON.stringify(marker) +
      ", 'w').write('must never run')",
  ],
  [
    "negative",
    "# os.system(_json['command'])\ntext = \"eval(_json['code'])\"\nvalue = 1 + 2",
  ],
  [
    "literal",
    "import subprocess\nsubprocess.run(['echo', 'synthetic'], shell=False)",
  ],
  ["invalid", "def broken(:"],
];
const bytes = Buffer.from(
  JSON.stringify({
    nodes: sources.map(([id, source]) => ({
      id,
      name: id,
      type: "n8n-nodes-base.code",
      typeVersion: 2,
      parameters: { language: "pythonNative", pythonCode: source },
    })),
    connections: {},
    notes: {
      positive,
      negative,
      formats,
      unsupportedLanguage: "홍길동의 주소는 서울입니다.",
    },
  }),
);
const context = createContext(bytes);
const scan = await runNativeInspection(context, {
  pythonExecutable: executable,
});
assert.ok(
  scan.modes.every((mode) => mode.status === "completed"),
  JSON.stringify(
    scan.modes.map(({ mode, status, diagnostics }) => ({
      mode,
      status,
      diagnostics,
    })),
  ),
);
const nlp = scan.modes.find((mode) => mode.mode === "nlp");
const python = scan.modes.find((mode) => mode.mode === "python");
const indexFor = (value) =>
  context.fields.find(
    (field) => field.kind === "value" && field.value === value,
  ).index;
const positiveCodes = nlp.findings
  .filter((item) => item.fieldIndex === indexFor(positive))
  .map((item) => item.code);
assert.ok(positiveCodes.includes("nlp_person_candidate"));
assert.ok(positiveCodes.includes("nlp_location_candidate"));
const formatCodes = nlp.findings
  .filter((item) => item.fieldIndex === indexFor(formats))
  .map((item) => item.code);
assert.ok(formatCodes.includes("nlp_email_candidate"));
assert.ok(formatCodes.includes("nlp_payment_card_candidate"));
assert.equal(
  nlp.findings.some((item) => item.fieldIndex === indexFor(negative)),
  false,
);
assert.ok(
  nlp.diagnostics.some((item) => item.code === "nlp_language_outside_profile"),
);
const pythonCodes = python.findings
  .filter((item) => item.fieldIndex === indexFor(sources[0][1]))
  .map((item) => item.code);
for (const code of [
  "python_external_input_shell_call",
  "python_external_input_evaluation",
  "python_external_input_request_call",
  "python_external_input_log_call",
  "python_file_access_call",
])
  assert.ok(pythonCodes.includes(code), code);
assert.equal(
  python.findings.some((item) => item.fieldIndex === indexFor(sources[1][1])),
  false,
);
assert.equal(
  python.findings.some(
    (item) =>
      item.fieldIndex === indexFor(sources[2][1]) &&
      item.code.includes("external_input"),
  ),
  false,
);
assert.ok(
  python.diagnostics.some((item) => item.code === "python_parse_unavailable"),
);
await assert.rejects(stat(marker), { code: "ENOENT" });
const rules = analyzeNativeInspection(context, scan).map((rule) =>
  ruleResultSchema.parse(rule),
);
for (const raw of [
  person,
  city,
  "person@example.invalid",
  marker,
  sources[0][1],
])
  assert.equal(JSON.stringify({ scan, rules }).includes(raw), false);
const errors = [];
for (const [name, options, expected] of [
  ["absent", {}, "native_tool_unavailable"],
  [
    "cancelled",
    { pythonExecutable: executable, signal: AbortSignal.abort() },
    "native_cancelled",
  ],
  [
    "output_limit",
    { pythonExecutable: executable, maxOutputBytes: 1 },
    "native_output_limit",
  ],
  ["timeout", { pythonExecutable: executable, timeoutMs: 1 }, "native_timeout"],
]) {
  const result = await runNativeInspection(context, {
    ...options,
    modes: ["python"],
  });
  assert.equal(result.modes[0].status, "error");
  assert.equal(result.modes[0].diagnostics[0].code, expected);
  errors.push({ case: name, status: "error", code: expected });
}
const report = {
  generatedAt: new Date().toISOString(),
  scope: "synthetic_native_inspection_only",
  execution: "not_run",
  nodeVersion: process.version,
  platform: process.platform,
  helperSha256: hash(
    await readFile(new URL("../tools/native-inspection.py", import.meta.url)),
  ),
  controllerSha256: hash(
    await readFile(
      new URL("../dist/runtime/native-inspection.js", import.meta.url),
    ),
  ),
  pythonExecutableSha256: hash(await readFile(executable)),
  inputSha256: hash(bytes),
  command:
    "WORKER_PYTHON_PATH=<trusted path> node validation/verify-native-inspection.mjs [report path]",
  arguments: ["-I", "-B", "<trusted helper>", "nlp|python"],
  limits: {
    inputBytes: 2097152,
    outputBytes: 262144,
    timeoutMsPerMode: 60000,
    nlpTotalChars: 262144,
    nlpFieldChars: 16384,
    pythonSourceChars: 65536,
    pythonAstNodes: 10000,
  },
  modes: scan.modes.map(
    ({ mode, status, versions, findings, diagnostics }) => ({
      mode,
      status,
      versions,
      findingCount: findings.length,
      findingCodes: [...new Set(findings.map((item) => item.code))].sort(),
      diagnosticCodes: [
        ...new Set(diagnostics.map((item) => item.code)),
      ].sort(),
    }),
  ),
  assertions: {
    englishPersonAndLocationCandidates: true,
    emailAndPaymentCardCandidates: true,
    negativeTextNoCandidates: true,
    unsupportedLanguageExplicit: true,
    pythonAliasesAndExternalInput: true,
    commentsAndStringsNotCalls: true,
    constantProcessNotInputInjection: true,
    invalidPythonPartial: true,
    workflowCodeNotExecuted: true,
    rawValuesAbsent: true,
  },
  errors,
};
const output = resolve(
  process.argv[2] ?? "evidence-local/native-inspection-results.json",
);
await mkdir(dirname(output), { recursive: true });
await writeFile(output, JSON.stringify(report, null, 2) + "\n");
console.log(
  JSON.stringify({
    completedModes: report.modes.length,
    assertions: Object.keys(report.assertions).length,
    errorCases: errors.length,
    execution: "not_run",
  }),
);
