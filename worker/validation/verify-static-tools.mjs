import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { runGitleaks } from "../dist/runtime/gitleaks.js";
import { createContext } from "../dist/workflow/static-context.js";
import { analyzeContent } from "../dist/rules/static-content.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";

const executable = process.env.WORKER_GITLEAKS_PATH;
assert.ok(
  executable && isAbsolute(executable),
  "Set WORKER_GITLEAKS_PATH to a trusted absolute Gitleaks 8.30.1 path",
);
const hash = (value) => createHash("sha256").update(value).digest("hex");
// Generated test-only token shape; no account, credential or workflow is used.
const alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const token =
  "ghp_" +
  Array.from(
    { length: 36 },
    (_, i) => alphabet[(i * 7 + 3) % alphabet.length],
  ).join("");
const samples = [
  {
    name: "clean",
    fields: [{ index: 0, value: "ordinary text" }],
    expected: [],
  },
  {
    name: "key_and_multiline",
    fields: [
      { index: 7, value: token },
      { index: 8, value: "line one\n" + token + "\nline three" },
    ],
    expected: [7, 8],
  },
  {
    name: "inline_allow_ignored",
    fields: [{ index: 2, value: 'token = "' + token + '" # gitleaks:allow' }],
    expected: [2],
  },
];
const results = [];
const priorConfig = process.env.GITLEAKS_CONFIG_TOML;
try {
  process.env.GITLEAKS_CONFIG_TOML = "[extend]\nuseDefault = false\n";
  for (const sample of samples) {
    const result = await runGitleaks(sample.fields, { executable });
    assert.equal(result.status, "completed", sample.name + ":" + result.reason);
    assert.deepEqual(
      result.findings.map(({ fieldIndex }) => fieldIndex).sort((a, b) => a - b),
      sample.expected,
    );
    assert.equal(JSON.stringify(result).includes(token), false);
    results.push({
      case: sample.name,
      inputSha256: hash(JSON.stringify(sample.fields)),
      status: result.status,
      findingCount: result.findings.length,
      fieldIndices: result.findings.map(({ fieldIndex }) => fieldIndex),
      redacted: true,
    });
  }
} finally {
  if (priorConfig === undefined) delete process.env.GITLEAKS_CONFIG_TOML;
  else process.env.GITLEAKS_CONFIG_TOML = priorConfig;
}

for (const [name, options, expected] of [
  ["output_limit", { executable, maxOutputBytes: 1 }, "tool_output_limit"],
  ["missing_tool", {}, "tool_unavailable"],
  ["cancelled", { executable, signal: AbortSignal.abort() }, "tool_cancelled"],
]) {
  const result = await runGitleaks([], options);
  assert.equal(result.status, "error");
  assert.equal(result.reason, expected);
  assert.deepEqual(result.findings, []);
  results.push({
    case: name,
    status: result.status,
    reason: result.reason,
    findingCount: 0,
  });
}

const workflow = {
  nodes: [
    {
      id: "synthetic-node",
      name: "Synthetic",
      type: "n8n-nodes-base.noOp",
      typeVersion: 1,
      parameters: { password: "synthetic-literal" },
    },
  ],
  connections: {},
  pinData: {
    Synthetic: [
      {
        json: {
          email: "person@example.invalid",
          phone: "010-1234-5678",
          card: "4111 1111 1111 1111",
        },
      },
    ],
  },
};
const ctx = createContext(Buffer.from(JSON.stringify(workflow)));
const tool = await runGitleaks(ctx.fields, { executable });
assert.equal(tool.status, "completed");
const content = analyzeContent(ctx, tool).map((rule) =>
  ruleResultSchema.parse(rule),
);
assert.ok(
  content[0].findings.some(
    (finding) => finding.evidence[0].code === "literal_credential_field",
  ),
);
const piiCodes = [
  ...new Set(content[1].findings.map((finding) => finding.evidence[0].code)),
].sort();
assert.deepEqual(piiCodes, [
  "email_candidate",
  "korean_mobile_candidate",
  "payment_card_candidate",
]);
for (const privateValue of [
  "synthetic-literal",
  "person@example.invalid",
  "010-1234-5678",
  "4111 1111 1111 1111",
])
  assert.equal(JSON.stringify(content).includes(privateValue), false);
results.push({
  case: "content_integration",
  inputSha256: hash(JSON.stringify(workflow)),
  status: "completed",
  literalCredentialDetected: true,
  piiCodes,
  redacted: true,
});

const report = {
  generatedAt: new Date().toISOString(),
  nodeVersion: process.version,
  gitleaksVersion: "8.30.1",
  gitleaksBinarySha256: hash(await readFile(executable)),
  validatorVersion: JSON.parse(
    await readFile(
      new URL("../node_modules/validator/package.json", import.meta.url),
      "utf8",
    ),
  ).version,
  scope: "synthetic_static_content_only",
  command:
    "WORKER_GITLEAKS_PATH=<trusted path> node validation/verify-static-tools.mjs [report path]",
  toolArguments: [
    "stdin",
    "--config",
    "<trusted temporary default config>",
    "--gitleaks-ignore-path",
    "<empty temporary ignore file>",
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
    "5",
  ],
  environmentConfigOverrideIgnored: true,
  results,
};
const output = resolve(
  process.argv[2] ?? "evidence-local/static-tool-results.json",
);
await mkdir(dirname(output), { recursive: true });
await writeFile(output, JSON.stringify(report, null, 2) + "\n");
console.log(
  JSON.stringify({
    cases: results.length,
    passed: results.length,
    gitleaksVersion: report.gitleaksVersion,
    validatorVersion: report.validatorVersion,
  }),
);
