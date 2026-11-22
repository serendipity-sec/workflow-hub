import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { createContext } from "../dist/static-context.js";
import { runAssessment } from "../dist/assessment-runner.js";
import { assessmentReportSchema } from "../dist/assessment-contract.js";

// Entirely synthetic controls. They check an explicitly declared NLP scope,
// not general precision/recall or whether the fictional names identify people.
const notes = {
  person: "John Smith lives in London.",
  shortPerson: "Jo lives in London.",
  tiny: "Li",
  brands: "Use Gmail and Slack to send JSON to PostgreSQL.",
  bracketed: "[John Smith lives in London]",
  template: "Hello John Smith, {{ $json.user }}",
  negative: "The status is complete and the total is forty.",
  contextSensitive: "Li lives in London.",
};
const input = Buffer.from(
  JSON.stringify({
    nodes: [
      {
        id: "00000000-0000-4000-8000-000000000001",
        name: "Gmail",
        type: "n8n-nodes-base.code",
        typeVersion: 2,
        parameters: {
          jsCode:
            'const customer = "John Smith"; const email = "synthetic@example.com";',
          specifyBody: "json",
          jsonBody: JSON.stringify({ name: "John Smith", city: "London" }),
        },
      },
    ],
    connections: {},
    notes,
    pinData: {
      source: [
        {
          json: {
            name: "John Smith",
            shortName: "Li",
            email: "synthetic@example.com",
          },
        },
      ],
    },
  }),
);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const context = createContext(input);
const report = assessmentReportSchema.parse(
  await runAssessment(input, undefined, {
    dockerExecutable: process.env.WORKER_DOCKER_PATH,
    image: process.env.WORKER_ASSESSMENT_IMAGE,
  }),
);
assert.notEqual(report.status, "error", JSON.stringify(report));
assert.equal(report.inputSha256, hash(input));
assert.equal(report.boundary.kind, "docker");
assert.equal(report.execution, "not_run");
const nlp = report.files[0].tools.native.modes.find(
  (mode) => mode.mode === "nlp",
);
assert.equal(nlp.status, "completed");
const matches = nlp.findings.map((item) => ({
  pointer: context.fields[item.fieldIndex].pointer,
  code: item.code,
}));
const has = (pointer, code) =>
  matches.some((item) => item.pointer === pointer && item.code === code);
let assertions = 0;
for (const pointer of [
  "/notes/person",
  "/notes/shortPerson",
  "/notes/tiny",
  "/notes/bracketed",
  "/notes/template",
  "/nodes/0/parameters/jsonBody",
  "/pinData/source/0/json/name",
  "/pinData/source/0/json/shortName",
]) {
  assert.ok(has(pointer, "nlp_person_candidate"), pointer);
  assertions++;
}
assert.ok(has("/notes/person", "nlp_location_candidate"));
assertions++;
for (const pointer of [
  "/nodes/0/id",
  "/nodes/0/type",
  "/nodes/0/name",
  "/nodes/0/parameters/specifyBody",
  "/notes/brands",
  "/notes/negative",
]) {
  assert.equal(
    matches.some((item) => item.pointer === pointer),
    false,
    pointer,
  );
  assertions++;
}
assert.equal(has("/nodes/0/parameters/jsCode", "nlp_person_candidate"), false);
assertions++;
for (const pointer of [
  "/nodes/0/parameters/jsCode",
  "/pinData/source/0/json/email",
]) {
  assert.ok(has(pointer, "nlp_email_candidate"));
  assertions++;
}
const output = {
  outcome: "passed",
  fixtureType: "synthetic_only",
  inputSha256: hash(input),
  image: process.env.WORKER_ASSESSMENT_IMAGE,
  engineVersion: report.engineVersion,
  workflowExecution: report.execution,
  versions: nlp.versions,
  assertions,
  contextSensitiveShortNameObserved: has(
    "/notes/contextSensitive",
    "nlp_person_candidate",
  ),
  limitations: [
    "english_model_context_sensitive",
    "no_general_recall_claim",
    "named_entities_in_code_not_analyzed",
    "format_candidates_in_code_retained",
  ],
  matches,
  diagnostics: nlp.diagnostics.map((item) => item.code),
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
};
const target = resolve(
  process.argv[2] ?? "evidence-local/native-profile-results.json",
);
await mkdir(dirname(target), { recursive: true });
await writeFile(target, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    outcome: output.outcome,
    assertions,
    contextSensitiveShortNameObserved: output.contextSensitiveShortNameObserved,
  }) + "\n",
);
