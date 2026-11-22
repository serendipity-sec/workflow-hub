import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { createContext } from "../dist/static-context.js";
import { runAssessment, sandboxArguments } from "../dist/assessment-runner.js";
import { nativeModeResultSchema } from "../dist/native-inspection.js";
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
  longText:
    " ".repeat(16380) +
    "John Smith lives in London." +
    " ".repeat(17000) +
    "John Smith lives in London.",
};
const email = "synthetic@example.com";
const longProgram = " ".repeat(16380) + email + " ".repeat(17000) + email;
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
          command: 'printf "%s" "John Smith" "synthetic@example.com"',
          jsonBody: JSON.stringify({ name: "John Smith", city: "London" }),
        },
      },
      {
        id: "long-program",
        name: "synthetic@example.com",
        type: "n8n-nodes-base.code",
        typeVersion: 2,
        parameters: { jsCode: longProgram },
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
  start: item.start,
  end: item.end,
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
const baselineAssertions = assertions;
const check = (condition, message) => {
  assert.ok(condition, message);
  assertions++;
};
const longCodePointer = "/nodes/1/parameters/jsCode";
check(
  matches.some(
    (item) =>
      item.pointer === longCodePointer &&
      item.code === "nlp_email_candidate" &&
      item.start === 16380 &&
      item.end === 16380 + email.length,
  ),
  "format at chunk boundary",
);
check(
  matches.some(
    (item) =>
      item.pointer === longCodePointer &&
      item.code === "nlp_email_candidate" &&
      item.end === longProgram.length,
  ),
  "format at long-field tail",
);
check(
  !has(longCodePointer, "nlp_person_candidate"),
  "program NER remains out of scope",
);
check(
  matches.some(
    (item) =>
      item.pointer === "/notes/longText" &&
      item.code === "nlp_person_candidate" &&
      item.start === 16380 &&
      item.end === 16390,
  ),
  "person at chunk boundary",
);
check(
  matches.some(
    (item) =>
      item.pointer === "/notes/longText" &&
      item.code === "nlp_person_candidate" &&
      item.start === notes.longText.lastIndexOf("John Smith") &&
      item.end === notes.longText.lastIndexOf("John Smith") + 10,
  ),
  "person at long-field tail",
);
check(
  nlp.diagnostics.some((item) => item.code === "nlp_chunked_text_profile"),
  "chunked coverage disclosed",
);
check(
  !nlp.diagnostics.some(
    (item) =>
      item.code === "native_field_size_limit" ||
      item.code === "native_input_scope_limit",
  ),
  "bounded long fields covered within total budget",
);
check(
  has("/nodes/0/parameters/command", "nlp_email_candidate"),
  "command literal format retained",
);
check(
  !has("/nodes/0/parameters/command", "nlp_person_candidate"),
  "command syntax not treated as names",
);
check(has("/nodes/1/name", "nlp_email_candidate"), "metadata format retained");
check(
  !has("/nodes/1/name", "nlp_person_candidate"),
  "metadata not treated as names",
);
const longTextAssertions = assertions - baselineAssertions;

// The assessment file cap is 256 KiB, so its native 262,144-character budget
// cannot normally be exceeded by a valid file. Exercise that helper boundary
// separately in the SAME immutable image and sandbox, with fixed synthetic
// values only. This is trusted test code, never uploaded workflow execution.
const limitControl = `
import { createHash } from 'node:crypto';
import { runNativeInspection, analyzeNativeInspection } from './dist/native-inspection.js';
import { createContext } from './dist/static-context.js';
const template = createContext(Buffer.from(JSON.stringify({nodes:[{id:'fixture',name:'fixture',type:'n8n-nodes-base.code',typeVersion:2,parameters:{}}],connections:{}})));
const cases = {};
for (const [name, values] of Object.entries({single:[' '.repeat(262145)+'synthetic@example.com'],aggregate:[' '.repeat(140000)+'synthetic@example.com',' '.repeat(140000)+'synthetic@example.com']})) {
  const context = {...template, fields:values.map((value,index)=>({index,kind:'value',value,pointer:'/notes/'+index,location:{nodeKey:null,pointer:''}}))};
  const native = await runNativeInspection(context,{pythonExecutable:'/opt/nlp/bin/python',modes:['nlp']});
  cases[name] = {inputSha256:createHash('sha256').update(JSON.stringify(values)).digest('hex'),fieldCharacters:values.map(value=>value.length),totalCharacters:values.reduce((sum,value)=>sum+value.length,0),mode:native.modes[0],coverage:analyzeNativeInspection(context,native)[0].coverage[0].status};
}
process.stdout.write(JSON.stringify(cases));
`;
const docker = process.env.WORKER_DOCKER_PATH;
assert.ok(
  docker && isAbsolute(docker),
  "absolute trusted Docker executable required",
);
const containerName = `worker-assess-${randomUUID()}`;
const createArgs = sandboxArguments(
  process.env.WORKER_ASSESSMENT_IMAGE,
  containerName,
);
createArgs[0] = "create";
createArgs.splice(createArgs.length - 1, 0, "--entrypoint=node");
createArgs.push("--input-type=module", "--eval", limitControl);
const environment = Object.fromEntries(
  [
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
  ]
    .filter((key) => process.env[key])
    .map((key) => [key, process.env[key]]),
);
const invoke = (args, timeout) =>
  execFileSync(docker, args, {
    env: environment,
    windowsHide: true,
    timeout,
    killSignal: "SIGKILL",
    maxBuffer: 256 * 1024,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
let limitCases;
let cleanupVerified = false;
try {
  assert.match(invoke(createArgs, 10000).trim(), /^[a-f0-9]{64}$/);
  limitCases = JSON.parse(
    invoke(["start", "--attach", "--interactive", containerName], 60000),
  );
} finally {
  try {
    invoke(["rm", "--force", containerName], 10000);
    cleanupVerified = true;
  } catch (error) {
    cleanupVerified =
      error.status === 1 &&
      String(error.stderr).trim() ===
        `Error response from daemon: No such container: ${containerName}`;
  }
  assert.equal(
    cleanupVerified,
    true,
    "native limit container cleanup required",
  );
}
for (const name of ["single", "aggregate"]) {
  const item = limitCases[name];
  item.mode = nativeModeResultSchema.parse(item.mode);
  check(item.mode.status === "completed", `${name}: native tool completed`);
  check(item.totalCharacters > 262144, `${name}: total budget exceeded`);
  check(
    item.mode.diagnostics.some(
      (diagnostic) => diagnostic.code === "native_input_scope_limit",
    ),
    `${name}: omitted scope disclosed`,
  );
  check(item.coverage === "partial", `${name}: omission cannot become clean`);
  check(
    JSON.stringify(item.mode.versions) === JSON.stringify(nlp.versions),
    `${name}: same native dependencies`,
  );
}
check(
  limitCases.single.mode.findings.length === 0,
  "oversized field omitted with diagnosis",
);
check(
  limitCases.aggregate.fieldCharacters.every((size) => size < 262144),
  "aggregate tests total budget rather than single field size",
);
check(
  limitCases.aggregate.mode.findings.some(
    (item) =>
      item.fieldIndex === 0 &&
      item.code === "nlp_email_candidate" &&
      item.end === limitCases.aggregate.fieldCharacters[0],
  ),
  "first aggregate field tail retained",
);
check(
  !limitCases.aggregate.mode.findings.some((item) => item.fieldIndex === 1),
  "over-budget second field omitted with diagnosis",
);
check(cleanupVerified, "temporary native limit container cleaned");
const output = {
  outcome: "passed",
  fixtureType: "synthetic_only",
  inputSha256: hash(input),
  image: process.env.WORKER_ASSESSMENT_IMAGE,
  engineVersion: report.engineVersion,
  workflowExecution: report.execution,
  versions: nlp.versions,
  assertions,
  assertionGroups: {
    baseline: baselineAssertions,
    longTextAndScopes: longTextAssertions,
    nativeBudget: assertions - baselineAssertions - longTextAssertions,
  },
  inputBytes: input.length,
  totalFieldCharacters: context.fields.reduce(
    (sum, field) => sum + field.value.length,
    0,
  ),
  longFieldCharacters: {
    program: longProgram.length,
    prose: notes.longText.length,
  },
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
  nativeBudgetControls: {
    boundary: "same_immutable_image_sandbox_fixed_synthetic_helper_calls",
    image: process.env.WORKER_ASSESSMENT_IMAGE,
    cleanupVerified,
    controlScriptSha256: hash(limitControl),
    cases: limitCases,
  },
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
};
const target = resolve(
  process.argv[2] ?? "evidence-local/native-profile-results.json",
);
await mkdir(dirname(target), { recursive: true });
const rawReportTarget = target + ".assessment.raw.json";
await writeFile(rawReportTarget, JSON.stringify(report, null, 2) + "\n");
output.rawAssessmentSha256 = hash(await readFile(rawReportTarget));
await writeFile(target, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    outcome: output.outcome,
    assertions,
    assertionGroups: output.assertionGroups,
    contextSensitiveShortNameObserved: output.contextSensitiveShortNameObserved,
  }) + "\n",
);
