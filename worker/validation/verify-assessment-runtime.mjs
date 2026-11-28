import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir, readdir } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  runAssessment,
  sandboxArguments,
} from "../dist/runtime/assessment-runner.js";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { createContext } from "../dist/workflow/static-context.js";
import {
  applyRemediation,
  compareDefinitions,
} from "../dist/assessment/assessment-change.js";
import { compareStatic } from "../dist/analysis/static-compare.js";

const docker = process.env.WORKER_DOCKER_PATH;
const image = process.env.WORKER_ASSESSMENT_IMAGE;
assert.ok(
  docker && isAbsolute(docker),
  "Set WORKER_DOCKER_PATH to the trusted Docker executable",
);
assert.match(image ?? "", /^sha256:[a-f0-9]{64}$/);
const options = { dockerExecutable: docker, image };
const hash = (value) => createHash("sha256").update(value).digest("hex");
const bytes = (value) => Buffer.from(JSON.stringify(value));
const node = (id, type, typeVersion, parameters = {}) => ({
  id,
  name: id,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const document = (...nodes) => ({ nodes, connections: {} });
const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((node, index) => [
        node.name,
        { main: [[{ node: nodes[index + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});
function execute(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(docker, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const output = [],
      errors = [];
    let size = 0;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(Error("validation_docker_timeout"));
    }, 20_000);
    child.stdout.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) child.kill("SIGKILL");
      else output.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) child.kill("SIGKILL");
      else errors.push(chunk);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(output).toString(),
        stderr: Buffer.concat(errors).toString(),
      });
    });
  });
}
const beforeContainers = await execute([
  "ps",
  "--all",
  "--filter",
  "name=worker-assess-",
  "--format",
  "{{.Names}}",
]);
assert.equal(beforeContainers.code, 0);
const probeName = `worker-assess-${randomUUID()}`;
const args = sandboxArguments(image, probeName);
args.splice(args.length - 1, 0, "--entrypoint=node");
// This is our own fixed probe program, not a workflow or uploaded Code node.
args.push(
  "--input-type=module",
  "-e",
  `
import fs from 'node:fs'; import net from 'node:net'; import crypto from 'node:crypto';
const read = (file) => fs.readFileSync(file,'utf8').trim();
let rootWriteDenied = false;
try { fs.writeFileSync('/opt/worker/isolation-probe','test'); } catch(e) { rootWriteDenied = ['EROFS','EACCES'].includes(e.code); }
const networkFailure = await new Promise(resolve => { const socket = net.connect({host:'198.51.100.1',port:9}); socket.setTimeout(1200,()=>{socket.destroy();resolve('timeout')}); socket.on('error',e=>resolve(e.code)); socket.on('connect',()=>{socket.destroy();resolve('connected')}); });
const artifactPaths = [...fs.readdirSync('/opt/worker/dist',{recursive:true}).filter(name=>name.endsWith('.js')).map(name=>'dist/'+name),'tools/native-inspection.py','package-lock.json'];
const artifactHashes = Object.fromEntries(artifactPaths.map(path=>[path,crypto.createHash('sha256').update(fs.readFileSync('/opt/worker/'+path)).digest('hex')]));
console.log(JSON.stringify({uid:process.getuid(),interfaces:fs.readdirSync('/sys/class/net').sort(),rootWriteDenied,networkFailure,memory:read('/sys/fs/cgroup/memory.max'),pids:read('/sys/fs/cgroup/pids.max'),cpu:read('/sys/fs/cgroup/cpu.max'),noNewPrivileges:/NoNewPrivs:\\s+1/.test(read('/proc/self/status')),noCapabilities:/CapEff:\\s+0+/.test(read('/proc/self/status')),artifactHashes}));
`,
);
let probe;
try {
  const executed = await execute(args);
  assert.equal(executed.code, 0, "isolation probe process failed");
  probe = JSON.parse(executed.stdout);
} finally {
  await execute(["rm", "--force", probeName]);
}
assert.equal(probe.uid, 65532);
assert.deepEqual(probe.interfaces, ["lo"]);
assert.equal(probe.rootWriteDenied, true);
assert.equal(probe.networkFailure, "ENETUNREACH");
assert.equal(probe.memory, "1073741824");
assert.equal(probe.pids, "96");
assert.equal(probe.cpu, "100000 100000");
assert.equal(probe.noNewPrivileges, true);
assert.equal(probe.noCapabilities, true);
const expectedArtifactPaths = [
  ...(await readdir("dist", { recursive: true }))
    .map((name) => name.replaceAll("\\", "/"))
    .filter((name) => name.endsWith(".js"))
    .map((name) => `dist/${name}`),
  "tools/native-inspection.py",
  "package-lock.json",
].sort();
assert.deepEqual(
  Object.keys(probe.artifactHashes).sort(),
  expectedArtifactPaths,
  "Image artifact inventory differs from current build",
);
for (const [path, digest] of Object.entries(probe.artifactHashes))
  assert.equal(
    hash(await readFile(path)),
    digest,
    `Stale image artifact: ${path}`,
  );

const reports = [];
async function assess(id, input, evidence) {
  const report = await runAssessment(
    input,
    evidence && bytes(evidence),
    options,
  );
  assert.notEqual(report.status, "error", `${id}: ${JSON.stringify(report)}`);
  assert.equal(assessmentReportSchema.safeParse(report).success, true);
  assert.equal(report.inputSha256, hash(input));
  assert.equal(report.boundary.kind, "docker");
  for (const file of report.files) {
    assert.equal(
      file.tools.gitleaks.status,
      "completed",
      `${id}: Gitleaks failure`,
    );
    assert.equal(file.tools.native.modes.length, 2);
    assert.ok(
      file.tools.native.modes.every((mode) => mode.status === "completed"),
      `${id}: native failure`,
    );
  }
  reports.push({ id, inputSha256: hash(input), report });
  return report;
}
const alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const token =
  "ghp_" +
  Array.from(
    { length: 36 },
    (_, i) => alphabet[(i * 7 + 3) % alphabet.length],
  ).join("");
const nativeInput = bytes({
  ...document(
    node("Python", "code", 2, {
      language: "pythonNative",
      pythonCode:
        "import os\ncommand = _json['command']\nos.system(command)\nraise RuntimeError('must never execute')",
    }),
    {
      ...node("PythonTool", "toolCode", 1.3, {
        language: "python",
        pythonCode:
          "import os\nos.system(_query)\nraise RuntimeError('must never execute')",
      }),
      type: "@n8n/n8n-nodes-langchain.toolCode",
    },
  ),
  notes: `John Smith lives in London. Credential: ${token}`,
});
const native = await assess("native_content_and_python", nativeInput);
assert.ok(native.files[0].tools.gitleaks.findings.length > 0);
assert.ok(
  native.files[0].tools.native.modes[0].findings.some(
    (item) => item.code === "nlp_person_candidate",
  ),
);
assert.ok(
  native.files[0].tools.native.modes[1].findings.some(
    (item) => item.code === "python_external_input_shell_call",
  ),
);
assert.ok(!JSON.stringify(native).includes(token));
assert.ok(!JSON.stringify(native).includes("John Smith"));
assert.ok(
  native.files[0].extensionRules
    .find((r) => r.ruleId === "PYTHON_STATIC_CAPABILITIES")
    .findings.some(
      (f) =>
        f.location.pointer === "/nodes/1/parameters/pythonCode" &&
        f.evidence.some((e) => e.code === "python_external_input_shell_call"),
    ),
);

const flowInput = bytes(
  chain(
    node("Input", "webhook", 2.1),
    node("Map", "set", 3.4, {
      assignments: {
        assignments: [
          {
            id: "a",
            name: "payload",
            value: "={{ $json.body.private }}",
            type: "string",
          },
        ],
      },
      includeOtherFields: false,
      options: {},
    }),
    node("Mail", "emailSend", 2.1, {
      resource: "email",
      operation: "send",
      toEmail: "ops@example.invalid",
      fromEmail: "sender@example.invalid",
      subject: "Status",
      emailFormat: "text",
      text: "={{ $json.payload }}",
      options: {},
    }),
  ),
);
const context = createContext(flowInput);
const now = "2026-11-22T00:00:00.000Z";
const flowEvidence = {
  schemaVersion: "1.0.0",
  inputSha256: hash(flowInput),
  sources: [
    {
      id: "test",
      kind: "declaration",
      method: "user_declaration",
      recordedAt: now,
    },
  ],
  classifications: [
    {
      nodeKey: context.nodes[0].key,
      field: "body.private",
      dataClass: "secret",
      sourceId: "test",
    },
  ],
  policy: {
    id: "test-policy",
    version: "1",
    sourceId: "test",
    purpose: "synthetic policy validation",
    defaultDecision: "review",
    unknownDecision: "inconclusive",
    rules: [],
    egress: [
      {
        id: "mail-rule",
        nodeKey: context.nodes[2].key,
        sink: "email",
        mode: "allowlist",
        destinations: ["ops@example.invalid"],
        allowedDataClasses: ["public"],
        purpose: "synthetic public messages only",
      },
    ],
  },
  packages: [
    {
      name: "synthetic-node",
      version: "1.0.0",
      nodeKeys: [context.nodes[2].key],
      sourceId: "test",
    },
  ],
  advisories: [
    {
      sourceId: "test",
      document: {
        id: "SYNTHETIC-ONLY-1",
        modified: now,
        affected: [
          {
            package: { ecosystem: "npm", name: "synthetic-node" },
            ranges: [
              {
                type: "SEMVER",
                events: [{ introduced: "0" }, { fixed: "1.1.0" }],
              },
            ],
          },
        ],
      },
    },
  ],
};
const flow = await assess(
  "mapped_sensitive_mail_and_package_policy",
  flowInput,
  flowEvidence,
);
assert.equal(flow.decision, "block");
assert.ok(
  flow.files[0].extensionRules.find(
    (rule) => rule.ruleId === "N8N_EXTENDED_OUTBOUND_DATA",
  ).findings.length > 0,
);
assert.ok(
  flow.files[0].dependencies.some((item) => item.status === "affected"),
);
assert.equal(flow.files[0].evidence.independentlyVerified, false);

const mappedSheet = await assess(
  "bounded_code_to_sheet",
  bytes(
    chain(
      node("Input", "webhook", 2),
      node("Map", "code", 2, {
        jsCode:
          "let data={}; data.email=$json.body.email; return [{json:data}];",
      }),
      node("Sheet", "googleSheets", 4.6, {
        operation: "append",
        documentId: { __rl: true, mode: "id", value: "synthetic-sheet" },
        sheetName: { __rl: true, mode: "id", value: "0" },
        columns: {
          mappingMode: "defineBelow",
          value: { email: "={{ $json.email }}" },
        },
        options: {},
      }),
    ),
  ),
);
assert.ok(
  mappedSheet.files[0].extensionRules
    .find((r) => r.ruleId === "N8N_EXTENDED_OUTBOUND_DATA")
    .findings.some((f) =>
      f.evidence.some((e) => e.code === "personal_data_candidate_transferred"),
    ),
);

const aiSource = node("Prompt", "webhook", 2);
const agentNode = {
  ...node("Agent", "agent", 2.2, {
    promptType: "define",
    text: "={{ $json.body.email }}",
    options: { passthroughBinaryImages: false },
  }),
  type: "@n8n/n8n-nodes-langchain.agent",
};
const modelNode = {
  ...node("Model", "lmChatOpenAi", 1.2, {
    model: { value: "synthetic-model" },
    options: {},
  }),
  type: "@n8n/n8n-nodes-langchain.lmChatOpenAi",
};
const toolNode = node("Tool", "httpRequestTool", 4.2, {
  url: "={{ $fromAI('url') }}",
});
const ai = await assess(
  "prompt_model_and_tool_contracts",
  bytes({
    nodes: [aiSource, agentNode, modelNode, toolNode],
    connections: {
      Prompt: { main: [[{ node: "Agent", type: "main", index: 0 }]] },
      Model: {
        ai_languageModel: [
          [{ node: "Agent", type: "ai_languageModel", index: 0 }],
        ],
      },
      Tool: { ai_tool: [[{ node: "Agent", type: "ai_tool", index: 0 }]] },
    },
  }),
);
const aiPrompt = ai.files[0].extensionRules.find(
  (r) => r.ruleId === "N8N_AI_PROMPT_DATA",
);
assert.ok(
  aiPrompt.findings.some((f) =>
    f.evidence.some((e) => e.code === "ai_prompt_to_model_pii_candidate"),
  ),
);
assert.ok(
  aiPrompt.findings.some((f) =>
    f.evidence.some(
      (e) => e.code === "ai_external_prompt_may_influence_tool_selection",
    ),
  ),
);
assert.ok(
  aiPrompt.diagnostics.some(
    (d) => d.code === "ai_model_invocation_and_output_unverified",
  ),
);

const definedSql = await assess(
  "code_literal_sql_definition",
  bytes(
    chain(
      node("Query", "code", 2, {
        jsCode:
          'return [{json:{statement:"SELECT id FROM records WHERE id=$1"}}];',
      }),
      node("Database", "postgres", 2.8, {
        operation: "executeQuery",
        query: "={{ $json.statement }}",
        options: { queryReplacement: ["synthetic"] },
      }),
    ),
  ),
);
const definedQueryRule = definedSql.files[0].extensionRules.find(
  (r) => r.ruleId === "N8N_ADVANCED_SQL",
);
for (const code of [
  "sql_query_definition_resolved",
  "sql_operation_capability",
  "sql_value_binding_configured",
])
  assert.ok(
    definedQueryRule.findings.some((f) =>
      f.evidence.some((e) => e.code === code),
    ),
  );

const sqlInput = await readFile("fixtures/workflows/interpolated.json");
const original = await assess("sql_original", sqlInput);
const plan = original.files[0].remediation.find(
  (item) => item.kind === "bind_postgres_lookup_value" && item.automatic,
);
assert.ok(plan);
const revisedBytes = applyRemediation(sqlInput, plan);
const revised = await assess("sql_repaired", revisedBytes);
const comparison = compareStatic(original.files[0].base, revised.files[0].base);
const semanticComparison = compareDefinitions(sqlInput, revisedBytes);
assert.ok(
  original.files[0].base.rules.some(
    (rule) => rule.category === "sql" && rule.findings.length,
  ),
);
assert.ok(
  !revised.files[0].base.rules.some(
    (rule) => rule.category === "sql" && rule.findings.length,
  ),
);
assert.equal(semanticComparison.behaviorPreserved, "not_verified");

const child = bytes(
  document(
    node("ChildHTTP", "httpRequest", 4.2, { url: "http://example.invalid" }),
  ),
);
const parent = bytes(
  document(
    node("Call", "executeWorkflow", 1.4, {
      source: "parameter",
      workflowJson: child.toString(),
    }),
  ),
);
const subworkflow = await assess("inline_child_definition", parent);
assert.equal(subworkflow.files.length, 2);
assert.equal(subworkflow.subworkflows[0].status, "definition_analyzed");

const invalidEvidence = await runAssessment(
  sqlInput,
  bytes({ ...flowEvidence, inputSha256: hash(flowInput) }),
  options,
);
assert.equal(invalidEvidence.status, "error");
assert.equal(invalidEvidence.code, "evidence_input_mismatch");
const cancellation = new AbortController();
const cancelledPromise = runAssessment(nativeInput, undefined, {
  ...options,
  signal: cancellation.signal,
});
const cancelTimer = setTimeout(() => cancellation.abort(), 100);
const cancelled = await cancelledPromise;
clearTimeout(cancelTimer);
assert.equal(cancelled.code, "cancelled");
const runningCancellation = new AbortController();
const runningPromise = runAssessment(nativeInput, undefined, {
  ...options,
  signal: runningCancellation.signal,
});
let observedRunning = false;
try {
  const preexisting = new Set(beforeContainers.stdout.trim().split("\n"));
  for (let attempt = 0; attempt < 30; attempt++) {
    const running = await execute([
      "ps",
      "--filter",
      "name=worker-assess-",
      "--format",
      "{{.Names}}",
    ]);
    assert.equal(running.code, 0);
    if (
      running.stdout
        .trim()
        .split("\n")
        .some((name) => name && !preexisting.has(name))
    ) {
      observedRunning = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
} finally {
  runningCancellation.abort();
}
const cancelledRunning = await runningPromise;
assert.equal(
  observedRunning,
  true,
  "running-phase cancellation was not exercised",
);
assert.equal(cancelledRunning.code, "cancelled");
const timedOut = await runAssessment(nativeInput, undefined, {
  ...options,
  timeoutMs: 100,
});
assert.equal(timedOut.code, "assessment_timeout");
const afterContainers = await execute([
  "ps",
  "--all",
  "--filter",
  "name=worker-assess-",
  "--format",
  "{{.Names}}",
]);
assert.equal(afterContainers.code, 0);
assert.equal(
  afterContainers.stdout,
  beforeContainers.stdout,
  "assessment containers were not cleaned up",
);

const hashes = {};
for (const [path, digest] of Object.entries(probe.artifactHashes))
  assert.equal(
    hash(await readFile(path)),
    digest,
    `Artifact changed during verification: ${path}`,
  );
for (const file of [
  "dist/runtime/assessment-runner.js",
  "dist/assessment/assessment-engine.js",
  "dist/runtime/assessment-entry.js",
  "dist/assessment/assessment-change.js",
  "dist/workflow/value-flow.js",
  "dist/rules/advanced-risks.js",
  "dist/rules/extended-sinks.js",
  "tools/native-inspection.py",
  "package-lock.json",
  "Dockerfile.assessment",
  "Dockerfile.assessment-runtime",
  "tools/requirements-nlp.txt",
  "validation/verify-assessment-runtime.mjs",
])
  hashes[file] = hash(await readFile(file));
const result = {
  outcome: "passed",
  fixtureType: "synthetic_only",
  execution: "uploaded_workflows_not_executed",
  image,
  isolationProbe: probe,
  reports,
  comparison,
  semanticComparison,
  failureChecks: [
    invalidEvidence.code,
    cancelled.code,
    cancelledRunning.code,
    timedOut.code,
  ],
  cancellationPhases: ["early_request", "observed_running"],
  cleanup: "no_new_containers",
  sourceHashes: hashes,
  limitations: [
    "sidecar_declarations_not_independently_verified",
    "normal_behavior_requires_separate_synthetic_execution",
    "actual_team_api_not_tested",
    "no_overall_safety_verdict",
  ],
};
const output = resolve(
  process.env.WORKER_ASSESSMENT_VALIDATION_OUTPUT ??
    "validation/assessment-runtime-results.json",
);
await mkdir(dirname(output), { recursive: true });
await writeFile(output, JSON.stringify(result, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    outcome: result.outcome,
    assessmentCases: reports.length,
    analyzedFiles: reports.reduce(
      (sum, item) => sum + item.report.files.length,
      0,
    ),
    failureChecks: result.failureChecks.length,
    isolationChecks: 9,
    cleanup: result.cleanup,
  }) + "\n",
);
