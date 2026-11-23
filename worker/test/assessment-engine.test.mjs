import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { assessBytes } from "../dist/assessment-engine.js";
import { assessmentReportSchema } from "../dist/assessment-contract.js";
import {
  planSubworkflows,
  evidenceForInput,
} from "../dist/assessment-subworkflows.js";
import { parseEvidence } from "../dist/assessment-evidence.js";
import { createContext } from "../dist/static-context.js";
import { runAssessment, sandboxArguments } from "../dist/assessment-runner.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const bytes = (value) => Buffer.from(JSON.stringify(value));
const node = (name, type, typeVersion = 1, parameters = {}) => ({
  id: name,
  name,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const document = (...nodes) => ({ nodes, connections: {} });
const now = "2026-11-22T00:00:00.000Z";
const source = {
  id: "test",
  kind: "declaration",
  method: "user_declaration",
  recordedAt: now,
};
const sidecar = (input, extra = {}) => ({
  schemaVersion: "1.0.0",
  inputSha256: hash(input),
  sources: [source],
  ...extra,
});
// Only unit-level fixtures. Native execution is separately required by verify-assessment-runtime.mjs.
const tools = async () => ({
  gitleaks: {
    tool: "gitleaks",
    version: "8.30.1",
    status: "completed",
    findings: [],
  },
  native: {
    tool: "native_inspection",
    version: "1.0.0",
    modes: ["nlp", "python"].map((mode) => ({
      mode,
      status: "completed",
      findings: [],
      diagnostics: [],
      versions: {
        python: "3.12.10",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    })),
  },
});

test("ID-less workflow summaries preserve bytes and expose only structural facts", async () => {
  const start = node("SYNTHETIC_PRIVATE_TITLE", "manualTrigger");
  const sink = node("SYNTHETIC_PRIVATE_RECIPIENT", "slack", 2.3, {});
  delete start.id;
  delete sink.id;
  sink.disabled = true;
  const input = bytes({
    nodes: [start, sink],
    connections: {
      [start.name]: { main: [[{ node: sink.name, type: "main", index: 0 }]] },
    },
  });
  const report = await assessBytes(input, { collectTools: tools, now });
  assert.notEqual(report.status, "error", JSON.stringify(report));
  assert.equal(report.engineVersion, "0.7.0");
  assert.equal(report.inputSha256, hash(input));
  const summary = report.files[0].functionSummary;
  assert.deepEqual(
    summary.nodes.map((node) => node.identity),
    ["name_derived", "name_derived"],
  );
  assert.equal(summary.nodes[1].disabled, true);
  assert.equal(summary.edges[0].from, summary.nodes[0].nodeKey);
  assert.equal(summary.edges[0].to, summary.nodes[1].nodeKey);
  assert.ok(summary.limitations.includes("name_derived_identity"));
  assert.equal(summary.meaning, "declared_structure_only");
  assert.ok(!JSON.stringify(report).includes("SYNTHETIC_PRIVATE"));
  const presentation = report.files[0].findingPresentation;
  assert.equal(presentation.vulnerabilityCount, "not_established");
  const infoIds = new Set(presentation.observations);
  assert.ok(
    report.files[0].remediation.every((plan) =>
      plan.findingIds.every((id) => !infoIds.has(id)),
    ),
  );
  const tampered = structuredClone(report);
  tampered.files[0].findingPresentation.observations.push("0".repeat(64));
  assert.equal(assessmentReportSchema.safeParse(tampered).success, false);
});

test("assessment rule completeness is versioned while historical reports remain readable", async () => {
  const current = await assessBytes(
    bytes(document(node("Manual", "manualTrigger", 1))),
    { collectTools: tools, now },
  );
  assert.notEqual(current.status, "error");
  assert.equal(current.files[0].extensionRules.length, 18);
  const added = new Set([
    "N8N_DATABASE_OPERATIONS",
    "N8N_FILE_OPERATION_PATHS",
    "N8N_MAPPED_HTTP_DESTINATION",
    "N8N_AI_CONNECTION_CONTRACTS",
    "N8N_AI_PROMPT_DATA",
  ]);
  const historical = structuredClone(current);
  historical.engineVersion = "0.5.0";
  historical.files[0].extensionRules =
    historical.files[0].extensionRules.filter((r) => !added.has(r.ruleId));
  assert.equal(assessmentReportSchema.safeParse(historical).success, true);
  historical.engineVersion = "0.6.0";
  assert.equal(assessmentReportSchema.safeParse(historical).success, false);
  const missing = structuredClone(current);
  missing.files[0].extensionRules = missing.files[0].extensionRules.filter(
    (r) => r.ruleId !== "N8N_AI_PROMPT_DATA",
  );
  assert.equal(assessmentReportSchema.safeParse(missing).success, false);
});

test("flow profile inventory names form, wait, aggregate and record-store capabilities without asserting complete analysis", async () => {
  const input = bytes(
    document(
      node("SYNTHETIC_PRIVATE_FORM", "formTrigger", 2.2),
      node("SYNTHETIC_PRIVATE_WAIT", "wait", 1.1, {
        resume: "timeInterval",
        amount: 1,
        unit: "seconds",
      }),
      node("SYNTHETIC_PRIVATE_AGGREGATE", "aggregate", 1, {
        aggregate: "aggregateAllItemData",
      }),
      node("SYNTHETIC_PRIVATE_STORE", "airtable", 2.1, {
        resource: "record",
        operation: "search",
      }),
      node("SYNTHETIC_PRIVATE_UNKNOWN", "unrecognizedSyntheticConnector", 1),
    ),
  );
  const report = await assessBytes(input, { collectTools: tools, now });
  assert.notEqual(report.status, "error");
  const summary = report.files[0].functionSummary;
  assert.deepEqual(
    summary.nodes.map(({ kind, roles }) => ({ kind, roles })),
    [
      { kind: "webhook", roles: ["trigger"] },
      { kind: "mapping", roles: ["transform"] },
      { kind: "mapping", roles: ["transform"] },
      { kind: "document", roles: ["read", "write"] },
      { kind: "unknown", roles: ["unknown"] },
    ],
  );
  assert.equal(summary.meaning, "declared_structure_only");
  assert.ok(summary.limitations.includes("node_roles_are_capabilities"));
  assert.ok(summary.limitations.includes("business_purpose_not_verified"));
  assert.ok(summary.limitations.includes("unknown_node_capabilities"));
  assert.equal(report.status, "partial");
  assert.equal(report.execution, "not_run");
  assert.ok(!JSON.stringify(summary).includes("SYNTHETIC_PRIVATE"));
  assert.equal(report.inputSha256, hash(input));
});

test("input failures provide safe parser codes and locations before collecting tools", async () => {
  let calls = 0;
  const collectTools = async () => {
    calls++;
    return tools();
  };
  const invalid = document(node("PRIVATE_NAME", "manualTrigger"));
  invalid.nodes[0].id = null;
  const report = await assessBytes(bytes(invalid), { collectTools, now });
  assert.equal(report.code, "invalid_input");
  assert.deepEqual(report.inputDiagnosis, {
    code: "invalid_workflow",
    pointer: "/nodes/0",
  });
  assert.equal(assessmentReportSchema.safeParse(report).success, true);
  assert.equal(calls, 0);
  assert.ok(!JSON.stringify(report).includes("PRIVATE_NAME"));
});

test("integrated assessment keeps ten base categories and real extension outputs without a safety verdict", async () => {
  const input = bytes(
    document(
      node("HTTP", "httpRequest", 4.2, {
        url: "http://example.invalid",
        options: { allowUnauthorizedCerts: true },
      }),
    ),
  );
  const report = await assessBytes(input, { collectTools: tools, now });
  assert.notEqual(report.status, "error", JSON.stringify(report));
  assert.equal(assessmentReportSchema.safeParse(report).success, true);
  assert.equal(
    new Set(report.files[0].base.rules.map((rule) => rule.category)).size,
    10,
  );
  assert.ok(report.files[0].extensionRules.length >= 10);
  assert.ok(report.files[0].remediation.some((plan) => plan.automatic));
  assert.equal(report.execution, "not_run");
  assert.equal(report.decision, "inconclusive");
  assert.equal(report.boundary.isolationVerified, false);
  assert.equal(report.publication, "requires_service_authorization");
  assert.ok(!JSON.stringify(report).includes("example.invalid"));
});

test("sidecar hash, duplicate keys, invalid JSON and cancellation fail before native tools run", async () => {
  const input = bytes(document(node("Start", "manualTrigger")));
  let calls = 0;
  const collectTools = async () => {
    calls++;
    return tools();
  };
  for (const evidenceBytes of [
    bytes(sidecar(Buffer.from("other"))),
    Buffer.from('{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}'),
  ]) {
    const report = await assessBytes(input, {
      collectTools,
      evidenceBytes,
      now,
    });
    assert.equal(report.status, "error");
  }
  assert.equal(
    (await assessBytes(Buffer.from("{"), { collectTools, now })).status,
    "error",
  );
  assert.equal(
    (
      await assessBytes(input, {
        collectTools,
        now,
        signal: AbortSignal.abort(),
      })
    ).code,
    "cancelled",
  );
  assert.equal(calls, 0);
});

test("native tool failure is visible and cannot become an allow result", async () => {
  const input = bytes(document(node("Start", "manualTrigger")));
  const result = await tools();
  result.gitleaks = {
    ...result.gitleaks,
    status: "error",
    reason: "tool_unavailable",
  };
  result.native.modes = ["nlp", "python"].map((mode) => ({
    mode,
    status: "error",
    findings: [],
    diagnostics: [{ fieldIndex: null, code: "native_tool_unavailable" }],
    versions: { python: null, presidio: null, spacy: null, model: null },
  }));
  const report = await assessBytes(input, {
    collectTools: async () => result,
    now,
  });
  assert.equal(report.status, "partial");
  assert.equal(report.decision, "inconclusive");
  assert.equal(report.files[0].tools.native.modes[0].status, "error");
});

test("rollup status and decision tampering is rejected", async () => {
  const report = await assessBytes(
    bytes(
      document(
        node("HTTP", "httpRequest", 4.2, { url: "http://example.invalid" }),
      ),
    ),
    { collectTools: tools, now },
  );
  assert.notEqual(report.status, "error");
  assert.equal(
    assessmentReportSchema.safeParse({ ...report, decision: "allow" }).success,
    false,
  );
  assert.equal(
    assessmentReportSchema.safeParse({ ...report, status: "analyzed" }).success,
    false,
  );
  const changed = structuredClone(report);
  changed.files[0].inputSha256 = hash("other");
  assert.equal(assessmentReportSchema.safeParse(changed).success, false);
  const missingRules = structuredClone(report);
  missingRules.files[0].extensionRules = [];
  assert.equal(assessmentReportSchema.safeParse(missingRules).success, false);
  const missingTool = structuredClone(report);
  missingTool.files[0].tools.native.modes.pop();
  assert.equal(assessmentReportSchema.safeParse(missingTool).success, false);
  const falseAllow = structuredClone(report);
  falseAllow.files[0].policy.decision = "allow";
  falseAllow.decision = "allow";
  assert.equal(assessmentReportSchema.safeParse(falseAllow).success, false);
});

function parentFixture(reference = "child-ref") {
  return bytes(
    document(
      node("Call", "executeWorkflow", 1.4, {
        workflowId: { mode: "id", value: reference },
        source: "database",
      }),
    ),
  );
}
function childRecord(parent, child, reference = "child-ref") {
  return {
    parentInputSha256: hash(parent),
    callerNodeKey: createContext(parent).nodes[0].key,
    reference,
    inputSha256: hash(child),
    content: child.toString(),
    workflowVersionId: "child-v1",
    sourceId: "test",
  };
}

test("supplied child definitions bind to exact caller, parent hash and reference; child findings are separate", async () => {
  const parent = parentFixture();
  const child = bytes(
    document(
      node("Child HTTP", "httpRequest", 4.2, {
        url: "http://child.example.invalid",
      }),
    ),
  );
  const evidenceBytes = bytes(
    sidecar(parent, { subworkflows: [childRecord(parent, child)] }),
  );
  const report = await assessBytes(parent, {
    evidenceBytes,
    collectTools: tools,
    now,
  });
  assert.notEqual(report.status, "error", JSON.stringify(report));
  assert.equal(report.files.length, 2);
  assert.equal(report.files[1].inputSha256, hash(child));
  assert.equal(report.files[1].parentAnalysisKey, report.files[0].analysisKey);
  assert.equal(report.subworkflows[0].status, "definition_analyzed");
  assert.ok(
    report.files[1].base.rules
      .flatMap((rule) => rule.findings)
      .some((finding) => finding.category === "transport"),
  );
  assert.ok(
    report.subworkflows[0].codes.includes(
      "subworkflow_argument_and_return_flow_unresolved",
    ),
  );
  assert.equal(report.files[1].evidence.independentlyVerified, false);
  assert.ok(!JSON.stringify(report).includes("child.example.invalid"));
  const orphan = structuredClone(report);
  orphan.subworkflows = [];
  assert.equal(assessmentReportSchema.safeParse(orphan).success, false);
  const selfParent = structuredClone(report);
  selfParent.files[1].parentAnalysisKey = selfParent.files[1].analysisKey;
  assert.equal(assessmentReportSchema.safeParse(selfParent).success, false);
  const badDepth = structuredClone(report);
  badDepth.files[1].depth = 3;
  assert.equal(assessmentReportSchema.safeParse(badDepth).success, false);
});

test("wrong supplied reference is not fetched or treated as the child", () => {
  const parent = parentFixture();
  const child = bytes(document(node("Start", "manualTrigger")));
  const evidence = parseEvidence(
    sidecar(parent, { subworkflows: [childRecord(parent, child, "other")] }),
    hash(parent),
  );
  const planned = planSubworkflows(parent, evidence);
  assert.equal(planned.inputs.length, 1);
  assert.equal(planned.links[0].status, "unresolved");
});

test("inline definitions are parsed statically and dynamic/external definitions stay unresolved", () => {
  const child = bytes(document(node("Start", "manualTrigger")));
  const inline = bytes(
    document(
      node("Call", "executeWorkflow", 1.4, {
        source: "parameter",
        workflowJson: child.toString(),
      }),
    ),
  );
  assert.equal(planSubworkflows(inline).inputs.length, 2);
  for (const parameters of [
    { source: "parameter", workflowJson: "={{ $json.definition }}" },
    { source: "url", workflowUrl: "https://example.invalid/private" },
    { source: "localFile", workflowPath: "C:/private" },
  ]) {
    const planned = planSubworkflows(
      bytes(document(node("Call", "executeWorkflow", 1, parameters))),
    );
    assert.equal(planned.inputs.length, 1);
    assert.equal(planned.links[0].status, "unresolved");
  }
});

test("hash cycles, child count and depth are bounded", () => {
  const parent = parentFixture();
  const cyclic = parseEvidence(
    sidecar(parent, { subworkflows: [childRecord(parent, parent)] }),
    hash(parent),
  );
  assert.equal(planSubworkflows(parent, cyclic).links[0].status, "cycle");
  let nested = bytes(document(node("Start", "manualTrigger")));
  for (let i = 0; i < 5; i++)
    nested = bytes(
      document(
        node(`Call${i}`, "executeWorkflow", 1.4, {
          source: "parameter",
          workflowJson: nested.toString(),
        }),
      ),
    );
  const planned = planSubworkflows(nested);
  assert.equal(planned.inputs.length, 4);
  assert.equal(planned.links.at(-1).status, "limit");
  const child = bytes(document(node("Start", "manualTrigger")));
  const broad = bytes(
    document(
      ...Array.from({ length: 12 }, (_, i) =>
        node(`Call${i}`, "executeWorkflow", 1.4, {
          source: "parameter",
          workflowJson: child.toString(),
        }),
      ),
    ),
  );
  const wide = planSubworkflows(broad);
  assert.equal(wide.inputs.length, 9);
  assert.equal(wide.links.filter((link) => link.status === "limit").length, 4);
});

test("root-scoped evidence never attaches to colliding child node identifiers", () => {
  const parent = parentFixture();
  const child = bytes(document(node("Call", "manualTrigger")));
  const key = createContext(parent).nodes[0].key;
  const evidence = parseEvidence(
    sidecar(parent, {
      classifications: [
        {
          nodeKey: key,
          field: "body.id",
          dataClass: "public",
          sourceId: "test",
        },
      ],
      subworkflows: [childRecord(parent, child)],
    }),
    hash(parent),
  );
  const planned = planSubworkflows(parent, evidence);
  assert.deepEqual(
    evidenceForInput(planned.inputs[1], evidence).classifications,
    [],
  );
});

test("sandbox accepts immutable image digests only and fixes isolation flags", () => {
  const name = "worker-assess-12345678-1234-1234-1234-123456789abc";
  const args = sandboxArguments(`sha256:${hash("image")}`, name);
  for (const flag of [
    "--network=none",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--memory=1g",
    "--pids-limit=96",
    "--user=65532:65532",
    "--pull=never",
  ])
    assert.ok(args.includes(flag));
  assert.equal(
    args.some((arg) => arg.includes("mount") || arg.includes("privileged")),
    false,
  );
  assert.throws(() => sandboxArguments("mutable:latest", name));
});

test("sandbox configuration and pre-cancellation fail closed without launching tools", async () => {
  const input = bytes(document(node("Start", "manualTrigger")));
  assert.equal(
    (await runAssessment(input, undefined, {})).code,
    "invalid_configuration",
  );
  assert.equal(
    (
      await runAssessment(input, undefined, {
        dockerExecutable: process.execPath,
        image: `sha256:${hash("image")}`,
        signal: AbortSignal.abort(),
      })
    ).code,
    "cancelled",
  );
});
