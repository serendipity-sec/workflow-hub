import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  categories,
  staticReportSchema,
} from "../dist/contracts/static-contract.js";
import { analyzeStatic } from "../dist/analysis/static-engine.js";
import { compareStatic } from "../dist/analysis/static-compare.js";
import { runStaticFile } from "../dist/runtime/static-runner.js";
import { sha256 } from "../dist/runtime/worker-io.js";

const cleanTool = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};
const encode = (value) => Buffer.from(JSON.stringify(value));
const node = (id, type, parameters = {}, typeVersion = 1) => ({
  id,
  name: id,
  type: `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
});
const wire = (node) => ({ node, type: "main", index: 0 });
function workflow() {
  return {
    nodes: [
      node("Webhook", "webhook", { httpMethod: "POST", path: "synthetic" }, 2),
      node(
        "Database",
        "postgres",
        {
          resource: "database",
          operation: "executeQuery",
          query: "SELECT label FROM items WHERE id = {{ $json.body.id }}",
          options: {},
        },
        2.8,
      ),
      node(
        "Request",
        "httpRequest",
        { url: "={{ $json.body.destination }}" },
        4.2,
      ),
      node(
        "Plain",
        "httpRequest",
        {
          url: "http://example.invalid",
          options: { allowUnauthorizedCerts: true },
        },
        4.2,
      ),
      node("Command", "executeCommand", {
        command: "=printf {{ $json.body.label }}",
      }),
      node(
        "Respond",
        "respondToWebhook",
        { respondWith: "allIncomingItems" },
        1.4,
      ),
      {
        ...node("Community", "custom", {}),
        type: "n8n-nodes-community-example.action",
      },
      {
        ...node("Notes", "noOp", { password: "synthetic-placeholder" }),
        notes: "synthetic.person@example.invalid",
      },
    ],
    connections: {
      Webhook: {
        main: [
          [wire("Database"), wire("Request"), wire("Command"), wire("Respond")],
        ],
      },
    },
  };
}

test("full pipeline includes all ten categories and never copies raw fields", () => {
  const bytes = encode(workflow());
  const report = staticReportSchema.parse(analyzeStatic(bytes, cleanTool));
  assert.notEqual(report.status, "error");
  assert.equal(report.inputSha256, sha256(bytes));
  assert.equal(report.execution, "not_run");
  assert.deepEqual(
    new Set(report.rules.map((item) => item.category)),
    new Set(categories),
  );
  for (const category of categories) {
    assert.ok(
      report.rules.some(
        (item) => item.category === category && item.findings.length > 0,
      ),
      `missing positive for ${category}`,
    );
  }
  const serialized = JSON.stringify(report);
  for (const raw of [
    "synthetic-placeholder",
    "synthetic.person@example.invalid",
    "example.invalid",
    "SELECT label",
    "Community",
  ]) {
    assert.equal(serialized.includes(raw), false, `raw content leaked: ${raw}`);
  }
});

test("missing secret tool does not suppress the other nine categories or imply clean scan", () => {
  const report = analyzeStatic(encode(workflow()), {
    tool: "gitleaks",
    version: "8.30.1",
    status: "error",
    findings: [],
    reason: "tool_unavailable",
  });
  assert.equal(report.status, "partial");
  assert.equal(new Set(report.rules.map((item) => item.category)).size, 10);
  assert.ok(
    report.rules
      .find((item) => item.category === "secrets")
      .diagnostics.some((item) => item.code === "tool_unavailable"),
  );
  assert.ok(
    report.rules.find((item) => item.category === "sql").findings.length > 0,
  );
});

test("bad JSON and injected external tool records cannot become clean reports", () => {
  const invalid = Buffer.from('{"nodes":[],"nodes":[],"connections":{}}');
  assert.deepEqual(analyzeStatic(invalid, cleanTool).code, "duplicate_key");
  const bytes = encode(workflow());
  assert.equal(
    analyzeStatic(bytes, {
      ...cleanTool,
      findings: [{ fieldIndex: 99999, ruleId: "generic-api-key" }],
    }).status,
    "error",
  );
  assert.equal(
    analyzeStatic(bytes, { ...cleanTool, secret: "not-allowed" }).status,
    "error",
  );
});

test("restricted child scans a local definition without invoking its Code", async () => {
  const directory = await mkdtemp(join(tmpdir(), "worker-static-"));
  try {
    const filename = join(directory, "workflow.json");
    const marker = join(directory, "must-not-exist");
    const input = workflow();
    input.nodes.push(
      node(
        "Code",
        "code",
        {
          jsCode: `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'not-run'); return [];`,
        },
        2,
      ),
    );
    const bytes = encode(input);
    await writeFile(filename, bytes);
    const report = await runStaticFile(filename);
    assert.notEqual(report.status, "error", JSON.stringify(report));
    assert.equal(report.inputSha256, sha256(bytes));
    assert.equal(report.execution, "not_run");
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("comparison preserves uncertainty for deleted nodes and incompatible reports", () => {
  const source = workflow();
  const before = analyzeStatic(encode(source), cleanTool);
  assert.notEqual(before.status, "error");
  const candidate = structuredClone(source);
  candidate.nodes = candidate.nodes.filter(({ id }) => id !== "Plain");
  const after = analyzeStatic(encode(candidate), cleanTool);
  assert.notEqual(after.status, "error");
  const oldTransport = before.rules.find(
    (item) => item.category === "transport",
  ).findings;
  const compared = compareStatic(before, after);
  for (const finding of oldTransport) {
    assert.equal(
      compared.rechecks.find(({ id }) => id === finding.id)?.status,
      "inconclusive",
    );
  }
  assert.equal(
    compareStatic(before, { ...after, engineVersion: "unknown" }).basis,
    "incompatible_or_failed",
  );
  assert.ok(
    compareStatic(before, before).rechecks.every(
      ({ status }) => status === "persisting",
    ),
  );
});

test("comparison observes node-scoped configuration changes without claiming a repair", () => {
  const source = workflow();
  const before = analyzeStatic(encode(source), cleanTool);
  const fixed = structuredClone(source);
  fixed.nodes.find(
    ({ id }) => id === "Plain",
  ).parameters.options.allowUnauthorizedCerts = false;
  const after = analyzeStatic(encode(fixed), cleanTool);
  assert.notEqual(before.status, "error");
  assert.notEqual(after.status, "error");
  const finding = before.rules
    .flatMap(({ findings }) => findings)
    .find(({ evidence }) =>
      evidence.some(
        ({ code }) => code === "tls_certificate_validation_disabled",
      ),
    );
  assert.ok(finding);
  assert.equal(
    compareStatic(before, after).rechecks.find(({ id }) => id === finding.id)
      ?.status,
    "not_observed",
  );
  assert.equal(
    compareStatic(after, before).newFindings.find(({ id }) => id === finding.id)
      ?.status,
    "newly_observed",
  );
  const unsupported = structuredClone(fixed);
  unsupported.nodes.find(({ id }) => id === "Plain").typeVersion = 99;
  const unknown = analyzeStatic(encode(unsupported), cleanTool);
  assert.equal(
    compareStatic(before, unknown).rechecks.find(({ id }) => id === finding.id)
      ?.status,
    "inconclusive",
  );
});

test("content comparison uses successful document coverage and preserves lost node or tool uncertainty", () => {
  const source = workflow();
  const before = analyzeStatic(encode(source), cleanTool);
  const candidate = structuredClone(source);
  candidate.nodes.find(({ id }) => id === "Notes").parameters.password = "";
  const after = analyzeStatic(encode(candidate), cleanTool);
  const findings = before.rules.find(
    ({ category }) => category === "secrets",
  ).findings;
  assert.ok(findings.length > 0);
  for (const finding of findings) {
    assert.equal(
      compareStatic(before, after).rechecks.find(({ id }) => id === finding.id)
        ?.status,
      "not_observed",
    );
    assert.equal(
      compareStatic(after, before).newFindings.find(
        ({ id }) => id === finding.id,
      )?.status,
      "newly_observed",
    );
  }
  const incomplete = analyzeStatic(encode(candidate), {
    tool: "gitleaks",
    version: "8.30.1",
    status: "error",
    findings: [],
    reason: "tool_unavailable",
  });
  candidate.nodes = candidate.nodes.filter(({ id }) => id !== "Notes");
  const deleted = analyzeStatic(encode(candidate), cleanTool);
  for (const finding of findings) {
    assert.equal(
      compareStatic(before, incomplete).rechecks.find(
        ({ id }) => id === finding.id,
      )?.status,
      "inconclusive",
    );
    assert.equal(
      compareStatic(before, deleted).rechecks.find(
        ({ id }) => id === finding.id,
      )?.status,
      "inconclusive",
    );
  }
});

test("outbound body changes have comparable coverage without clearing unsupported nodes", () => {
  const source = workflow();
  const target = source.nodes.find(({ id }) => id === "Plain");
  target.parameters.sendBody = true;
  target.parameters.contentType = "json";
  target.parameters.specifyBody = "json";
  target.parameters.jsonBody = "={ synthetic: true }";
  const before = analyzeStatic(encode(source), cleanTool);
  const finding = before.rules
    .find(({ category }) => category === "egress")
    .findings.find(({ evidence }) =>
      evidence.some(({ code }) => code === "configured_outbound_body"),
    );
  assert.ok(finding);
  target.parameters.sendBody = false;
  const after = analyzeStatic(encode(source), cleanTool);
  assert.equal(
    compareStatic(before, after).rechecks.find(({ id }) => id === finding.id)
      ?.status,
    "not_observed",
  );
  assert.equal(
    compareStatic(after, before).newFindings.find(({ id }) => id === finding.id)
      ?.status,
    "newly_observed",
  );
  target.typeVersion = 99;
  const unknown = analyzeStatic(encode(source), cleanTool);
  assert.equal(
    compareStatic(before, unknown).rechecks.find(({ id }) => id === finding.id)
      ?.status,
    "inconclusive",
  );
});
