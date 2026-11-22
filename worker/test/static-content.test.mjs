import assert from "node:assert/strict";
import test from "node:test";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import { analyzeContent } from "../dist/static-content.js";
import { runGitleaks } from "../dist/gitleaks.js";

const cleanTool = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};
const node = (index = 0) => ({
  id: `node-${index}`,
  name: `Node ${index}`,
  type: "n8n-nodes-base.noOp",
  typeVersion: 1,
  parameters: {},
});
const context = (extra = {}, nodes = [node()]) =>
  createContext(
    Buffer.from(JSON.stringify({ nodes, connections: {}, ...extra })),
  );
const inspect = (ctx, tool = cleanTool) =>
  analyzeContent(ctx, tool).map((result) => ruleResultSchema.parse(result));

test("content candidates include keys, notes and pinData with no raw PII in output", () => {
  const email = "synthetic.person@example.invalid";
  const phone = "010-1234-5678";
  const card = "4111 1111 1111 1111";
  const workflowNode = { ...node(), notes: `Contact ${phone}` };
  const ctx = context(
    { pinData: { privateSourceName: [{ json: { [email]: card } }] } },
    [workflowNode],
  );
  const [, pii] = inspect(ctx);
  const codes = new Set(
    pii.findings.flatMap((item) => item.evidence.map((item) => item.code)),
  );
  assert.deepEqual(
    codes,
    new Set([
      "email_candidate",
      "payment_card_candidate",
      "korean_mobile_candidate",
    ]),
  );
  assert.equal(pii.coverage[0].status, "checked");
  const output = JSON.stringify(pii);
  for (const value of [email, phone, card, "privateSourceName"])
    assert.equal(output.includes(value), false);
  assert.ok(pii.findings.every(({ claim }) => claim === "candidate"));
});

test("invalid formats and ordinary numbers are not PII candidates", () => {
  const ctx = context({
    notes: "not-an-email; invoice 1234567890123456; version 2.48.7",
  });
  const [, pii] = inspect(ctx);
  assert.equal(pii.findings.length, 0);
  assert.equal(pii.coverage[0].status, "checked");
});

test("literal credential parameters and named headers are candidates, credential references are not", () => {
  const item = {
    ...node(),
    credentials: {
      postgres: { id: "opaque-reference", name: "My DB credentials" },
    },
    parameters: {
      password: "synthetic-literal",
      apiKey: "={{ $env.KEY }}",
      headerParameters: {
        parameters: [{ name: "Authorization", value: "Bearer synthetic" }],
      },
    },
  };
  const [secrets] = inspect(context({}, [item]));
  assert.equal(secrets.findings.length, 2);
  assert.ok(
    secrets.findings.every(
      (finding) => finding.evidence[0].code === "literal_credential_field",
    ),
  );
  assert.equal(JSON.stringify(secrets).includes("synthetic-literal"), false);
  const [references] = inspect(
    context({}, [{ ...node(), credentials: item.credentials }]),
  );
  assert.equal(references.findings.length, 0);
});

test("missing secret scanner is partial even with zero findings", () => {
  const [secrets, pii] = analyzeContent(context());
  ruleResultSchema.parse(secrets);
  assert.equal(secrets.coverage[0].status, "partial");
  assert.equal(secrets.diagnostics[0].code, "tool_unavailable");
  assert.equal(pii.coverage[0].status, "checked");
});

test("literal credentials containing expression delimiters remain candidates", () => {
  for (const password of ["literal{{ suffix }}", '= {{ "literal" }}']) {
    const [secrets] = inspect(
      context({}, [{ ...node(), parameters: { password } }]),
    );
    assert.equal(secrets.findings.length, 1);
    assert.equal(
      secrets.findings[0].evidence[0].code,
      "literal_credential_field",
    );
  }
});

test("Gitleaks maps only field indices and keeps provider output out of evidence", () => {
  const secret = "synthetic-sensitive-content";
  const ctx = context({ pinData: { [secret]: secret } });
  const selected = ctx.fields.find(
    (field) => field.kind === "key" && field.value === secret,
  );
  const [secrets] = inspect(ctx, {
    ...cleanTool,
    findings: [{ fieldIndex: selected.index, ruleId: "github-pat" }],
  });
  assert.equal(secrets.findings.length, 1);
  assert.equal(
    secrets.findings[0].evidence[0].code,
    "gitleaks_secret_candidate",
  );
  assert.equal(JSON.stringify(secrets).includes(secret), false);
  assert.equal(JSON.stringify(secrets).includes("github-pat"), false);
});

test("invalid tool version or field index produces explicit partial coverage", () => {
  for (const tool of [
    { ...cleanTool, version: "0.0.0" },
    { ...cleanTool, findings: [{ fieldIndex: 99999, ruleId: "github-pat" }] },
  ]) {
    const [secrets] = inspect(context(), tool);
    assert.equal(secrets.coverage[0].status, "partial");
    assert.equal(secrets.diagnostics[0].code, "tool_invalid_report");
  }
});

test("finding limit preserves candidates and reports incomplete coverage", () => {
  const nodes = Array.from({ length: 40 }, (_, index) => ({
    ...node(index),
    notes: `person${index}@example.invalid`,
  }));
  const [, pii] = inspect(context({}, nodes));
  assert.equal(pii.findings.length, 32);
  assert.equal(pii.coverage[0].status, "partial");
  assert.ok(pii.diagnostics.some(({ code }) => code === "finding_limit"));
});

test("trusted tool runner rejects absence, relative executables and cancellation", async () => {
  assert.equal((await runGitleaks([])).reason, "tool_unavailable");
  assert.equal(
    (await runGitleaks([], { executable: "gitleaks" })).reason,
    "tool_unavailable",
  );
  const controller = new AbortController();
  controller.abort();
  assert.equal(
    (
      await runGitleaks([], {
        executable: process.execPath,
        signal: controller.signal,
      })
    ).reason,
    "tool_cancelled",
  );
  assert.equal(
    (await runGitleaks([], { executable: process.execPath, timeoutMs: 0 }))
      .reason,
    "tool_input_limit",
  );
  const wrongTool = await runGitleaks([], { executable: process.execPath });
  assert.equal(wrongTool.status, "error");
  assert.deepEqual(wrongTool.findings, []);
  assert.equal(JSON.stringify(wrongTool).includes(process.execPath), false);
});
