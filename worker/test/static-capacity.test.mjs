import assert from "node:assert/strict";
import test from "node:test";
import { limits } from "../dist/contracts/contract.js";
import { analyzeStatic } from "../dist/analysis/static-engine.js";
import { runStaticChild } from "../dist/runtime/static-runner.js";
import {
  staticLimits,
  staticReportSchema,
  ruleResultSchema,
} from "../dist/contracts/static-contract.js";

const input = Buffer.from(
  JSON.stringify({
    nodes: Array.from({ length: 100 }, (_, i) => ({
      id: String(i),
      name: String(i),
      type: "synthetic.unknown",
      typeVersion: 1,
      parameters: {},
    })),
    connections: {},
  }),
);
const scanner = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};
test("ten-category evidence over the legacy SQL output cap survives the bounded child", async () => {
  const report = analyzeStatic(input, scanner);
  assert.equal(report.status, "partial");
  const bytes = Buffer.byteLength(JSON.stringify(report));
  assert.ok(bytes > limits.resultBytes && bytes < staticLimits.resultBytes);
  const child = await runStaticChild(input, scanner);
  assert.deepEqual(child, report);
  assert.equal(limits.resultBytes, 128 * 1024);
});
test("oversized otherwise-valid static evidence is still rejected", () => {
  const report = analyzeStatic(input, scanner);
  const template = report.rules.find(
    (rule) => rule.findings.length === 0 && rule.diagnostics.length > 50,
  );
  assert.ok(template);
  let index = 0;
  while (
    Buffer.byteLength(JSON.stringify(report)) <= staticLimits.resultBytes
  ) {
    const rule = {
      ...structuredClone(template),
      ruleId: `TEST_CAPACITY_${index++}`,
    };
    assert.ok(ruleResultSchema.safeParse(rule).success);
    report.rules.push(rule);
  }
  assert.ok(report.rules.length <= 64);
  assert.equal(staticReportSchema.safeParse(report).success, false);
});
