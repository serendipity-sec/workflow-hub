import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { resultSchema, taskSchema, versions } from "../dist/contract.js";

const fixture = (name) => new URL(`../fixtures/${name}`, import.meta.url);
const json = async (name) => JSON.parse(await readFile(fixture(name), "utf8"));

test("contract examples link the exact input bytes and all work identifiers", async () => {
  const task = taskSchema.parse(await json("task.json"));
  const captured = await json("result.json");
  assert.equal(captured.engineVersion, "0.1.0");
  assert.equal(resultSchema.safeParse(captured).success, false);
  const result = resultSchema.parse({
    ...captured,
    engineVersion: versions.engine,
  });
  assert.equal(
    task.inputSha256,
    createHash("sha256")
      .update(await readFile(fixture("workflows/interpolated.json")))
      .digest("hex"),
  );
  for (const key of [
    "taskId",
    "attemptId",
    "workflowVersionId",
    "inputSha256",
    "contractVersion",
  ]) {
    assert.equal(task[key], result[key]);
  }
  assert.equal(
    taskSchema.safeParse({ ...task, contractVersion: "2.0.0" }).success,
    false,
  );
  assert.equal(
    taskSchema.safeParse({ ...task, command: "unexpected" }).success,
    false,
  );
  for (const [url, valid] of [
    ["https://fixture.invalid/workflow?signature=synthetic", true],
    ["http://127.0.0.1:1234/workflow", true],
    ["http://fixture.invalid/workflow", false],
    ["file:///workflow.json", false],
    ["https://user@fixture.invalid/workflow", false],
    ["invalid", false],
  ]) {
    assert.equal(
      taskSchema.safeParse({ ...task, file: { kind: "download", url } })
        .success,
      valid,
    );
  }
  assert.equal(
    resultSchema.safeParse({ ...result, coverage: [] }).success,
    false,
  );
  assert.equal(
    resultSchema.safeParse({ ...result, status: "unsupported" }).success,
    false,
  );
  assert.equal(
    resultSchema.safeParse({ ...result, findings: [] }).success,
    false,
  );
  const unknown = {
    ...result.coverage[0],
    disposition: "unknown",
    inputKey: null,
    shapeKey: null,
  };
  assert.equal(
    resultSchema.safeParse({ ...result, coverage: [unknown], findings: [] })
      .success,
    false,
  );
  const expected = (await json("cases.json")).cases.find(
    ({ id }) => id === "interpolated",
  );
  const [finding] = result.findings;
  assert.equal(result.coverage[0].disposition, expected.disposition);
  assert.equal(finding.reference, expected.reference);
  assert.equal(finding.guard, expected.guard);
  assert.equal(finding.source.pointer, expected.sourcePointer);
  assert.equal(finding.sink.pointer, expected.sinkPointer);
  assert.deepEqual(
    finding.path.map(({ pointer }) => pointer),
    expected.pathPointers,
  );
  const invalidFinding = (replacement) =>
    resultSchema.safeParse({
      ...result,
      findings: [{ ...finding, ...replacement }],
    }).success;
  assert.equal(invalidFinding({ path: [...finding.path].reverse() }), false);
  assert.equal(
    invalidFinding({
      remediation: { ...finding.remediation, binding: finding.source },
    }),
    false,
  );
  assert.equal(
    invalidFinding({
      remediation: {
        ...finding.remediation,
        checks: Array(3).fill(finding.remediation.checks[0]),
      },
    }),
    false,
  );
});

test("manifest cases name valid evidence locations and matched recheck inputs", async () => {
  const manifest = await json("cases.json");
  const ids = new Set();
  for (const example of manifest.cases) {
    assert.equal(ids.has(example.id), false);
    ids.add(example.id);
    const input = await json(example.file);
    assert.ok(input.nodes.length >= 1);
    if (example.label === "risk") {
      const pointers = [
        example.sourcePointer,
        ...example.pathPointers,
        example.sinkPointer,
      ];
      for (const pointer of pointers) {
        assert.notEqual(
          pointer
            .slice(1)
            .split("/")
            .reduce((value, key) => value?.[key], input),
          undefined,
          example.id,
        );
      }
    }
  }
  for (const { baseline, candidate } of manifest.rechecks) {
    assert.ok(ids.has(baseline) && ids.has(candidate));
  }
});
