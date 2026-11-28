import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const root = fileURLToPath(new URL("..", import.meta.url));
const fixtures = resolve(root, "fixtures");
export const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

export function frozenCorpus() {
  const manifestBytes = readFileSync(resolve(fixtures, "cases.json"));
  const manifest = JSON.parse(manifestBytes);
  const { manifestSha256, files } = readJson(
    resolve(root, "validation/case-sha256.json"),
  );
  assert.equal(sha256(manifestBytes), manifestSha256, "case manifest");
  const names = new Set();
  const cases = manifest.cases.map((example) => {
    assert.match(example.id, /^[a-z0-9-]+$/);
    assert.equal(example.file, `workflows/${example.id}.json`);
    const path = resolve(fixtures, example.file);
    const bytes = readFileSync(path);
    const inputSha256 = sha256(bytes);
    assert.equal(inputSha256, files[example.id], example.id);
    const workflow = JSON.parse(bytes);
    assert.equal(workflow.active, false, example.id);
    assert.equal(names.has(workflow.name), false, workflow.name);
    names.add(workflow.name);
    return { ...example, path, workflow, inputSha256 };
  });
  assert.equal(cases.length, Object.keys(files).length);
  return { ...manifest, cases };
}

function count(cases, observations) {
  const totals = {
    positive: 0,
    negative: 0,
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
    failed: 0,
    unsupported: 0,
  };
  for (const { id, label } of cases) {
    const outcome = observations[id];
    assert.ok(
      ["positive", "negative", "failure", "unsupported"].includes(outcome),
      id,
    );
    if (label !== "unsupported") {
      const risk = label === "risk";
      totals[risk ? "positive" : "negative"] += 1;
      if (risk) totals[outcome === "positive" ? "tp" : "fn"] += 1;
      if (!risk && outcome === "positive") totals.fp += 1;
      if (!risk && outcome === "negative") totals.tn += 1;
    }
    if (outcome === "failure") totals.failed += 1;
    if (outcome === "unsupported") totals.unsupported += 1;
  }
  return totals;
}

export function metrics(cases, observations) {
  return {
    all: count(cases, observations),
    validation: count(
      cases.filter((example) => example.split === "validation"),
      observations,
    ),
  };
}
