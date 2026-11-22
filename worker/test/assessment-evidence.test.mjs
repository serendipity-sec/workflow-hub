import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  AssessmentEvidenceError,
  evidenceLimits,
  evidenceSummary,
  evidenceSummarySchema,
  parseEvidence,
  parseEvidenceBytes,
} from "../dist/assessment-evidence.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const inputSha256 = hash("synthetic workflow");
const now = "2026-11-22T00:00:00.000Z";
const source = {
  id: "fixture-source",
  kind: "declaration",
  method: "user_declaration",
  recordedAt: now,
};
const fixture = (extra = {}) => ({
  schemaVersion: "1.0.0",
  inputSha256,
  sources: [source],
  ...extra,
});
const rejects = (value, code) =>
  assert.throws(
    () => parseEvidence(value, inputSha256),
    (error) => error instanceof AssessmentEvidenceError && error.code === code,
  );

test("evidence is strict, file-bound, and rejects ambiguous source bindings", () => {
  const parsed = parseEvidence(fixture(), inputSha256);
  assert.deepEqual(parsed.packages, []);
  rejects(
    fixture({ inputSha256: hash("different file") }),
    "evidence_input_mismatch",
  );
  rejects(fixture({ unknownAuthorization: true }), "invalid_evidence");
  rejects(fixture({ sources: [source, source] }), "duplicate_evidence");
  rejects(
    fixture({
      packages: [
        { name: "fixture-package", version: "1.0.0", sourceId: "missing" },
      ],
    }),
    "unknown_evidence_source",
  );
  rejects(
    fixture({ sources: [{ ...source, kind: "supplied_observation" }] }),
    "invalid_evidence",
  );
  rejects(
    fixture({
      sources: [
        {
          ...source,
          kind: "supplied_observation",
          artifactSha256: "not-a-digest",
        },
      ],
    }),
    "invalid_evidence",
  );
});

test("evidence JSON rejects duplicate escaped keys, malformed UTF-8, excessive depth and bytes", () => {
  assert.throws(
    () =>
      parseEvidenceBytes(
        Buffer.from('{"schemaVersion":"1.0.0","schema\\u0056ersion":"1.0.0"}'),
        inputSha256,
      ),
    { code: "duplicate_evidence" },
  );
  assert.throws(() => parseEvidenceBytes(Buffer.from([0xff]), inputSha256), {
    code: "invalid_evidence",
  });
  assert.throws(
    () =>
      parseEvidenceBytes(
        Buffer.from(
          "[".repeat(evidenceLimits.depth + 1) +
            "]".repeat(evidenceLimits.depth + 1),
        ),
        inputSha256,
      ),
    { code: "evidence_limit" },
  );
  assert.throws(
    () =>
      parseEvidenceBytes(
        Buffer.alloc(evidenceLimits.bytes + 1, 32),
        inputSha256,
      ),
    { code: "evidence_limit" },
  );
  assert.throws(() => parseEvidenceBytes(Buffer.from('{"x":}'), inputSha256), {
    code: "invalid_evidence",
  });
  assert.equal(
    parseEvidenceBytes(Buffer.from(JSON.stringify(fixture())), inputSha256)
      .inputSha256,
    inputSha256,
  );
});

test("child bytes and parent identity are bound before recursive analysis", () => {
  const content = JSON.stringify({ nodes: [], connections: {} });
  const child = {
    parentInputSha256: inputSha256,
    callerNodeKey: hash("caller"),
    reference: "synthetic-child",
    inputSha256: hash(content),
    content,
    workflowVersionId: "fixture-v1",
    sourceId: source.id,
  };
  assert.equal(
    parseEvidence(fixture({ subworkflows: [child] }), inputSha256).subworkflows
      .length,
    1,
  );
  rejects(
    fixture({ subworkflows: [{ ...child, content: content + " " }] }),
    "subworkflow_hash_mismatch",
  );
  rejects(
    fixture({
      subworkflows: [{ ...child, parentInputSha256: hash("unrelated parent") }],
    }),
    "evidence_input_mismatch",
  );
  rejects(fixture({ subworkflows: [child, child] }), "duplicate_evidence");
  const oversized = "한".repeat(90_000);
  rejects(
    fixture({
      subworkflows: [
        { ...child, content: oversized, inputSha256: hash(oversized) },
      ],
    }),
    "evidence_limit",
  );
});

test("conflicting same-node metadata is rejected while declarations remain claims", () => {
  const classification = {
    nodeKey: hash("node"),
    field: "body.email",
    dataClass: "personal",
    sourceId: source.id,
  };
  rejects(
    fixture({
      classifications: [
        classification,
        { ...classification, dataClass: "public" },
      ],
    }),
    "duplicate_evidence",
  );
  const runtime = {
    sourceId: source.id,
    environmentId: "fixture-environment",
    n8nVersion: "2.0.0",
    upstreamAuthentication: [
      {
        nodeKey: hash("node"),
        kind: "jwt",
        enforced: true,
        sourceId: source.id,
      },
    ],
  };
  const parsed = parseEvidence(fixture({ runtime }), inputSha256);
  assert.equal(parsed.runtime.upstreamAuthentication[0].enforced, true);
  assert.equal(evidenceSummary(parsed).independentlyVerified, false);
});

test("source and synthetic receipt summary masks names and separates other-file evidence", () => {
  const observation = {
    ...source,
    kind: "supplied_observation",
    method: "synthetic_test_receipt",
    artifactSha256: hash("receipt artifact"),
  };
  const receipt = {
    inputSha256,
    environmentId: "private-environment-name",
    sourceId: source.id,
    recordedAt: now,
    cases: [
      {
        caseId: "private-case-name",
        attackBlocked: true,
        normalBehaviorPreserved: true,
      },
    ],
  };
  const parsed = parseEvidence(
    fixture({
      sources: [observation],
      provenance: {
        sourceId: source.id,
        platform: "private-platform-name",
        sourceUrl: "https://private.example.invalid/template",
        collectedAt: now,
      },
      syntheticReceipts: [
        receipt,
        { ...receipt, inputSha256: hash("other file") },
      ],
    }),
    inputSha256,
  );
  const result = evidenceSummarySchema.parse(evidenceSummary(parsed));
  assert.equal(result.independentlyVerified, false);
  assert.deepEqual(
    result.syntheticReceipts.map(({ scope }) => scope),
    ["assessed_file", "other_file"],
  );
  assert.equal(result.syntheticReceipts[0].kind, "supplied_observation");
  for (const sensitive of [
    source.id,
    "private-environment-name",
    "private-case-name",
    "private-platform-name",
    "private.example.invalid",
  ])
    assert.equal(JSON.stringify(result).includes(sensitive), false);
  evidenceSummarySchema.parse(evidenceSummary(undefined));
});

test("OSV descriptive fields are bounded input only and discarded from matching records", () => {
  const parsed = parseEvidence(
    fixture({
      advisories: [
        {
          sourceId: source.id,
          document: {
            id: "x_FIXTURE-1",
            modified: now,
            details: "untrusted descriptive content",
            affected: [
              {
                package: {
                  ecosystem: "npm",
                  name: "fixture-package",
                  purl: "pkg:npm/fixture-package",
                },
                ranges: [
                  {
                    type: "SEMVER",
                    events: [{ introduced: "0" }, { fixed: "2.0.0" }],
                  },
                ],
              },
            ],
          },
        },
      ],
    }),
    inputSha256,
  );
  assert.equal(parsed.advisories[0].document.details, undefined);
  assert.equal(
    parsed.advisories[0].document.affected[0].package.purl,
    undefined,
  );
});

test("classification aliases cannot create conflicting same-field policies", () => {
  const annotation = {
    nodeKey: hash("node"),
    field: "/body/password",
    dataClass: "public",
    sourceId: source.id,
  };
  rejects(
    fixture({
      classifications: [
        annotation,
        { ...annotation, field: "body.password", dataClass: "secret" },
      ],
    }),
    "duplicate_evidence",
  );
  const literalDot = parseEvidence(
    fixture({
      classifications: [
        annotation,
        { ...annotation, field: "/body.password", dataClass: "secret" },
        { ...annotation, field: "", dataClass: "internal" },
      ],
    }),
    inputSha256,
  );
  assert.equal(literalDot.classifications.length, 3);
  rejects(
    fixture({
      classifications: [{ ...annotation, field: "/body/~2password" }],
    }),
    "invalid_evidence",
  );
  rejects(
    fixture({
      classifications: [{ ...annotation, field: "body.__proto__.password" }],
    }),
    "invalid_evidence",
  );
});
