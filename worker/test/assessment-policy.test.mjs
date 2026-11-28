import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  assessDestination,
  parseEvidence,
} from "../dist/assessment/assessment-evidence.js";
import {
  evaluatePolicy,
  policyEvaluationSchema,
} from "../dist/assessment/assessment-policy.js";
import {
  categories,
  reportStatus,
  stableId,
  staticReportSchema,
  staticResultVersions,
} from "../dist/contracts/static-contract.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const inputSha256 = hash("policy fixture");
const nodeKey = hash("node");
const now = "2026-11-22T00:00:00.000Z";
const source = {
  id: "policy-source",
  kind: "declaration",
  method: "user_declaration",
  recordedAt: now,
};
const policy = {
  id: "fixture-policy",
  version: "1.0.0",
  sourceId: source.id,
  purpose: "synthetic export",
  defaultDecision: "allow",
  unknownDecision: "inconclusive",
};
const evidence = (changes = {}, extra = {}) =>
  parseEvidence(
    {
      schemaVersion: "1.0.0",
      inputSha256,
      sources: [source],
      policy: { ...policy, ...changes },
      ...extra,
    },
    inputSha256,
  );

test("a known forbidden class remains disallowed with an unknown or malformed destination", () => {
  for (const sink of ["http", "ai_model", "ai_vector_store"]) {
    const supplied = evidence({
      egress: [
        {
          id: "fixed-sink",
          nodeKey,
          sink,
          mode: "allowlist",
          destinations: ["https://example.invalid"],
          allowedDataClasses: ["public"],
          purpose: "synthetic transfer boundary",
        },
      ],
    });
    for (const destination of [null, "=unresolved-destination"]) {
      const denied = assessDestination(supplied, nodeKey, sink, destination, [
        "secret",
        "unknown",
      ]);
      assert.equal(denied.status, "disallowed");
      assert.deepEqual(denied.codes, ["data_class_not_allowed"]);
      assert.equal(
        assessDestination(supplied, nodeKey, sink, destination, ["unknown"])
          .status,
        "unknown",
      );
      assert.equal(
        assessDestination(supplied, nodeKey, sink, destination, ["public"])
          .status,
        "unknown",
      );
    }
    assert.equal(
      assessDestination(undefined, nodeKey, sink, null, ["secret"]).status,
      "unknown",
    );
    assert.equal(
      assessDestination(supplied, hash("different-node"), sink, null, [
        "secret",
      ]).status,
      "unknown",
    );
  }
});
const review = {
  inputSha256,
  sourceId: source.id,
  reviewId: "file-review",
  reviewerId: "reviewer",
  status: "approved",
  recordedAt: "2026-11-21T00:00:00.000Z",
  expiresAt: "2026-11-23T00:00:00.000Z",
  scopes: ["secrets", "pii", "internal_addresses", "account_references"],
  policyId: policy.id,
  policyVersion: policy.version,
};
function report(
  category = null,
  code = "synthetic_configuration",
  partial = false,
) {
  const rules = categories.map((value, index) => {
    const ruleId = `FIXTURE_RULE_${index}`;
    const location = { nodeKey: null, pointer: "" };
    const findings =
      value === category
        ? [
            {
              id: stableId(ruleId, location, code),
              ruleId,
              category: value,
              severity: "high",
              claim: "candidate",
              location,
              evidence: [{ code, location }],
              assumptions: [],
              remediation: {
                code: "review_configuration",
                checks: ["reassess_file"],
              },
            },
          ]
        : [];
    const diagnostics =
      partial && index === 0
        ? [
            {
              id: stableId(ruleId, location, "unsupported_fixture"),
              code: "unsupported_fixture",
              location,
            },
          ]
        : [];
    return {
      ruleId,
      category: value,
      profileVersion: "1.0.0",
      findings,
      diagnostics,
      coverage: [
        {
          location,
          status: diagnostics.length
            ? "partial"
            : findings.length
              ? "checked"
              : "not_applicable",
          findingIds: findings.map(({ id }) => id),
          diagnosticIds: diagnostics.map(({ id }) => id),
        },
      ],
    };
  });
  return staticReportSchema.parse({
    ...staticResultVersions,
    inputSha256,
    execution: "not_run",
    status: reportStatus(rules),
    rules,
  });
}
function evaluate(base, metadata) {
  return policyEvaluationSchema.parse(evaluatePolicy(base, [], metadata, now));
}

test("SEC-POLICY-01 identical transmission has separate destination and data decisions", () => {
  const egress = [
    {
      id: "egress-rule",
      nodeKey,
      sink: "http",
      mode: "allowlist",
      destinations: ["https://allowed.example.invalid"],
      allowedDataClasses: ["public"],
      purpose: "public feed",
    },
  ];
  const provided = evidence({ egress });
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "http",
      "https://allowed.example.invalid/path?q=x",
      ["public"],
    ).status,
    "allowed",
  );
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "http",
      "https://other.example.invalid/path",
      ["public"],
    ).status,
    "disallowed",
  );
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "http",
      "https://allowed.example.invalid/path",
      ["personal"],
    ).status,
    "disallowed",
  );
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "http",
      "https://allowed.example.invalid/path",
      ["unknown"],
    ).status,
    "unknown",
  );
  assert.equal(
    assessDestination(provided, nodeKey, "http", null, ["public"]).status,
    "unknown",
  );
  assert.equal(
    assessDestination(
      undefined,
      nodeKey,
      "http",
      "https://allowed.example.invalid",
      ["public"],
    ).status,
    "unknown",
  );
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "http",
      "https://user:secret@allowed.example.invalid",
      ["public"],
    ).status,
    "unknown",
  );
});

test("destination rules reject display-name email syntax and match symbolic outputs exactly", () => {
  const egress = [
    {
      id: "email-rule",
      nodeKey,
      sink: "email",
      mode: "denylist",
      destinations: ["blocked@example.invalid"],
      allowedDataClasses: ["public"],
      purpose: "notification",
    },
    {
      id: "response-rule",
      nodeKey,
      sink: "response",
      mode: "allowlist",
      destinations: ["caller"],
      allowedDataClasses: ["public"],
      purpose: "response",
    },
  ];
  const provided = evidence({ egress });
  assert.equal(
    assessDestination(provided, nodeKey, "email", "blocked@example.invalid", [
      "public",
    ]).status,
    "disallowed",
  );
  assert.equal(
    assessDestination(
      provided,
      nodeKey,
      "email",
      "Display <ok@example.invalid>",
      ["public"],
    ).status,
    "unknown",
  );
  assert.equal(
    assessDestination(provided, nodeKey, "response", "caller", ["public"])
      .status,
    "allowed",
  );
  assert.equal(
    assessDestination(provided, nodeKey, "response", "anyone", ["public"])
      .status,
    "unknown",
  );
});

test("SEC-POLICY-02 scoped active exceptions preserve findings and expire without changing analysis", () => {
  const base = report("transport");
  const original = JSON.stringify(base);
  const findingId = base.rules.find(({ category }) => category === "transport")
    .findings[0].id;
  const exception = {
    id: "approved-risk",
    findingId,
    inputSha256,
    decision: "allow",
    kind: "risk_acceptance",
    subjectId: "reviewer",
    reasonCode: "synthetic_case_accepted",
    sourceId: source.id,
    approvedAt: "2026-11-21T00:00:00.000Z",
    expiresAt: "2026-11-23T00:00:00.000Z",
  };
  const blocking = {
    rules: [
      { category: "transport", minimumSeverity: "high", decision: "block" },
    ],
  };
  assert.equal(evaluate(base, evidence(blocking)).decision, "block");
  const accepted = evaluate(
    base,
    evidence({ ...blocking, exceptions: [exception] }),
  );
  assert.equal(accepted.decision, "allow");
  assert.equal(accepted.findingDecisions.length, 1);
  assert.ok(accepted.findingDecisions[0].exceptionKey);
  assert.equal(
    evaluate(
      base,
      evidence({ ...blocking, exceptions: [{ ...exception, expiresAt: now }] }),
    ).decision,
    "block",
  );
  assert.equal(
    evaluate(
      base,
      evidence({
        ...blocking,
        exceptions: [{ ...exception, inputSha256: hash("other") }],
      }),
    ).decision,
    "block",
  );
  assert.equal(JSON.stringify(base), original);
});

test("policy cannot convert incomplete analysis or an analyzer failure into permission", () => {
  const base = report("transport", "synthetic_configuration", true);
  assert.equal(evaluate(base, evidence()).decision, "inconclusive");
  assert.equal(
    evaluate(base, evidence({ unknownDecision: "block" })).decision,
    "block",
  );
  const failed = {
    ...staticResultVersions,
    inputSha256,
    execution: "not_run",
    status: "error",
    code: "invalid_result",
  };
  assert.equal(evaluate(failed, evidence()).status, "analysis_failed");
  assert.equal(evaluate(report(), undefined).publication.status, "hold");
});

test("file authentication and AI approval requirements remain explicit policy facts", () => {
  assert.equal(
    evaluate(
      report("request_auth", "webhook_authentication_default_none"),
      evidence(
        {},
        {
          runtime: {
            sourceId: source.id,
            environmentId: "env",
            n8nVersion: "2.0.0",
            upstreamAuthentication: [
              { nodeKey, kind: "jwt", enforced: true, sourceId: source.id },
            ],
          },
        },
      ),
    ).decision,
    "block",
  );
  assert.equal(
    evaluate(
      report("dependencies", "ai_tool_approval_not_declared"),
      evidence(),
    ).decision,
    "block",
  );
  assert.equal(
    evaluate(report("egress", "data_class_not_allowed"), evidence()).decision,
    "block",
  );
});

test("public-file prerequisite checks exact bytes, current review, full exposure scope and policy identity", () => {
  const base = report();
  assert.equal(evaluate(base, evidence()).publication.status, "hold");
  const eligible = evaluate(base, evidence({}, { publicationReview: review }));
  assert.equal(eligible.publication.status, "eligible_for_service_review");
  assert.equal(eligible.authority, "local_policy_evaluation_only");
  for (const mutation of [
    { inputSha256: hash("changed bytes") },
    { expiresAt: now },
    { scopes: ["secrets"] },
    { policyVersion: "2.0.0" },
    { status: "pending" },
  ])
    assert.equal(
      evaluate(
        base,
        evidence({}, { publicationReview: { ...review, ...mutation } }),
      ).publication.status,
      "hold",
    );
  assert.equal(
    evaluate(
      base,
      evidence(
        { requirePublicationReview: false },
        { publicationReview: review },
      ),
    ).publication.status,
    "hold",
  );
  assert.equal(
    evaluate(
      base,
      evidence({}, { publicationReview: { ...review, status: "rejected" } }),
    ).publication.status,
    "rejected",
  );
});

test("risk acceptance cannot publish a secret candidate while a scoped false-positive review can", () => {
  const base = report("secrets");
  const findingId = base.rules[0].findings[0].id;
  const exception = {
    id: "secret-review",
    findingId,
    inputSha256,
    decision: "allow",
    kind: "risk_acceptance",
    subjectId: "reviewer",
    reasonCode: "fixture_review",
    sourceId: source.id,
    approvedAt: "2026-11-21T00:00:00.000Z",
    expiresAt: "2026-11-23T00:00:00.000Z",
  };
  assert.equal(
    evaluate(
      base,
      evidence({ exceptions: [exception] }, { publicationReview: review }),
    ).publication.status,
    "hold",
  );
  assert.equal(
    evaluate(
      base,
      evidence(
        { exceptions: [{ ...exception, kind: "false_positive" }] },
        { publicationReview: review },
      ),
    ).publication.status,
    "eligible_for_service_review",
  );
  const provenance = {
    sourceId: source.id,
    platform: "synthetic",
    sourceUrl: "https://fixture.invalid/source",
    collectedAt: now,
    license: {
      identifier: "LicenseRef-Fixture",
      redistribution: "restricted",
      evidenceUrl: "https://fixture.invalid/license",
    },
  };
  assert.equal(
    evaluate(report(), evidence({}, { publicationReview: review, provenance }))
      .publication.status,
    "rejected",
  );
});

test("policy output schema rejects contradictory sandbox claims", () => {
  const missing = evaluate(report(), undefined);
  for (const mutation of [
    { decision: "allow" },
    { policyKey: hash("invented policy") },
    {
      publication: {
        status: "eligible_for_service_review",
        codes: ["authenticated_service_publication_check_still_required"],
      },
    },
  ])
    assert.equal(
      policyEvaluationSchema.safeParse({ ...missing, ...mutation }).success,
      false,
    );
  const eligible = evaluate(
    report(),
    evidence({}, { publicationReview: review }),
  );
  assert.equal(
    policyEvaluationSchema.safeParse({ ...eligible, decision: "block" })
      .success,
    false,
  );
  assert.equal(
    policyEvaluationSchema.safeParse({
      ...eligible,
      publication: { ...eligible.publication, codes: [] },
    }).success,
    false,
  );
  const blocked = evaluate(
    report("egress", "data_class_not_allowed"),
    evidence(),
  );
  assert.equal(
    policyEvaluationSchema.safeParse({ ...blocked, decision: "allow" }).success,
    false,
  );
});
