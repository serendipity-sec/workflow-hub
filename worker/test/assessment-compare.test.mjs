import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { assessBytes } from "../dist/assessment-engine.js";
import {
  assessmentReportSchema,
  assessmentError,
  assessmentExtensionRules,
  legacyAssessmentExtensionRules,
} from "../dist/assessment-contract.js";
import {
  compareAssessment,
  assessmentComparisonSchema,
} from "../dist/assessment-compare.js";
import { presentFindings } from "../dist/assessment-summary.js";
import { reportStatus, stableId } from "../dist/static-contract.js";

const now = "2026-11-22T00:00:00.000Z";
const hash = (text) => createHash("sha256").update(text).digest("hex");
const encode = (value) => Buffer.from(JSON.stringify(value));
const node = (id, type, version = 1, parameters = {}) => ({
  id,
  name: id,
  type: `n8n-nodes-base.${type}`,
  typeVersion: version,
  parameters,
});
const document = (...nodes) => ({ nodes, connections: {} });
const http = (insecure = true) =>
  node("HTTP", "httpRequest", 4.2, {
    url: "https://synthetic.example.invalid",
    options: { allowUnauthorizedCerts: insecure },
  });
// These callbacks supply unit-level controller records. They never stand in
// for the separately executed native/Docker acceptance harness.
function tools(context, options = {}) {
  const modes = ["nlp", "python"].map((mode) => ({
    mode,
    status: "completed",
    findings: [],
    diagnostics: [],
    versions: {
      python: options.pythonVersion ?? "3.12.10",
      presidio: mode === "nlp" ? "2.2.366" : null,
      spacy: mode === "nlp" ? "3.8.18" : null,
      model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
    },
  }));
  const candidate = context.fields.find(
    (field) =>
      field.kind === "value" &&
      field.value === "synthetic private-person marker",
  );
  if (candidate)
    modes[0].findings.push({
      fieldIndex: candidate.index,
      code: "nlp_person_candidate",
      start: 0,
      end: 9,
      line: null,
    });
  if (options.failed) {
    modes[0] = {
      mode: "nlp",
      status: "error",
      findings: [],
      diagnostics: [{ fieldIndex: null, code: "native_tool_unavailable" }],
      versions: { python: null, presidio: null, spacy: null, model: null },
    };
  }
  return {
    gitleaks: {
      tool: "gitleaks",
      version: "8.30.1",
      status: "completed",
      findings: [],
    },
    native: { tool: "native_inspection", version: "1.0.0", modes },
  };
}
async function report(value, options = {}) {
  const bytes = encode(value);
  const result = await assessBytes(bytes, {
    now: options.now ?? now,
    collectTools: async (context) => tools(context, options),
    ...(options.evidence
      ? { evidenceBytes: encode(options.evidence(bytes)) }
      : {}),
  });
  assert.notEqual(result.status, "error", JSON.stringify(result));
  assert.equal(assessmentReportSchema.safeParse(result).success, true);
  return result;
}
const all = (file) =>
  [
    ...(file.base.status === "error" ? [] : file.base.rules),
    ...file.extensionRules,
  ].flatMap((rule) => rule.findings);
const find = (result, code, index = 0) =>
  all(result.files[index]).find((finding) =>
    finding.evidence.some((evidence) => evidence.code === code),
  );
const recheck = (result, finding, file = result.files[0]) =>
  result.rechecks.find(
    (entry) =>
      entry.filePairKey === file.key && entry.before?.id === finding.id,
  );
function compared(before, after) {
  const result = compareAssessment(before, after);
  assert.equal(
    assessmentComparisonSchema.safeParse(result).success,
    true,
    JSON.stringify(result),
  );
  assert.equal(result.behaviorPreserved, "not_verified");
  assert.equal(result.exploitBlocked, "not_verified");
  assert.equal(result.securityEquivalent, "not_claimed");
  return result;
}

test("every base and extension finding is accounted for, with info observations kept separate from a safety claim", async () => {
  const result = await report(
    document(
      http(),
      node("SQL", "postgres", 2.8, {
        operation: "executeQuery",
        query: "SELECT value FROM sample WHERE id = $1",
        options: { queryReplacement: "={{ [ $json.body.id ] }}" },
      }),
      node("Notes", "stickyNote", 1, {
        content: "synthetic private-person marker",
      }),
    ),
  );
  assert.equal(result.files[0].extensionRules.length, 19);
  assert.deepEqual(
    new Set(result.files[0].extensionRules.map((rule) => rule.ruleId)),
    new Set(assessmentExtensionRules),
  );
  assert.ok(find(result, "nlp_person_candidate"));
  assert.ok(find(result, "sql_operation_capability"));
  const comparison = compared(result, result);
  const expected = result.files.flatMap((file) => all(file));
  assert.equal(comparison.counts.beforeFindings, expected.length);
  assert.equal(comparison.counts.afterFindings, expected.length);
  assert.equal(comparison.newFindings.length, 0);
  assert.ok(
    comparison.rechecks.every((entry) => entry.status === "persisting"),
  );
  assert.deepEqual(
    new Set(comparison.rechecks.map((entry) => entry.before.id)),
    new Set(expected.map((finding) => finding.id)),
  );
  assert.ok(
    comparison.rechecks.some((entry) => entry.before.severity === "info"),
  );
});

test("a checked TLS option disappearance and its inverse are bounded observations", async () => {
  const before = await report(document(http(true)));
  const after = await report(document(http(false)));
  const finding = find(before, "tls_certificate_validation_disabled");
  assert.ok(finding);
  const change = compared(before, after);
  assert.equal(recheck(change, finding).status, "not_observed");
  assert.equal(change.beforeSha256, before.inputSha256);
  assert.equal(change.afterSha256, after.inputSha256);
  const inverse = compared(after, before);
  assert.equal(
    inverse.newFindings.find((entry) => entry.after?.id === finding.id).status,
    "newly_observed",
  );
});

test("native extension disappearance is compared, but tool failure or a native version change prevents that conclusion", async () => {
  const original = document(
    node("Notes", "stickyNote", 1, {
      content: "synthetic private-person marker",
    }),
  );
  const revised = structuredClone(original);
  revised.nodes[0].parameters.content = "";
  const before = await report(original);
  const after = await report(revised);
  const finding = find(before, "nlp_person_candidate");
  assert.equal(
    recheck(compared(before, after), finding).status,
    "not_observed",
  );
  for (const options of [{ failed: true }, { pythonVersion: "3.12.11" }]) {
    const entry = recheck(
      compared(before, await report(revised, options)),
      finding,
    );
    assert.equal(entry.status, "inconclusive");
    assert.ok(
      entry.codes.includes(
        options.failed ? "tool_failed" : "native_profile_changed",
      ),
    );
  }
});

test("deletion, disabling, and unsupported versions never clear the earlier observation", async () => {
  const before = await report(document(http(true)));
  const finding = find(before, "tls_certificate_validation_disabled");
  const removed = await report(document(node("Start", "manualTrigger")));
  assert.ok(
    recheck(compared(before, removed), finding).codes.includes("node_removed"),
  );
  const disabledNode = { ...http(false), disabled: true };
  const disabled = recheck(
    compared(before, await report(document(disabledNode))),
    finding,
  );
  assert.equal(disabled.status, "inconclusive");
  assert.ok(disabled.codes.includes("node_disabled"));
  const unknown = http(false);
  unknown.typeVersion = 99;
  const unsupported = recheck(
    compared(before, await report(document(unknown))),
    finding,
  );
  assert.equal(unsupported.status, "inconclusive");
  assert.ok(unsupported.codes.includes("scope_not_checked"));
});

test("array reorder preserves stable matching and name-derived identity is explicit", async () => {
  const first = document(http(true), node("Start", "manualTrigger"));
  const before = await report(first);
  first.nodes.reverse();
  const after = await report(first);
  const finding = find(before, "tls_certificate_validation_disabled");
  assert.equal(recheck(compared(before, after), finding).status, "persisting");
  const derived = document(http(true));
  delete derived.nodes[0].id;
  const derivedBefore = await report(derived);
  derived.nodes[0].parameters.options.allowUnauthorizedCerts = false;
  const derivedAfter = await report(derived);
  const derivedFinding = find(
    derivedBefore,
    "tls_certificate_validation_disabled",
  );
  const observed = recheck(
    compared(derivedBefore, derivedAfter),
    derivedFinding,
  );
  assert.equal(observed.status, "not_observed");
  assert.ok(observed.codes.includes("name_derived_identity"));
  derived.nodes[0].name = "Renamed";
  const renamed = recheck(
    compared(derivedBefore, await report(derived)),
    derivedFinding,
  );
  assert.equal(renamed.status, "inconclusive");
  assert.ok(renamed.codes.includes("node_identity_unmatched"));
});

test("an earlier report without node inventory and engine changes remain readable but inconclusive", async () => {
  const before = await report(document(http(true)));
  const after = await report(document(http(false)));
  const finding = find(before, "tls_certificate_validation_disabled");
  const historical = structuredClone(before);
  historical.engineVersion = "0.3.0";
  for (const file of historical.files) {
    file.extensionRules = file.extensionRules.filter((rule) =>
      legacyAssessmentExtensionRules.includes(rule.ruleId),
    );
    const remaining = new Set(
      [...file.base.rules, ...file.extensionRules].flatMap((rule) =>
        rule.findings.map((f) => f.id),
      ),
    );
    file.policy.findingDecisions = file.policy.findingDecisions.filter(
      (decision) => remaining.has(decision.findingId),
    );
    delete file.functionSummary;
    delete file.findingPresentation;
  }
  assert.equal(assessmentReportSchema.safeParse(historical).success, true);
  const changed = compared(historical, after);
  assert.equal(changed.basis, "incompatible_or_failed");
  assert.ok(
    recheck(changed, finding).codes.includes("assessment_engine_changed"),
  );
  assert.ok(
    recheck(compared(historical, historical), finding).codes.includes(
      "node_inventory_unavailable",
    ),
  );
});

test("rule profile and coverage shrinkage prevent disappearance classification", async () => {
  const before = await report(document(http(true)));
  const after = await report(document(http(false)));
  const finding = find(before, "tls_certificate_validation_disabled");
  const updated = structuredClone(after);
  updated.files[0].base.rules.find(
    (rule) => rule.ruleId === finding.ruleId,
  ).profileVersion = "1.1.0";
  assert.equal(assessmentReportSchema.safeParse(updated).success, true);
  assert.ok(
    recheck(compared(before, updated), finding).codes.includes(
      "rule_profile_changed",
    ),
  );
  const reduced = structuredClone(after);
  const rule = reduced.files[0].base.rules.find(
    (item) => item.ruleId === finding.ruleId,
  );
  rule.coverage = [
    {
      location: rule.coverage[0].location,
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    },
  ];
  rule.findings = [];
  reduced.files[0].findingPresentation = presentFindings(all(reduced.files[0]));
  assert.equal(assessmentReportSchema.safeParse(reduced).success, true);
  const incomplete = recheck(compared(before, reduced), finding);
  assert.equal(incomplete.status, "inconclusive");
  assert.ok(incomplete.codes.includes("coverage_changed"));
});

test("document-wide partial node coverage is not hidden by a checked node scope", async () => {
  const original = document(http(), node("Next", "noOp"));
  Object.assign(original.nodes[0].parameters, {
    sendBody: true,
    contentType: "json",
    specifyBody: "json",
    jsonBody: "{}",
  });
  // The producer reports this non-main channel as partial workflow topology.
  // Both versions have the same limitation; only the body option changes.
  original.connections = {
    HTTP: { ai_tool: [[{ node: "Next", type: "ai_tool", index: 0 }]] },
  };
  const before = await report(original);
  original.nodes[0].parameters.sendBody = false;
  const after = await report(original);
  const rule = before.files[0].base.rules.find(
    (item) => item.ruleId === "N8N_HTTP_EGRESS",
  );
  assert.ok(
    rule.coverage.some(
      (item) => item.location.nodeKey !== null && item.status === "checked",
    ),
  );
  assert.ok(
    rule.coverage.some(
      (item) => item.location.pointer === "/nodes" && item.status === "partial",
    ),
  );
  const finding = find(before, "configured_outbound_body");
  assert.ok(finding);
  const entry = recheck(compared(before, after), finding);
  assert.equal(entry.status, "inconclusive");
  assert.ok(entry.codes.includes("scope_not_checked"));
  assert.equal(
    entry.codes.includes("observation_not_seen_in_checked_scope"),
    false,
  );
});

function sidecar(input, policyVersion = "v1") {
  return {
    schemaVersion: "1.0.0",
    inputSha256: hash(input),
    sources: [
      {
        id: "operator",
        kind: "declaration",
        method: "user_declaration",
        recordedAt: now,
      },
    ],
    policy: {
      id: "policy",
      version: policyVersion,
      sourceId: "operator",
      purpose: "Synthetic comparison policy",
      defaultDecision: "review",
      unknownDecision: "inconclusive",
    },
  };
}
test("policy, rebound evidence, evaluation time, and isolation changes are independent comparison boundaries", async () => {
  const before = await report(document(http(true)), { evidence: sidecar });
  const after = await report(document(http(false)), {
    evidence: (input) => sidecar(input, "v2"),
  });
  const finding = find(before, "tls_certificate_validation_disabled");
  const entry = recheck(compared(before, after), finding);
  assert.equal(entry.status, "inconclusive");
  assert.ok(entry.codes.includes("policy_context_changed"));
  assert.ok(entry.codes.includes("evidence_context_changed"));
  const later = await report(document(http(true)), {
    evidence: sidecar,
    now: "2026-11-23T00:00:00.000Z",
  });
  assert.ok(
    recheck(compared(before, later), finding).codes.includes(
      "policy_evaluation_time_changed",
    ),
  );
  const isolated = structuredClone(before);
  isolated.boundary = {
    kind: "docker",
    isolationVerified: true,
    imageSha256: hash("synthetic-image"),
    network: "none",
    readOnlyRoot: true,
    uid: 65532,
    memoryMiB: 1024,
    pids: 96,
    cpus: 1,
  };
  assert.ok(
    compared(before, isolated).codes.includes("isolation_boundary_changed"),
  );
});

const inlineParent = (child, id = "Call") =>
  node(id, "executeWorkflow", 1.4, {
    source: "parameter",
    workflowJson: JSON.stringify(child),
  });
test("identical children pair by caller route and hash when the parent's bytes and analysis key change", async () => {
  const child = document(http());
  const original = document(
    inlineParent(child, "Call A"),
    inlineParent(child, "Call B"),
  );
  const before = await report(original);
  const modified = structuredClone(original);
  modified.name = "Changed parent metadata";
  modified.nodes.reverse();
  const after = await report(modified);
  const result = compared(before, after);
  assert.notEqual(before.files[1].analysisKey, after.files[1].analysisKey);
  const children = result.files.filter(
    (pair) => pair.correspondence === "same_child_hash",
  );
  assert.equal(children.length, 2);
  assert.equal(new Set(children.map((pair) => pair.key)).size, 2);
  assert.ok(
    children.every(
      (pair) => pair.before.inputSha256 === pair.after.inputSha256,
    ),
  );
  for (const pair of children)
    assert.ok(
      result.rechecks
        .filter((entry) => entry.filePairKey === pair.key)
        .every((entry) => entry.status === "persisting"),
    );
  assert.equal(
    result.counts.beforeFindings,
    before.files.reduce((total, file) => total + all(file).length, 0),
  );
});

test("changed child bytes, missing child definitions and disabled callers are never fixes", async () => {
  const child = document(http(true));
  const original = document(inlineParent(child));
  const before = await report(original);
  const finding = find(before, "tls_certificate_validation_disabled", 1);
  const revised = await report(document(inlineParent(document(http(false)))));
  const modified = compared(before, revised);
  const pair = modified.files.find(
    (item) => item.correspondence === "changed_child_hash",
  );
  assert.equal(recheck(modified, finding, pair).status, "inconclusive");
  assert.ok(
    recheck(modified, finding, pair).codes.includes("child_definition_changed"),
  );
  for (const caller of [
    node("Call", "executeWorkflow", 1.4, {
      source: "database",
      workflowId: "unavailable",
    }),
    { ...inlineParent(child), disabled: true },
  ]) {
    const result = compared(before, await report(document(caller)));
    const missing = result.files.find(
      (item) => item.correspondence === "before_only",
    );
    assert.equal(recheck(result, finding, missing).status, "inconclusive");
    assert.ok(
      missing.codes.includes(
        caller.disabled ? "child_disabled" : "child_definition_missing",
      ),
    );
  }
});

test("identical grandchildren do not bypass a changed ancestor definition", async () => {
  const grandchild = document(http(true));
  const child = document(inlineParent(grandchild));
  const before = await report(document(inlineParent(child)));
  child.name = "Changed child metadata";
  const after = await report(document(inlineParent(child)));
  const result = compared(before, after);
  const grandchildPair = result.files.find((pair) => pair.before?.depth === 2);
  assert.equal(grandchildPair.correspondence, "same_child_hash");
  assert.ok(grandchildPair.codes.includes("child_definition_changed"));
  assert.ok(
    result.rechecks
      .filter((entry) => entry.filePairKey === grandchildPair.key)
      .every((entry) => entry.status === "inconclusive"),
  );
});

test("all 18 extension rule findings are included even when the base report cannot classify the observation", async () => {
  const fixture = await report(document(http()));
  for (const rule of fixture.files[0].extensionRules) {
    const location = {
      nodeKey: fixture.files[0].functionSummary.nodes[0].nodeKey,
      pointer: "/nodes/0/parameters",
    };
    const id = stableId(
      rule.ruleId,
      location,
      "synthetic_contract_observation",
    );
    const finding = {
      id,
      ruleId: rule.ruleId,
      category: rule.category,
      severity: "info",
      claim: "configuration",
      location,
      evidence: [{ code: "synthetic_contract_observation", location }],
      assumptions: ["unit_contract_fixture"],
      remediation: {
        code: "review_configuration",
        checks: ["rescan_exact_file"],
      },
    };
    rule.findings.push(finding);
    rule.coverage.push({
      location,
      status: "checked",
      findingIds: [id],
      diagnosticIds: [],
    });
  }
  fixture.files[0].findingPresentation = presentFindings(all(fixture.files[0]));
  fixture.status = reportStatus([
    ...fixture.files[0].base.rules,
    ...fixture.files[0].extensionRules,
  ]);
  assert.equal(assessmentReportSchema.safeParse(fixture).success, true);
  const result = compared(fixture, fixture);
  for (const rule of fixture.files[0].extensionRules)
    assert.ok(
      result.rechecks.some((entry) => entry.before?.ruleId === rule.ruleId),
    );
});

test("comparison exports only bounded references and fixed reason codes, not user paths or evidence text", async () => {
  const fixture = await report(document(http()));
  const finding = find(fixture, "tls_certificate_validation_disabled");
  const privateMarker = "private_customer_01012345678";
  finding.location.pointer += "/" + privateMarker;
  finding.evidence.push({ code: privateMarker, location: finding.location });
  assert.equal(assessmentReportSchema.safeParse(fixture).success, true);
  const serialized = JSON.stringify(compared(fixture, fixture));
  assert.equal(serialized.includes(privateMarker), false);
  assert.equal(serialized.includes("synthetic.example.invalid"), false);
});

test("strict comparison validation rejects altered totals, duplicate rows and unsupported safety claims", async () => {
  const before = await report(document(http(true)));
  const after = await report(document(http(false)));
  const result = compared(before, after);
  assert.equal(
    assessmentComparisonSchema.safeParse({ ...result, exploitBlocked: true })
      .success,
    false,
  );
  assert.equal(
    assessmentComparisonSchema.safeParse({ ...result, raw: "unexpected" })
      .success,
    false,
  );
  const countChanged = structuredClone(result);
  countChanged.counts.beforeFindings++;
  assert.equal(
    assessmentComparisonSchema.safeParse(countChanged).success,
    false,
  );
  const duplicate = structuredClone(result);
  duplicate.rechecks.push(duplicate.rechecks[0]);
  assert.equal(assessmentComparisonSchema.safeParse(duplicate).success, false);
  const incompatible = compared(before, { ...after, engineVersion: "unknown" });
  assert.equal(incompatible.status, "inconclusive");
  assert.equal(incompatible.basis, "incompatible_or_failed");
  assert.ok(incompatible.codes.includes("invalid_after_report"));
  assert.equal(incompatible.counts.beforeFindings, all(before.files[0]).length);
  assert.ok(
    incompatible.rechecks.every((entry) => entry.status === "inconclusive"),
  );
  const contradictory = structuredClone(result);
  contradictory.rechecks
    .find((entry) => entry.status === "not_observed")
    .codes.push("tool_failed");
  assert.equal(
    assessmentComparisonSchema.safeParse(contradictory).success,
    false,
  );
});

test("a failed whole-file recheck retains the valid baseline instead of showing an empty clean comparison", async () => {
  const before = await report(document(http(true)));
  const failed = assessmentError(hash("failed-input"), "assessment_timeout");
  const result = compared(before, failed);
  assert.equal(result.basis, "incompatible_or_failed");
  assert.equal(result.counts.beforeFindings, all(before.files[0]).length);
  assert.ok(
    result.rechecks.every(
      (entry) =>
        entry.status === "inconclusive" &&
        entry.codes.includes("after_assessment_failed"),
    ),
  );
  const reverse = compared(failed, before);
  assert.equal(reverse.counts.afterFindings, all(before.files[0]).length);
  assert.ok(
    reverse.newFindings.every((entry) => entry.status === "inconclusive"),
  );
});
