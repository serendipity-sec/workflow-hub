import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  assessDependencies,
  assessEnvironment,
  dependencyResultsSchema,
  matchAdvisory,
} from "../dist/assessment-environment.js";
import {
  osvDocumentSchema,
  parseEvidence,
} from "../dist/assessment-evidence.js";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const now = "2026-11-22T00:00:00.000Z";
const source = {
  id: "environment-source",
  kind: "declaration",
  method: "user_declaration",
  recordedAt: now,
};
const node = (name, type, typeVersion = 1) => ({
  id: `fixture-${name}`,
  name,
  type,
  typeVersion,
  parameters: {},
});
function workflow(nodes, connections = {}) {
  const bytes = Buffer.from(JSON.stringify({ nodes, connections }));
  return { context: createContext(bytes), inputSha256: hash(bytes) };
}
const community = workflow([
  node("Community", "fixture-community-node.action", 7),
]);
const evidence = (target, extra = {}) =>
  parseEvidence(
    {
      schemaVersion: "1.0.0",
      inputSha256: target.inputSha256,
      sources: [source],
      ...extra,
    },
    target.inputSha256,
  );
const advisory = (
  events = [{ introduced: "0" }, { fixed: "2.0.0" }],
  extra = {},
) =>
  osvDocumentSchema.parse({
    id: "x_FIXTURE-1",
    modified: now,
    affected: [
      {
        package: { ecosystem: "npm", name: "fixture-package" },
        ranges: [{ type: "SEMVER", events }],
      },
    ],
    ...extra,
  });
const codes = (rule) =>
  rule.findings.flatMap(({ evidence }) => evidence.map(({ code }) => code));
const diagnostics = (rule) => rule.diagnostics.map(({ code }) => code);
function assess(target, provided) {
  const rules = assessEnvironment(target.context, provided);
  rules.forEach((rule) => ruleResultSchema.parse(rule));
  return Object.fromEntries(rules.map((rule) => [rule.ruleId, rule]));
}

test("OSV npm boundaries support introduced, fixed, last affected, limits and prereleases", () => {
  const document = advisory([
    { introduced: "1.0.0" },
    { fixed: "2.0.0" },
    { introduced: "3.0.0" },
    { last_affected: "3.1.0" },
    { introduced: "4.0.0" },
    { limit: "4.2.0" },
  ]);
  for (const version of [
    "1.0.0",
    "1.5.0",
    "2.0.0-rc.1",
    "3.0.0",
    "3.1.0",
    "4.1.0",
  ])
    assert.equal(
      matchAdvisory("fixture-package", version, document).status,
      "affected",
      version,
    );
  for (const version of ["0.9.0", "2.0.0", "3.1.1", "4.2.0"])
    assert.equal(
      matchAdvisory("fixture-package", version, document).status,
      "not_affected",
      version,
    );
  assert.equal(
    matchAdvisory("fixture-package", "0.0.1", advisory()).status,
    "affected",
  );
  const explicit = advisory([], {
    affected: [
      {
        package: { ecosystem: "npm", name: "fixture-package" },
        versions: ["9.1.0"],
      },
    ],
  });
  assert.equal(
    matchAdvisory("fixture-package", "9.1.0", explicit).status,
    "affected",
  );
  assert.equal(
    matchAdvisory("fixture-package", "9.2.0", explicit).status,
    "not_affected",
  );
});

test("unsupported or malformed advisory semantics remain unknown, including withdrawn snapshots", () => {
  const git = advisory([], {
    affected: [
      {
        package: { ecosystem: "npm", name: "fixture-package" },
        ranges: [
          { type: "GIT", events: [{ introduced: "abc" }, { fixed: "def" }] },
        ],
      },
    ],
  });
  for (const document of [
    git,
    advisory([{ fixed: "2.0.0" }]),
    advisory([{ introduced: "2.0.0" }, { fixed: "1.0.0" }]),
    advisory(undefined, { withdrawn: now }),
  ])
    assert.equal(
      matchAdvisory("fixture-package", "1.0.0", document).status,
      "unknown",
    );
  assert.equal(
    matchAdvisory("other-package", "1.0.0", advisory()).status,
    "unknown",
  );
  assert.equal(
    matchAdvisory("fixture-package", "not-a-version", advisory()).status,
    "unknown",
  );
  const ecosystem = advisory([], {
    affected: [
      {
        package: { ecosystem: "npm", name: "fixture-package" },
        ranges: [
          {
            type: "ECOSYSTEM",
            events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
          },
        ],
      },
    ],
  });
  assert.equal(
    matchAdvisory("fixture-package", "1.4.0", ecosystem).status,
    "affected",
  );
});

test("SEC-DEP-01 actual supplied package version controls matching and typeVersion never substitutes", () => {
  const nodeKey = community.context.nodes[0].key;
  const bundle = (version) =>
    evidence(community, {
      packages: [
        {
          name: "fixture-package",
          version,
          nodeKeys: [nodeKey],
          sourceId: source.id,
        },
      ],
      advisories: [{ sourceId: source.id, document: advisory() }],
    });
  const affected = dependencyResultsSchema.parse(
    assessDependencies(community.context, bundle("1.0.0")),
  );
  assert.equal(affected[0].status, "affected");
  assert.equal(affected[0].observationKind, "declaration");
  assert.equal(affected[0].independentlyVerified, false);
  assert.equal(
    assessDependencies(community.context, bundle("2.0.0"))[0].status,
    "not_affected",
  );
  assert.deepEqual(assessDependencies(community.context, undefined), []);
  assert.ok(
    diagnostics(
      assess(community, undefined).CONTEXT_PACKAGE_ADVISORIES,
    ).includes("external_node_package_evidence_missing"),
  );
  const noSnapshot = evidence(community, {
    packages: [
      {
        name: "fixture-package",
        version: "2.0.0",
        nodeKeys: [nodeKey],
        sourceId: source.id,
      },
    ],
  });
  assert.equal(
    assessDependencies(community.context, noSnapshot)[0].status,
    "unknown",
  );
  assert.equal(JSON.stringify(affected).includes("fixture-package"), false);
});

test("SEC-ENV-01 runtime version and credential/network/auth declarations keep verification boundaries", () => {
  const nodeKey = community.context.nodes[0].key;
  const supplied = evidence(community, {
    runtime: {
      sourceId: source.id,
      environmentId: "private-instance",
      n8nVersion: "2.0.0",
      credentialScopes: [
        { nodeKey, scopes: ["database:write", "*"], sourceId: source.id },
      ],
      networkControls: [
        { kind: "dns_validation", enabled: true, sourceId: source.id },
      ],
      upstreamAuthentication: [
        { nodeKey, kind: "jwt", enforced: true, sourceId: source.id },
      ],
    },
    packages: [{ name: "n8n", version: "1.0.0", sourceId: source.id }],
  });
  const result = assess(community, supplied).CONTEXT_RUNTIME_EVIDENCE;
  assert.ok(codes(result).includes("runtime_version_supplied"));
  assert.ok(codes(result).includes("broad_credential_scope_declared"));
  assert.ok(codes(result).includes("dns_validation_declared_enabled"));
  assert.ok(
    codes(result).includes("upstream_authentication_declared_enforced"),
  );
  assert.ok(diagnostics(result).includes("runtime_package_version_conflict"));
  assert.ok(
    diagnostics(result).includes(
      "upstream_authentication_not_independently_verified",
    ),
  );
  for (const item of result.findings)
    assert.ok(
      item.assumptions.includes("supplied_evidence_not_independently_verified"),
    );
  assert.equal(JSON.stringify(result).includes("private-instance"), false);
  assert.ok(
    diagnostics(assess(community, undefined).CONTEXT_RUNTIME_EVIDENCE).includes(
      "runtime_evidence_missing",
    ),
  );
});

test("SEC-AI-01 external input, model, tool and approval are structural claims with runtime uncertainty", () => {
  const target = workflow(
    [
      node("Webhook", "n8n-nodes-base.webhook", 2),
      node("Agent", "@n8n/n8n-nodes-langchain.agent", 2),
      node("Tool", "@n8n/n8n-nodes-langchain.toolCode", 1),
      node("Model", "@n8n/n8n-nodes-langchain.lmChatOpenAi", 1),
    ],
    {
      Webhook: { main: [[{ node: "Agent", type: "main", index: 0 }]] },
      Tool: { ai_tool: [[{ node: "Agent", type: "ai_tool", index: 0 }]] },
      Model: {
        ai_languageModel: [
          [{ node: "Agent", type: "ai_languageModel", index: 0 }],
        ],
      },
    },
  );
  const missing = assess(target, undefined).CONTEXT_AI_APPROVAL_BOUNDARY;
  for (const code of [
    "ai_model_boundary_declared",
    "ai_tool_boundary_declared",
    "external_input_control_path_to_ai",
    "ai_tool_privileged_capability_declared",
    "ai_tool_approval_not_declared",
  ])
    assert.ok(codes(missing).includes(code), code);
  const provided = evidence(target, {
    aiApprovals: [
      {
        nodeKey: target.context.nodes[1].key,
        required: true,
        toolNodeKeys: [target.context.nodes[2].key],
        sourceId: source.id,
      },
    ],
  });
  const configured = assess(target, provided).CONTEXT_AI_APPROVAL_BOUNDARY;
  assert.ok(codes(configured).includes("ai_tool_approval_declared_required"));
  assert.equal(
    codes(configured).includes("ai_tool_approval_not_declared"),
    false,
  );
  assert.ok(
    diagnostics(configured).includes("runtime_approval_enforcement_unverified"),
  );
  assert.ok(
    diagnostics(configured).includes(
      "model_attack_resistance_and_value_flow_unverified",
    ),
  );
  assert.equal(configured.coverage[0].status, "partial");
});

test("synthetic receipts preserve two outcomes and never count as worker execution", () => {
  const receipt = {
    inputSha256: community.inputSha256,
    environmentId: "fixture-runtime",
    sourceId: source.id,
    recordedAt: now,
    cases: [
      {
        caseId: "SEC-SQL-01",
        attackBlocked: true,
        normalBehaviorPreserved: true,
      },
    ],
  };
  const passed = assess(
    community,
    evidence(community, { syntheticReceipts: [receipt] }),
  ).CONTEXT_SYNTHETIC_RECEIPTS;
  assert.ok(
    codes(passed).includes(
      "supplied_synthetic_receipt_reports_both_checks_passed",
    ),
  );
  assert.ok(
    diagnostics(passed).includes(
      "synthetic_receipt_not_independently_reexecuted",
    ),
  );
  const failed = assess(
    community,
    evidence(community, {
      syntheticReceipts: [
        {
          ...receipt,
          cases: [{ ...receipt.cases[0], normalBehaviorPreserved: false }],
        },
      ],
    }),
  ).CONTEXT_SYNTHETIC_RECEIPTS;
  assert.ok(
    codes(failed).includes("supplied_synthetic_receipt_reports_failed_checks"),
  );
  const other = assess(
    community,
    evidence(community, {
      syntheticReceipts: [{ ...receipt, inputSha256: hash("other input") }],
    }),
  ).CONTEXT_SYNTHETIC_RECEIPTS;
  assert.ok(diagnostics(other).includes("synthetic_receipt_input_mismatch"));
  assert.equal(other.findings.length, 0);
});
