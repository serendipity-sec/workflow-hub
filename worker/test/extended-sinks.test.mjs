import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { analyzeExtendedSinks } from "../dist/extended-sinks.js";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import { parseEvidence } from "../dist/assessment-evidence.js";
import { buildValueFlow } from "../dist/value-flow.js";

const node = (id, type, typeVersion, parameters = {}) => ({
  id,
  name: id,
  type: "n8n-nodes-base." + type,
  typeVersion,
  parameters,
});
const webhook = () => node("Source", "webhook", 2, { authentication: "none" });
function run(nodes, connections = {}, configure) {
  const bytes = Buffer.from(JSON.stringify({ nodes, connections }));
  const context = createContext(bytes);
  const evidence = configure?.(
    context,
    createHash("sha256").update(bytes).digest("hex"),
  );
  const sourceAnnotations =
    evidence?.classifications.flatMap((item) =>
      ["public", "personal", "secret"].includes(item.dataClass)
        ? [
            {
              nodeKey: item.nodeKey,
              fieldPath: item.field,
              sensitivity:
                item.dataClass === "secret"
                  ? "secret_candidate"
                  : item.dataClass === "personal"
                    ? "pii_candidate"
                    : "public_literal",
              provenance: "operator",
            },
          ]
        : [],
    ) ?? [];
  const rules = analyzeExtendedSinks(
    context,
    buildValueFlow(context, { sourceAnnotations }),
    evidence,
  ).map((rule) => ruleResultSchema.parse(rule));
  return { rules, context, evidence };
}
const edge = (target) => ({
  main: [[{ node: target, type: "main", index: 0 }]],
});
const codes = (rules) =>
  rules.flatMap((rule) =>
    rule.findings.flatMap((finding) =>
      finding.evidence.map((item) => item.code),
    ),
  );
const diagnostics = (rules) =>
  rules.flatMap((rule) => rule.diagnostics.map((item) => item.code));
function policy(
  context,
  hash,
  sink,
  targets,
  classes = ["public"],
  extra = {},
) {
  return parseEvidence(
    {
      schemaVersion: "1.0.0",
      inputSha256: hash,
      sources: [
        {
          id: "operator",
          kind: "declaration",
          method: "user_declaration",
          recordedAt: "2026-11-22T00:00:00Z",
        },
      ],
      policy: {
        id: "policy",
        version: "1",
        sourceId: "operator",
        purpose: "Synthetic delivery test",
        defaultDecision: "review",
        unknownDecision: "review",
        egress: [
          {
            id: "route",
            nodeKey: context.nodes.at(-1).key,
            sink,
            mode: "allowlist",
            destinations: targets,
            allowedDataClasses: classes,
            purpose: "Deliver only approved synthetic fields",
          },
        ],
      },
      ...extra,
    },
    hash,
  );
}

test("email content selection follows version defaults and checks BCC separately", () => {
  const email = node("Mail", "emailSend", 2.1, {
    toEmail: "approved@example.invalid",
    html: "Public status",
    text: "={{ $json.body.password }}",
    options: { bccEmail: "other@example.invalid" },
  });
  const { rules } = run(
    [webhook(), email],
    { Source: edge("Mail") },
    (ctx, hash) => policy(ctx, hash, "email", ["approved@example.invalid"]),
  );
  assert.ok(codes(rules).includes("trusted_policy_transfer_disallowed"));
  assert.ok(!codes(rules).includes("secret_candidate_transferred"));
  assert.equal(
    JSON.stringify(rules).includes("approved@example.invalid"),
    false,
  );
  assert.equal(JSON.stringify(rules).includes("other@example.invalid"), false);
});

test("Gmail transmitted message tracks sensitive source fields without exporting values", () => {
  const { rules } = run(
    [
      webhook(),
      node("Mail", "gmail", 2.2, {
        sendTo: "recipient@example.invalid",
        message: "={{ $json.body.password }}",
      }),
    ],
    { Source: edge("Mail") },
  );
  const findings = rules[0].findings.filter(
    (finding) => finding.evidence[0].code === "secret_candidate_transferred",
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].claim, "supported_path");
  assert.equal(JSON.stringify(rules).includes("password"), false);
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

test("Slack direct channel and Telegram dynamic recipient are distinguished", () => {
  const slack = run(
    [
      webhook(),
      node("Message", "slack", 2.7, {
        select: "channel",
        channelId: { mode: "id", value: "C123ABC" },
        text: "Public status",
        otherOptions: { includeLinkToWorkflow: false },
      }),
    ],
    { Source: edge("Message") },
    (ctx, hash) => policy(ctx, hash, "slack", ["C123ABC"]),
  );
  assert.equal(slack.rules[0].coverage[0].status, "checked");
  const telegram = run(
    [
      webhook(),
      node("Message", "telegram", 1.2, {
        chatId: "={{ $json.body.chat }}",
        text: "={{ $json.body.email }}",
      }),
    ],
    { Source: edge("Message") },
  );
  assert.ok(codes(telegram.rules).includes("dynamic_recipient_or_destination"));
  assert.ok(
    codes(telegram.rules).includes("personal_data_candidate_transferred"),
  );
});

test("HTTP analyses enabled query headers and body, ignores disabled payload settings", () => {
  const http = node("Send", "httpRequest", 4.2, {
    url: "https://approved.example.invalid/path",
    sendQuery: true,
    queryParameters: {
      parameters: [{ name: "q", value: "={{ $json.body.email }}" }],
    },
    sendHeaders: true,
    headerParameters: {
      parameters: [{ name: "Authorization", value: "={{ $json.body.token }}" }],
    },
    sendBody: false,
    jsonBody: "={{ $json }}",
    options: { redirect: { redirect: { followRedirects: false } } },
  });
  const { rules } = run([webhook(), http], { Source: edge("Send") });
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("secret_candidate_transferred"));
  assert.ok(
    !rules[0].findings.some((finding) =>
      finding.location.pointer.includes("jsonBody"),
    ),
  );
});

test("JSON body field projection carries DB origin into external transfer", () => {
  const db = node("Database", "postgres", 2.8, {
    operation: "executeQuery",
    query: "select email from synthetic_table",
  });
  const target = node("Send", "httpRequest", 4.2, {
    url: "https://approved.example.invalid",
    sendBody: true,
    specifyBody: "json",
    jsonBody: "={{ $json.email }}",
  });
  const { rules } = run([db, target], { Database: edge("Send") });
  assert.ok(codes(rules).includes("database_result_transferred"));
  assert.ok(codes(rules).includes("database_result_origin"));
});

test("whole DB response retains unknown sensitivity while field response carries classification", () => {
  const db = node("Database", "postgres", 2.8, {
    operation: "executeQuery",
    query: "select email from synthetic_table",
  });
  const whole = run([db, node("Response", "respondToWebhook", 1.5)], {
    Database: edge("Response"),
  });
  assert.ok(codes(whole.rules).includes("whole_object_transferred"));
  assert.ok(codes(whole.rules).includes("database_result_transferred"));
  assert.ok(
    diagnostics(whole.rules).includes(
      "transferred_data_sensitivity_unverified",
    ),
  );
  const projected = run(
    [
      db,
      node("Response", "respondToWebhook", 1.5, {
        respondWith: "json",
        responseBody: "={{ $json.email }}",
      }),
    ],
    { Database: edge("Response") },
  );
  assert.ok(
    codes(projected.rules).includes("personal_data_candidate_transferred"),
  );
});

test("console AST inspection is nonexecuting and conservatively candidate-only", () => {
  const code = node("Code", "code", 2, {
    jsCode:
      "console.log($json.body.password); throw new Error('DO_NOT_EXECUTE_SENTINEL');",
  });
  const { rules } = run([webhook(), code], { Source: edge("Code") });
  const findings = rules[1].findings.filter(
    (finding) => finding.evidence[0].code === "secret_candidate_transferred",
  );
  assert.equal(findings[0]?.claim, "candidate");
  assert.ok(diagnostics(rules).includes("code_logging_semantics_partial"));
  assert.equal(
    JSON.stringify(rules).includes("DO_NOT_EXECUTE_SENTINEL"),
    false,
  );
});

test("attachments unknown operations versions and format switches remain partial", () => {
  for (const target of [
    node("Mail", "emailSend", 2.1, {
      toEmail: "a@example.invalid",
      html: "Public",
      options: { fileAttachments: "data" },
    }),
    node("Mail", "gmail", 2.2, { operation: "reply", message: "Public" }),
    node("Send", "telegram", 99, { chatId: "1", text: "Public" }),
    node("Send", "httpRequest", 4.2, {
      url: "https://example.invalid",
      sendBody: "={{ true }}",
    }),
  ]) {
    const { rules } = run([target]);
    assert.equal(rules[0].coverage[0].status, "partial");
    assert.ok(
      codes(rules).some((code) =>
        ["outbound_send_capability", "external_connector_declared"].includes(
          code,
        ),
      ),
    );
  }
});

test("workflow-provided policy assertions never become trusted destination permission", () => {
  const target = node("Mail", "gmail", 2.2, {
    sendTo: "untrusted@example.invalid",
    message: "Public",
    policy: { allowed: true },
  });
  const { rules } = run([target]);
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
  assert.equal(
    JSON.stringify(rules).includes("untrusted@example.invalid"),
    false,
  );
});

test("disabled destinations produce no transfer claim and noData emits no response finding", () => {
  const target = {
    ...node("Mail", "gmail", 2.2, {
      sendTo: "any@example.invalid",
      message: "={{ $json }}",
    }),
    disabled: true,
  };
  const { rules } = run([
    target,
    node("Response", "respondToWebhook", 1.5, { respondWith: "noData" }),
  ]);
  assert.equal(rules.flatMap((rule) => rule.findings).length, 0);
  assert.ok(diagnostics(rules).includes("disabled_node_not_executed"));
});

test("Slack body overrides and excess recipients cannot silently pass an allowlist", () => {
  const slack = run(
    [
      node("Send", "slack", 2.7, {
        select: "channel",
        channelId: { mode: "id", value: "C123ABC" },
        messageType: "block",
        blocksUi: '{"channel":"OTHER","blocks":[]}',
        otherOptions: { includeLinkToWorkflow: false },
      }),
    ],
    {},
    (ctx, hash) => policy(ctx, hash, "slack", ["C123ABC"]),
  );
  assert.ok(
    diagnostics(slack.rules).includes("trusted_policy_transfer_unresolved"),
  );
  const many = run(
    [
      node("Send", "gmail", 2.2, {
        sendTo: Array.from({ length: 129 }, () => "a@example.invalid").join(
          ",",
        ),
        message: "Public",
      }),
    ],
    {},
    (ctx, hash) => policy(ctx, hash, "email", ["a@example.invalid"]),
  );
  assert.ok(
    diagnostics(many.rules).includes("trusted_policy_transfer_unresolved"),
  );
});

test("trusted internal field classification applies without conflating internal trust and sensitivity", () => {
  const target = node("Mail", "gmail", 2.2, {
    sendTo: "a@example.invalid",
    message: "={{ $json.body.report }}",
  });
  const { rules } = run(
    [webhook(), target],
    { Source: edge("Mail") },
    (ctx, hash) =>
      policy(ctx, hash, "email", ["a@example.invalid"], ["internal"], {
        classifications: [
          {
            nodeKey: ctx.nodes[0].key,
            field: "/body/report",
            dataClass: "internal",
            sourceId: "operator",
          },
        ],
      }),
  );
  assert.ok(!codes(rules).includes("trusted_policy_transfer_disallowed"));
  assert.ok(!diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

test("known personal or secret parts do not hide an unclassified joined value from policy", () => {
  for (const [field, kind] of [
    ["email", "personal"],
    ["password", "secret"],
  ]) {
    const target = node("Mail", "gmail", 2.2, {
      sendTo: "a@example.invalid",
      message: `={{ $json.body.${field} + $json.body.misc }}`,
    });
    const { rules } = run(
      [webhook(), target],
      { Source: edge("Mail") },
      (ctx, hash) =>
        policy(ctx, hash, "email", ["a@example.invalid"], [kind], {
          classifications: [
            {
              nodeKey: ctx.nodes[0].key,
              field: "/body/" + field,
              dataClass: kind,
              sourceId: "operator",
            },
          ],
        }),
    );
    assert.ok(
      diagnostics(rules).includes("trusted_policy_transfer_unresolved"),
    );
    assert.ok(
      codes(rules).includes(
        kind === "secret"
          ? "secret_candidate_transferred"
          : "personal_data_candidate_transferred",
      ),
    );
  }
});

test("public annotations do not authorize an unsupported transformation", () => {
  const target = node("Mail", "gmail", 2.2, {
    sendTo: "a@example.invalid",
    message: "={{ transformUnknown($json.body.report) }}",
  });
  const { rules } = run(
    [webhook(), target],
    { Source: edge("Mail") },
    (ctx, hash) =>
      policy(ctx, hash, "email", ["a@example.invalid"], ["public"], {
        classifications: [
          {
            nodeKey: ctx.nodes[0].key,
            field: "/body/report",
            dataClass: "public",
            sourceId: "operator",
          },
        ],
      }),
  );
  assert.ok(diagnostics(rules).includes("payload_provenance_unresolved"));
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

test("dotted trusted classifications match canonical source pointers", () => {
  const target = node("Mail", "gmail", 2.2, {
    sendTo: "a@example.invalid",
    message: "={{ $json.body.report }}",
  });
  const { rules } = run(
    [webhook(), target],
    { Source: edge("Mail") },
    (ctx, hash) =>
      policy(ctx, hash, "email", ["a@example.invalid"], ["internal"], {
        classifications: [
          {
            nodeKey: ctx.nodes[0].key,
            field: "body.report",
            dataClass: "internal",
            sourceId: "operator",
          },
        ],
      }),
  );
  assert.ok(!diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

for (const [representation, payload] of [
  ["whole object", { specifyBody: "json", jsonBody: "={{ $json }}" }],
  [
    "JSON serialization",
    { contentType: "raw", body: "={{ JSON.stringify($json) }}" },
  ],
  [
    "concatenation",
    { contentType: "raw", body: "={{ $json.password + ':' + $json.email }}" },
  ],
]) {
  test(`mixed secret and personal ${representation} enforces every data class`, () => {
    const source = node("Map", "set", 3.4, {
      mode: "raw",
      jsonOutput: JSON.stringify({
        password: "synthetic-password-marker",
        email: "synthetic-person@example.invalid",
      }),
    });
    const target = node("Send", "httpRequest", 4.2, {
      url: "https://approved.example.invalid",
      sendBody: true,
      ...payload,
      options: { redirect: { redirect: { followRedirects: false } } },
    });
    for (const allowed of [
      ["public", "secret"],
      ["public", "personal"],
      ["public", "secret", "personal"],
    ]) {
      const { rules } = run(
        [source, target],
        { Map: edge("Send") },
        (ctx, hash) =>
          policy(
            ctx,
            hash,
            "http",
            ["https://approved.example.invalid"],
            allowed,
          ),
      );
      assert.ok(codes(rules).includes("secret_candidate_transferred"));
      assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
      assert.equal(
        codes(rules).includes("data_class_not_allowed"),
        allowed.length < 3,
      );
      assert.equal(
        codes(rules).includes("trusted_policy_transfer_disallowed"),
        allowed.length < 3,
      );
      assert.equal(
        diagnostics(rules).includes("trusted_policy_transfer_unresolved"),
        false,
      );
      for (const raw of [
        "synthetic-password-marker",
        "synthetic-person@example.invalid",
      ])
        assert.equal(JSON.stringify(rules).includes(raw), false);
    }
  });
}

test("projecting only the permitted secret omits the unrelated personal field", () => {
  const { rules } = run(
    [
      node("Map", "set", 3.4, {
        mode: "raw",
        jsonOutput: JSON.stringify({
          password: "synthetic-value",
          email: "synthetic@example.invalid",
        }),
      }),
      node("Send", "httpRequest", 4.2, {
        url: "https://approved.example.invalid",
        sendBody: true,
        contentType: "raw",
        body: "={{ $json.password }}",
        options: { redirect: { redirect: { followRedirects: false } } },
      }),
    ],
    { Map: edge("Send") },
    (ctx, hash) =>
      policy(
        ctx,
        hash,
        "http",
        ["https://approved.example.invalid"],
        ["public", "secret"],
      ),
  );
  assert.ok(codes(rules).includes("secret_candidate_transferred"));
  assert.equal(
    codes(rules).includes("personal_data_candidate_transferred"),
    false,
  );
  assert.equal(codes(rules).includes("data_class_not_allowed"), false);
  assert.equal(
    diagnostics(rules).includes("trusted_policy_transfer_unresolved"),
    false,
  );
});
