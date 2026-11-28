import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { analyzeExtendedSinks } from "../dist/rules/extended-sinks.js";
import { createContext } from "../dist/workflow/static-context.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";
import { parseEvidence } from "../dist/assessment/assessment-evidence.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";

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
const rlc = (value) => ({ mode: "id", value });
const openai = (parameters = {}, version = 2) => ({
  ...node("Model", "unused", version, {
    modelId: rlc("synthetic-model"),
    responses: { values: [{ content: "public" }] },
    ...parameters,
  }),
  type: "@n8n/n8n-nodes-langchain.openAi",
});

test("OpenAI V2 defaults to Responses and inspects messages instructions and metadata with an unknown endpoint", () => {
  for (const version of [2, 2.1, 2.2, 2.3]) {
    const { rules } = run(
      [
        webhook(),
        openai(
          {
            responses: { values: [{ content: "={{ $json.body.email }}" }] },
            options: {
              instructions: "={{ $json.body.password }}",
              metadata: { opaque_customer_key: "={{ $json.body.email }}" },
            },
            messages: { values: [{ content: "inactive" }] },
          },
          version,
        ),
      ],
      { Source: edge("Model") },
      (ctx, hash) =>
        policy(
          ctx,
          hash,
          "openai",
          ["https://api.openai.com"],
          ["public", "personal", "secret"],
        ),
    );
    assert.ok(codes(rules).includes("openai_responses_output_profile"));
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.ok(codes(rules).includes("secret_candidate_transferred"));
    assert.ok(
      diagnostics(rules).includes(
        "provider_endpoint_from_credentials_unverified",
      ),
    );
    assert.ok(
      diagnostics(rules).includes("trusted_policy_transfer_unresolved"),
    );
    assert.equal(JSON.stringify(rules).includes("opaque_customer_key"), false);
    assert.equal(JSON.stringify(rules).includes("synthetic-model"), false);
  }
});

test("OpenAI Responses selects output format and remote prompt variables without sending local loop controls", () => {
  for (const type of ["text", "json_schema"]) {
    const { rules } = run(
      [
        webhook(),
        openai({
          options: {
            promptConfig: {
              promptOptions: {
                promptId: "synthetic",
                variables: { opaque: "={{ $json.body.email }}" },
              },
            },
            textFormat: {
              textOptions: {
                type,
                schema: "={{ $json.body.password }}",
                description: "={{ $json.body.password }}",
                strict: "={{ $json.body.password }}",
              },
            },
            maxToolsIterations: "synthetic@example.invalid",
            backgroundMode: {
              values: { enabled: false, timeout: "={{ $json.body.password }}" },
            },
          },
        }),
      ],
      { Source: edge("Model") },
    );
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.equal(
      codes(rules).includes("secret_candidate_transferred"),
      type === "json_schema",
    );
    assert.ok(
      diagnostics(rules).includes("model_remote_prompt_content_unverified"),
    );
  }
  const inactive = run([
    openai({
      options: {
        maxToolsIterations: "synthetic@example.invalid",
        textFormat: {
          textOptions: { type: "text", schema: "synthetic@example.invalid" },
        },
      },
    }),
  ]);
  assert.equal(
    codes(inactive.rules).includes("personal_data_candidate_transferred"),
    false,
  );
});

test("OpenAI media inputs select active references and preserve binary or remote content uncertainty", () => {
  for (const imageType of ["url", "base64", "unknown"]) {
    const { rules } = run(
      [
        webhook(),
        openai({
          responses: {
            values: [
              { type: "text", content: "public" },
              {
                type: "image",
                imageType,
                imageUrl: "={{ $json.body.email }}",
                fileId: "={{ $json.body.password }}",
                binaryPropertyName: "={{ $json.body.password }}",
              },
            ],
          },
        }),
      ],
      { Source: edge("Model") },
    );
    assert.equal(
      codes(rules).includes("personal_data_candidate_transferred"),
      imageType === "url",
    );
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
    assert.ok(
      diagnostics(rules).includes(
        imageType === "url"
          ? "remote_attachment_content_unavailable"
          : imageType === "base64"
            ? "binary_payload_unavailable"
            : "model_message_media_selection_unresolved",
      ),
    );
  }
});

test("OpenAI built-in tools retain selected metadata and unknown actual execution while JSON strings stay literal", () => {
  const { rules } = run(
    [
      webhook(),
      openai({
        builtInTools: {
          webSearch: { city: "={{ $json.body.email }}" },
          fileSearch: { filters: '{"match":"={{ $json.body.password }}"}' },
          codeInterpreter: true,
        },
        options: { previousResponseId: "synthetic-history" },
      }),
    ],
    { Source: edge("Model") },
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
  assert.ok(diagnostics(rules).includes("model_provider_tools_unverified"));
  assert.ok(
    diagnostics(rules).includes("model_remote_history_content_unverified"),
  );
  const plain = run([openai({ builtInTools: { codeInterpreter: false } })]);
  assert.equal(
    diagnostics(plain.rules).includes("model_provider_tools_unverified"),
    false,
  );
});

test("OpenAI unsupported operations versions and dynamic option shapes remain unresolved", () => {
  for (const target of [
    openai({}, 1.8),
    openai({}, 99),
    openai({ operation: "message" }),
    openai({ resource: "audio" }),
  ]) {
    const { rules } = run([target]);
    assert.ok(
      diagnostics(rules).some((code) =>
        ["unsupported_node_version", "unsupported_send_operation"].includes(
          code,
        ),
      ),
    );
    assert.equal(
      codes(rules).includes("openai_responses_output_profile"),
      false,
    );
  }
  const dynamic = run([
    openai({
      responses: "={{ $json.messages }}",
      options: { promptConfig: "={{ $json.config }}" },
      builtInTools: { fileSearch: "={{ $json.tools }}" },
    }),
  ]);
  for (const code of [
    "model_messages_unresolved",
    "model_options_selection_unresolved",
    "model_provider_tools_selection_unresolved",
    "transfer_policy_not_configured",
  ])
    assert.ok(diagnostics(dynamic.rules).includes(code));
  const missing = run([openai({ responses: { values: [] } })]);
  assert.ok(
    diagnostics(missing.rules).includes(
      "model_required_text_prompt_unresolved",
    ),
  );
});

test("OpenAI main-node custom tools remain unresolved and hideTools excludes the inactive connection", () => {
  for (const hideTools of [undefined, "hide"]) {
    const { rules } = run(
      [
        node("Tool", "httpRequestTool", 4.2, {
          url: "https://example.invalid",
        }),
        openai({ hideTools }),
      ],
      {
        Tool: { ai_tool: [[{ node: "Model", type: "ai_tool", index: 0 }]] },
      },
    );
    assert.equal(
      diagnostics(rules).includes(
        "model_custom_tool_schema_and_result_unverified",
      ),
      hideTools !== "hide",
    );
  }
});

const openaiJsonFields = [
  (value) => ({ options: { metadata: value } }),
  (value) => ({
    options: {
      promptConfig: {
        promptOptions: { promptId: "synthetic", variables: value },
      },
    },
  }),
  (value) => ({
    options: {
      textFormat: { textOptions: { type: "json_schema", schema: value } },
    },
  }),
  (value) => ({ builtInTools: { fileSearch: { filters: value } } }),
  (value) => ({ builtInTools: { fileSearch: { vectorStoreIds: value } } }),
];
test("OpenAI parsed JSON data strings preserve the same secret and personal fields as literal objects", () => {
  const data = {
    nested: { password: "synthetic-private-marker" },
    email: "synthetic@example.invalid",
  };
  for (const configure of openaiJsonFields) {
    for (const value of [data, JSON.stringify(data)]) {
      const { rules } = run([openai(configure(value))]);
      assert.ok(codes(rules).includes("secret_candidate_transferred"));
      assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
      for (const raw of [
        "synthetic-private-marker",
        "synthetic@example.invalid",
        "password",
      ])
        assert.equal(JSON.stringify(rules).includes(raw), false);
    }
  }
});

test("OpenAI parsed data never reinterprets nested expression-shaped strings as runtime references", () => {
  for (const configure of openaiJsonFields) {
    for (const data of [
      { note: "={{ $json.body.password }}" },
      "={{ $json.body.password }}",
    ]) {
      const { rules } = run(
        [webhook(), openai(configure(JSON.stringify(data)))],
        { Source: edge("Model") },
      );
      assert.equal(
        codes(rules).includes("secret_candidate_transferred"),
        false,
      );
      assert.equal(
        codes(rules).includes("personal_data_candidate_transferred"),
        false,
      );
    }
    const live = run(
      [webhook(), openai(configure({ note: "={{ $json.body.password }}" }))],
      { Source: edge("Model") },
    );
    assert.ok(codes(live.rules).includes("secret_candidate_transferred"));
  }
});

test("OpenAI invalid and expression-produced JSON retain explicit structure uncertainty", () => {
  for (const configure of openaiJsonFields) {
    for (const [value, diagnostic] of [
      ["{invalid", "model_json_data_parse_unverified"],
      ["={{ $json.body.payload }}", "model_json_data_structure_unverified"],
    ]) {
      const { rules } = run([webhook(), openai(configure(value))], {
        Source: edge("Model"),
      });
      assert.ok(diagnostics(rules).includes(diagnostic));
      assert.ok(diagnostics(rules).includes("transfer_policy_not_configured"));
      assert.equal(rules[0].coverage.at(-1).status, "partial");
    }
  }
});

test("OpenAI JSON data depth and size limits preserve known candidates and an unknown remainder", () => {
  let nested = { note: "public" };
  for (let i = 0; i < 20; i++) nested = { next: nested };
  const cases = [
    { password: "synthetic-private-marker", nested },
    {
      password: "synthetic-private-marker",
      values: Array.from({ length: 600 }, () => "public"),
    },
    {
      password: "synthetic-private-marker",
      rows: Array.from({ length: 100 }, () =>
        Array.from({ length: 30 }, () => "x"),
      ),
    },
  ];
  for (const value of cases) {
    const { rules } = run([
      openai({ options: { metadata: JSON.stringify(value) } }),
    ]);
    assert.ok(codes(rules).includes("secret_candidate_transferred"));
    assert.ok(diagnostics(rules).includes("model_json_data_limit"));
    assert.ok(diagnostics(rules).includes("transfer_policy_not_configured"));
  }
  const oversized = run([
    openai({
      options: { metadata: JSON.stringify({ note: "x".repeat(65536) }) },
    }),
  ]);
  assert.ok(diagnostics(oversized.rules).includes("model_json_data_limit"));
});

test("flow-proven literal destinations resolve while public declarations do not invent addresses", () => {
  const target = node("Send", "telegram", 1.2, {
    chatId: "={{ $json.target }}",
    text: "Public status",
  });
  const fixed = run(
    [
      node("Map", "set", 3.4, {
        mode: "raw",
        jsonOutput: JSON.stringify({ target: "12345678" }),
      }),
      target,
    ],
    { Map: edge("Send") },
    (ctx, hash) => policy(ctx, hash, "telegram", ["12345678"]),
  );
  assert.equal(
    diagnostics(fixed.rules).includes("trusted_policy_transfer_unresolved"),
    false,
  );
  assert.ok(codes(fixed.rules).includes("dynamic_recipient_or_destination"));
  assert.equal(JSON.stringify(fixed.rules).includes("12345678"), false);
  const unknown = run(
    [webhook(), target],
    { Source: edge("Send") },
    (ctx, hash) =>
      policy(ctx, hash, "telegram", ["12345678"], ["public"], {
        classifications: [
          {
            nodeKey: ctx.nodes[0].key,
            field: "/target",
            dataClass: "public",
            sourceId: "operator",
          },
        ],
      }),
  );
  assert.ok(
    diagnostics(unknown.rules).includes("trusted_policy_transfer_unresolved"),
  );
});

test("response nested body and noData headers retain personal and secret classes", () => {
  for (const respondWith of ["json", "noData", "binary", "unknown_mode"]) {
    const { rules } = run(
      [
        webhook(),
        node("Response", "respondToWebhook", 1.5, {
          respondWith,
          responseBody: { opaque_label: "={{ $json.body.email }}" },
          options: {
            responseHeaders: {
              entries: [
                { name: "X-Synthetic", value: "={{ $json.body.password }}" },
              ],
            },
          },
        }),
      ],
      { Source: edge("Response") },
      (ctx, hash) => policy(ctx, hash, "response", ["caller"], ["public"]),
    );
    assert.ok(codes(rules).includes("secret_candidate_transferred"));
    assert.equal(
      codes(rules).includes("personal_data_candidate_transferred"),
      respondWith === "json",
    );
    assert.ok(codes(rules).includes("data_class_not_allowed"));
    if (respondWith === "binary")
      assert.ok(
        diagnostics(rules).includes("binary_response_content_unavailable"),
      );
    if (respondWith === "unknown_mode")
      assert.ok(diagnostics(rules).includes("response_mode_unresolved"));
    assert.equal(JSON.stringify(rules).includes("opaque_label"), false);
  }
  const plain = run(
    [
      webhook(),
      node("Response", "respondToWebhook", 1.5, {
        respondWith: "json",
        responseBody: '{"message":"={{ $json.body.password }}"}',
      }),
    ],
    { Source: edge("Response") },
  );
  assert.equal(
    codes(plain.rules).includes("secret_candidate_transferred"),
    false,
  );
});

test("JWT and redirect responses expose selected payload fields without treating signing as encryption", () => {
  for (const [mode, fields, code] of [
    [
      "jwt",
      {
        payload: { opaque_label: "={{ $json.body.email }}" },
        responseBody: "={{ $json.body.password }}",
      },
      "signed_response_payload_not_encrypted",
    ],
    [
      "redirect",
      {
        redirectURL: "={{ $json.body.email }}",
        payload: "={{ $json.body.password }}",
      },
      "redirect_location_response",
    ],
  ]) {
    const { rules } = run(
      [
        webhook(),
        node("Response", "respondToWebhook", 1.5, {
          respondWith: mode,
          ...fields,
        }),
      ],
      { Source: edge("Response") },
    );
    assert.ok(codes(rules).includes(code));
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
  }
});

test("oversized response headers retain known candidates and unknown remainder", () => {
  const entries = Array.from({ length: 129 }, (_, i) => ({
    name: "X-Synthetic",
    value: i ? "public" : "={{ $json.body.email }}",
  }));
  const { rules } = run(
    [
      webhook(),
      node("Response", "respondToWebhook", 1.5, {
        respondWith: "noData",
        options: { responseHeaders: { entries } },
      }),
    ],
    { Source: edge("Response") },
    (ctx, hash) =>
      policy(ctx, hash, "response", ["caller"], ["public", "personal"]),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(diagnostics(rules).includes("response_headers_limit"));
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

test("Notion read filters select active typed values and leave remote properties unclassified", () => {
  for (const condition of ["equals", "is_empty"]) {
    const { rules } = run(
      [
        webhook(),
        node("Read", "notion", 2.2, {
          resource: "databasePage",
          operation: "getAll",
          databaseId: rlc("synthetic-db"),
          filterType: "manual",
          filters: {
            conditions: [
              {
                key: "Opaque|email",
                condition,
                emailValue: "={{ $json.body.email }}",
                numberValue: "={{ $json.body.password }}",
              },
            ],
          },
          title: "={{ $json.body.password }}",
        }),
      ],
      { Source: edge("Read") },
    );
    assert.ok(codes(rules).includes("external_read_capability"));
    assert.ok(
      codes(rules).includes("notion_remote_properties_response_profile"),
    );
    assert.equal(
      codes(rules).includes("personal_data_candidate_transferred"),
      condition === "equals",
    );
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
    assert.ok(
      diagnostics(rules).includes("read_response_classification_unverified"),
    );
  }
  const docs = run([
    node("Read", "googleDocs", 2, {
      operation: "get",
      documentURL: "synthetic-doc",
      title: "={{ $json.body.password }}",
    }),
  ]);
  assert.ok(codes(docs.rules).includes("google_document_response_profile"));
  assert.ok(
    diagnostics(docs.rules).includes("read_response_classification_unverified"),
  );
  assert.equal(
    codes(docs.rules).includes("secret_candidate_transferred"),
    false,
  );
});

test("Slack option transformations inspect selected values and ephemeral recipient independently", () => {
  const { rules } = run(
    [
      webhook(),
      node("Send", "slack", 2.7, {
        select: "channel",
        channelId: rlc("C-SYNTHETIC"),
        text: "public",
        otherOptions: {
          includeLinkToWorkflow: false,
          thread_ts: {
            replyValues: {
              thread_ts: "={{ $json.body.email }}",
              reply_broadcast: false,
            },
          },
          botProfile: {
            imageValues: {
              profilePhotoType: "image",
              icon_url: "={{ $json.body.email }}",
              icon_emoji: "={{ $json.body.password }}",
            },
          },
          ephemeral: { ephemeralValues: { user: rlc("U-SYNTHETIC") } },
        },
      }),
    ],
    { Source: edge("Send") },
    (ctx, hash) =>
      policy(ctx, hash, "slack", ["C-SYNTHETIC"], ["public", "personal"]),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
  assert.ok(codes(rules).includes("destination_not_allowlisted"));
  assert.ok(
    diagnostics(rules).includes("ephemeral_recipient_authorization_unverified"),
  );
  const missing = run([
    node("Send", "slack", 2.3, { select: "user", text: "public" }),
  ]);
  assert.ok(diagnostics(missing.rules).includes("required_send_field_missing"));
});
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
  assert.ok(diagnostics(rules).includes("transfer_policy_not_configured"));
});

test("structured n8n parameters resolve nested expressions without parsing plain JSON string literals", () => {
  const settings = {
    url: "https://approved.example.invalid/",
    sendBody: true,
    specifyBody: "json",
    options: { redirect: { redirect: { followRedirects: false } } },
  };
  const nested = run(
    [
      webhook(),
      node("Send", "httpRequest", 4.2, {
        ...settings,
        jsonBody: {
          opaque_customer_field: {
            email: "={{ $json.body.email }}",
            token: "={{ $json.body.password }}",
          },
        },
      }),
    ],
    { Source: edge("Send") },
  );
  assert.ok(
    codes(nested.rules).includes("personal_data_candidate_transferred"),
  );
  assert.ok(codes(nested.rules).includes("secret_candidate_transferred"));
  assert.equal(
    JSON.stringify(nested.rules).includes("opaque_customer_field"),
    false,
  );
  const literal = run(
    [
      webhook(),
      node("Send", "httpRequest", 4.2, {
        ...settings,
        jsonBody: JSON.stringify({ value: "={{ $json.body.password }}" }),
      }),
    ],
    { Source: edge("Send") },
  );
  assert.equal(
    codes(literal.rules).includes("secret_candidate_transferred"),
    false,
  );
});

test("structured parameter limits retain known facts and never make truncated content public", () => {
  const fields = Object.fromEntries(
    Array.from({ length: 600 }, (_, i) => [
      "slot" + i,
      i === 0 ? "={{ $json.body.email }}" : "Public",
    ]),
  );
  const { rules } = run(
    [
      webhook(),
      node("Send", "httpRequest", 4.2, {
        url: "https://approved.example.invalid/",
        sendBody: true,
        specifyBody: "json",
        jsonBody: fields,
        options: { redirect: { redirect: { followRedirects: false } } },
      }),
    ],
    { Source: edge("Send") },
    (ctx, hash) =>
      policy(
        ctx,
        hash,
        "http",
        ["https://approved.example.invalid"],
        ["public", "personal"],
      ),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(diagnostics(rules).includes("parameter_value_analysis_limit"));
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
});

test("Airtable create maps selected column values and enforces compound destination and every data class", () => {
  const { rules } = run(
    [
      webhook(),
      node("Write", "airtable", 2.1, {
        operation: "create",
        base: rlc("appSynthetic"),
        table: rlc("tblSynthetic"),
        columns: {
          mappingMode: "defineBelow",
          value: {
            opaque_field: "={{ $json.body.email }}",
            credential_field: "={{ $json.body.password }}",
          },
        },
        options: {},
      }),
    ],
    { Source: edge("Write") },
    (ctx, hash) =>
      policy(
        ctx,
        hash,
        "airtable",
        ["appSynthetic/tblSynthetic"],
        ["public", "secret"],
      ),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("secret_candidate_transferred"));
  assert.ok(codes(rules).includes("data_class_not_allowed"));
  assert.ok(codes(rules).includes("airtable_record_response_profile"));
  assert.equal(JSON.stringify(rules).includes("opaque_field"), false);
  assert.equal(JSON.stringify(rules).includes("appSynthetic"), false);
});

test("Airtable update excludes non-id local matching values whereas upsert transmits them", () => {
  for (const operation of ["update", "upsert"]) {
    const { rules } = run(
      [
        webhook(),
        node("Write", "airtable", 2.1, {
          operation,
          base: rlc("appSynthetic"),
          table: rlc("tblSynthetic"),
          columns: {
            mappingMode: "defineBelow",
            matchingColumns: ["match"],
            value: { match: "={{ $json.body.email }}", status: "Public" },
          },
          options: {},
        }),
      ],
      { Source: edge("Write") },
    );
    assert.equal(
      codes(rules).includes("personal_data_candidate_transferred"),
      operation === "upsert",
    );
    assert.ok(diagnostics(rules).includes("record_match_selection_unverified"));
  }
});

test("Airtable search profiles query transmission and response without treating inactive writes as sent", () => {
  for (const version of [2.1, 2.2]) {
    const { rules } = run(
      [
        webhook(),
        node("Read", "airtable", version, {
          operation: "search",
          base: rlc("appSynthetic"),
          table: rlc("tblSynthetic"),
          filterByFormula: "={{ $json.body.email }}",
          columns: {
            mappingMode: "defineBelow",
            value: { unused: "={{ $json.body.password }}" },
          },
          options: {},
        }),
      ],
      { Source: edge("Read") },
    );
    assert.ok(codes(rules).includes("external_read_capability"));
    assert.equal(codes(rules).includes("outbound_send_capability"), false);
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
    assert.ok(
      codes(rules).includes(
        version < 2.2
          ? "airtable_flattened_response_profile"
          : "airtable_record_response_profile",
      ),
    );
    assert.ok(
      diagnostics(rules).includes("read_response_classification_unverified"),
    );
  }
});

test("Airtable default get and delete select only record id and preserve attachment uncertainty", () => {
  for (const operation of [undefined, "deleteRecord"]) {
    const { rules } = run(
      [
        webhook(),
        node("Record", "airtable", 2.1, {
          operation,
          base: rlc("appSynthetic"),
          table: rlc("tblSynthetic"),
          id: "={{ $json.body.email }}",
          filterByFormula: "={{ $json.body.password }}",
          options: { downloadFields: ["attachment"] },
        }),
      ],
      { Source: edge("Record") },
    );
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
    assert.equal(
      codes(rules).includes("external_read_capability"),
      operation === undefined,
    );
  }
});

test("table profiles keep unsupported versions, resources and dynamic mapping explicit", () => {
  for (const [kind, version, parameters] of [
    ["airtable", 99, { operation: "create" }],
    ["airtable", 2.1, { resource: "base", operation: "create" }],
    ["googleSheets", 3, { operation: "append" }],
    ["googleSheets", 4.6, { resource: "spreadsheet", operation: "create" }],
  ]) {
    const { rules } = run([node("Table", kind, version, parameters)]);
    assert.ok(codes(rules).includes("external_connector_declared"));
    assert.ok(
      diagnostics(rules).some((code) => code.startsWith("unsupported_")),
    );
  }
  const dynamic = run([
    node("Table", "airtable", 2.1, {
      operation: "create",
      base: rlc("appSynthetic"),
      table: rlc("tblSynthetic"),
      columns: { mappingMode: "={{ $json.mode }}", value: { label: "Public" } },
    }),
  ]);
  assert.ok(
    diagnostics(dynamic.rules).includes("resource_mapping_mode_unresolved"),
  );
  assert.ok(
    diagnostics(dynamic.rules).includes("transfer_policy_not_configured"),
  );
});

test("Google Sheets manual append preserves the conditional empty-sheet whole-input fallback", () => {
  const { rules } = run(
    [
      webhook(),
      node("Sheet", "googleSheets", 4.6, {
        operation: "append",
        documentId: rlc("docSynthetic"),
        sheetName: rlc("0"),
        columns: {
          mappingMode: "defineBelow",
          value: { label: "Public" },
          schema: [{ id: "label" }],
        },
        options: {},
      }),
    ],
    { Source: edge("Sheet") },
  );
  assert.ok(
    diagnostics(rules).includes("sheet_empty_header_fallback_possible"),
  );
  assert.ok(diagnostics(rules).includes("sheet_headers_runtime_unverified"));
  const whole = rules[0].findings.find(
    (f) => f.evidence[0].code === "whole_object_transferred",
  );
  assert.ok(whole);
  assert.equal(whole.claim, "candidate");
});

test("Google Sheets mapped update selects values while default read does not send local lookup filters", () => {
  const baseParameters = {
    documentId: rlc("docSynthetic"),
    sheetName: rlc("0"),
    columns: {
      mappingMode: "defineBelow",
      value: { value: "={{ $json.body.email }}" },
      schema: [{ id: "value" }],
      matchingColumns: ["value"],
    },
    filtersUI: {
      values: [
        { lookupColumn: "value", lookupValue: "={{ $json.body.password }}" },
      ],
    },
    options: {},
  };
  const update = run(
    [
      webhook(),
      node("Sheet", "googleSheets", 4.6, {
        ...baseParameters,
        operation: "update",
      }),
    ],
    { Source: edge("Sheet") },
  );
  assert.ok(
    codes(update.rules).includes("personal_data_candidate_transferred"),
  );
  assert.equal(
    codes(update.rules).includes("secret_candidate_transferred"),
    false,
  );
  const read = run(
    [webhook(), node("Sheet", "googleSheets", 4.6, baseParameters)],
    { Source: edge("Sheet") },
  );
  assert.ok(codes(read.rules).includes("external_read_capability"));
  assert.equal(
    codes(read.rules).includes("secret_candidate_transferred"),
    false,
  );
  assert.equal(
    codes(read.rules).includes("personal_data_candidate_transferred"),
    false,
  );
  assert.ok(
    diagnostics(read.rules).includes("read_response_classification_unverified"),
  );
});

test("Gmail read requests inspect selected filters or id while remote content remains unclassified", () => {
  for (const [operation, simple] of [
    ["get", false],
    ["getAll", undefined],
  ]) {
    const { rules } = run(
      [
        webhook(),
        node("Read", "gmail", 2.1, {
          operation,
          simple,
          messageId: "={{ $json.body.email }}",
          filters: { q: "={{ $json.body.email }}" },
          message: "={{ $json.body.password }}",
          options: { downloadAttachments: true },
        }),
      ],
      { Source: edge("Read") },
    );
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
    assert.ok(
      codes(rules).includes(
        simple === false
          ? "gmail_parsed_message_response_profile"
          : "gmail_metadata_response_profile",
      ),
    );
    assert.ok(
      diagnostics(rules).includes("read_response_classification_unverified"),
    );
    assert.equal(
      diagnostics(rules).includes("binary_response_content_unavailable"),
      simple === false,
    );
  }
});

test("EmailSend v1 scans both bodies and top-level CC/BCC without treating V2 options as active", () => {
  const mail = node("Mail", "emailSend", 1, {
    toEmail: "approved@example.invalid",
    ccEmail: "approved@example.invalid",
    bccEmail: "other@example.invalid",
    text: "={{ $json.body.password }}",
    html: "={{ $json.body.email }}",
    emailFormat: "text",
    attachments: "syntheticBinary",
    options: { bccEmail: "ignored@example.invalid" },
  });
  const { rules } = run(
    [webhook(), mail],
    { Source: edge("Mail") },
    (ctx, hash) => policy(ctx, hash, "email", ["approved@example.invalid"]),
  );
  assert.equal(diagnostics(rules).includes("unsupported_node_version"), false);
  assert.ok(codes(rules).includes("secret_candidate_transferred"));
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("destination_not_allowlisted"));
  assert.ok(diagnostics(rules).includes("binary_payload_unavailable"));
  assert.equal(
    rules[0].findings.some((f) =>
      f.location.pointer.includes("options/bccEmail"),
    ),
    false,
  );
  assert.equal(JSON.stringify(rules).includes("other@example.invalid"), false);
  assert.equal(rules[0].profileVersion, "1.5.0");
});

test("Telegram documents retain recipient and caption facts while binary content stays unknown", () => {
  const document = node("Message", "telegram", 1.2, {
    operation: "sendDocument",
    chatId: "12345678",
    binaryData: true,
    binaryPropertyName: "payload",
    file: "={{ $json.body.password }}",
    text: "={{ $json.body.password }}",
    additionalFields: {
      caption: "={{ $json.body.email }}",
      fileName: "report.txt",
    },
  });
  const { rules } = run(
    [webhook(), document],
    { Source: edge("Message") },
    (ctx, hash) =>
      policy(ctx, hash, "telegram", ["12345678"], ["public", "personal"]),
  );
  assert.ok(codes(rules).includes("outbound_send_capability"));
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
  assert.equal(
    diagnostics(rules).includes("unsupported_send_operation"),
    false,
  );
  assert.ok(diagnostics(rules).includes("binary_payload_unavailable"));
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
  assert.equal(rules[0].coverage[0].status, "partial");
});

test("Telegram remote file references and unknown binary mode do not certify file contents", () => {
  for (const binaryData of [false, "={{ $json.mode }}"]) {
    const { rules } = run(
      [
        webhook(),
        node("Message", "telegram", 1.2, {
          operation: "sendDocument",
          chatId: "12345678",
          binaryData,
          file: "={{ $json.body.email }}",
          additionalFields: {},
        }),
      ],
      { Source: edge("Message") },
    );
    if (binaryData === false) {
      assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
      assert.ok(
        diagnostics(rules).includes("remote_attachment_content_unavailable"),
      );
    } else {
      assert.equal(
        codes(rules).includes("personal_data_candidate_transferred"),
        false,
      );
      assert.ok(diagnostics(rules).includes("binary_payload_mode_unresolved"));
    }
  }
  const unsupported = run([
    node("Message", "telegram", 1.2, { operation: "sendAnimation" }),
  ]);
  assert.ok(
    diagnostics(unsupported.rules).includes("unsupported_send_operation"),
  );
});

test("Telegram optional keyboards preserve defaults, content candidates and missing recipients", () => {
  for (const replyMarkup of ["replyKeyboard", "inlineKeyboard"]) {
    for (const keyboard of [undefined, {}, { rows: [] }]) {
      const { rules } = run([
        node("Message", "telegram", 1.2, {
          chatId: "12345678",
          text: "A public update",
          replyMarkup,
          [replyMarkup]: keyboard,
        }),
      ]);
      assert.equal(
        diagnostics(rules).includes("required_send_field_missing"),
        false,
      );
      assert.ok(diagnostics(rules).includes("message_reply_markup_unverified"));
    }
    const { rules } = run(
      [
        webhook(),
        node("Message", "telegram", 1.2, {
          chatId: "12345678",
          text: "A public update",
          replyMarkup,
          [replyMarkup]: {
            rows: [{ row: { buttons: [{ text: "={{ $json.body.email }}" }] } }],
          },
        }),
      ],
      { Source: edge("Message") },
    );
    assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    assert.ok(diagnostics(rules).includes("message_reply_markup_unverified"));
  }
  const missingRecipient = run([
    node("Message", "telegram", 1.2, {
      text: "A public update",
      replyMarkup: "replyKeyboard",
    }),
  ]);
  assert.ok(
    diagnostics(missingRecipient.rules).includes("required_send_field_missing"),
  );
});

test("Telegram keyboard web apps, unsupported shapes and limits retain data uncertainty", () => {
  const keyboard = (buttons) => ({ rows: [{ row: { buttons } }] });
  const cases = [
    {
      value: keyboard([
        {
          text: "Open",
          additionalFields: { web_app: { url: "={{ $json.body.email }}" } },
        },
      ]),
      personal: true,
    },
    {
      value: keyboard([
        {
          text: "Open",
          additionalFields: { "private-field-name": "={{ $json.body.email }}" },
        },
      ]),
      personal: true,
      gap: "message_keyboard_shape_unresolved",
    },
    {
      value: { rows: "={{ $json.rows }}" },
      gap: "message_keyboard_shape_unresolved",
    },
    {
      value: keyboard([
        {
          text: "Public",
          additionalFields: {
            web_app: { url: { nested: "={{ $json.body.email }}" } },
          },
        },
      ]),
      gap: "message_keyboard_shape_unresolved",
    },
    {
      value: {
        rows: Array.from({ length: 129 }, () => ({
          row: { buttons: [{ text: "Public" }] },
        })),
      },
      gap: "message_keyboard_limit",
    },
    {
      value: keyboard(Array.from({ length: 129 }, () => ({ text: "Public" }))),
      gap: "message_keyboard_limit",
    },
    {
      value: keyboard(
        Array.from({ length: 128 }, () => ({
          text: "Public",
          additionalFields: {
            url: "https://example.invalid",
            callback_data: "public",
          },
        })),
      ),
      gap: "message_keyboard_limit",
    },
  ];
  for (const entry of cases) {
    const { rules } = run(
      [
        webhook(),
        node("Message", "telegram", 1.2, {
          chatId: "12345678",
          text: "Public",
          replyMarkup: "inlineKeyboard",
          inlineKeyboard: entry.value,
        }),
      ],
      { Source: edge("Message") },
      (ctx, hash) =>
        policy(ctx, hash, "telegram", ["12345678"], ["public", "personal"]),
    );
    if (entry.personal)
      assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
    if (entry.gap) assert.ok(diagnostics(rules).includes(entry.gap));
    assert.ok(
      diagnostics(rules).includes("trusted_policy_transfer_unresolved"),
    );
    assert.equal(JSON.stringify(rules).includes("private-field-name"), false);
  }
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
  assert.ok(diagnostics(rules).includes("transfer_policy_not_configured"));
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

test("Notion database pages select transmitted property types and keep destination policy separate", () => {
  const { rules } = run(
    [
      webhook(),
      node("Save", "notion", 2.2, {
        resource: "databasePage",
        databaseId: { mode: "id", value: "synthetic-database" },
        title: "Public heading",
        propertiesUi: {
          propertyValues: [
            {
              key: "Contact|rich_text",
              richText: false,
              textContent: "={{ $json.body.email }}",
              title: "={{ $json.body.password }}",
            },
          ],
        },
        options: {},
      }),
    ],
    { Source: edge("Save") },
    (ctx, hash) =>
      policy(ctx, hash, "notion", ["synthetic-database"], ["public"]),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("data_class_not_allowed"));
  assert.equal(codes(rules).includes("secret_candidate_transferred"), false);
  assert.ok(diagnostics(rules).includes("destination_access_unverified"));
  assert.equal(JSON.stringify(rules).includes("synthetic-database"), false);
});

test("Notion unknown property selection and URL locators retain uncertainty", () => {
  const { rules } = run([
    node("Save", "notion", 2.1, {
      resource: "databasePage",
      operation: "update",
      pageId: { mode: "url", value: "https://www.notion.so/synthetic" },
      propertiesUi: {
        propertyValues: [
          { key: "={{ $json.property }}", textContent: "private" },
        ],
      },
    }),
  ]);
  assert.ok(diagnostics(rules).includes("notion_property_type_unresolved"));
  assert.ok(diagnostics(rules).includes("destination_locator_unresolved"));
  assert.ok(diagnostics(rules).includes("transfer_policy_not_configured"));
});

test("Google Docs creation and text updates identify the transmitted title and active action fields", () => {
  const create = run(
    [
      webhook(),
      node("Save", "googleDocs", 2, {
        title: "={{ $json.body.email }}",
        folderId: "synthetic-folder",
      }),
    ],
    { Source: edge("Save") },
  );
  assert.ok(
    codes(create.rules).includes("personal_data_candidate_transferred"),
  );
  const update = run(
    [
      webhook(),
      node("Save", "googleDocs", 2, {
        operation: "update",
        documentURL: "synthetic-document",
        actionsUi: {
          actionFields: [
            {
              object: "text",
              action: "insert",
              text: "={{ $json.body.email }}",
              replaceText: "={{ $json.body.password }}",
            },
            {
              object: "text",
              action: "replaceAll",
              text: "Public token",
              replaceText: "={{ $json.body.password }}",
            },
          ],
        },
      }),
    ],
    { Source: edge("Save") },
  );
  assert.ok(
    codes(update.rules).includes("personal_data_candidate_transferred"),
  );
  const secrets = update.rules
    .flatMap((r) => r.findings)
    .filter((f) => f.evidence[0].code === "secret_candidate_transferred");
  assert.equal(secrets.length, 1);
  assert.ok(
    secrets[0].location.pointer.includes("/actionFields/1/replaceText"),
  );
});

test("Google Docs unsupported actions and unknown operations do not silently become covered sends", () => {
  const action = run([
    node("Save", "googleDocs", 1, {
      operation: "update",
      documentURL: "https://docs.google.com/document/d/synthetic/edit",
      actionsUi: { actionFields: [{ object: "image", action: "insert" }] },
    }),
  ]);
  assert.ok(diagnostics(action.rules).includes("document_action_unsupported"));
  assert.ok(
    diagnostics(action.rules).includes("transfer_policy_not_configured"),
  );
  for (const version of [2, 99]) {
    const unknown = run([
      node("Save", "googleDocs", version, { operation: "invented" }),
    ]);
    assert.ok(codes(unknown.rules).includes("external_connector_declared"));
    assert.equal(
      codes(unknown.rules).includes("outbound_send_capability"),
      false,
    );
  }
});

test("WhatsApp text sends enforce exact recipient and data policy without treating a send as malicious", () => {
  const { rules } = run(
    [
      webhook(),
      node("Send", "whatsApp", 1.1, {
        operation: "send",
        recipientPhoneNumber: "+15550100100",
        textBody: "={{ $json.body.email }}",
        additionalFields: { previewUrl: false },
      }),
    ],
    { Source: edge("Send") },
    (ctx, hash) => policy(ctx, hash, "whatsapp", ["+15550100100"], ["public"]),
  );
  assert.ok(codes(rules).includes("outbound_send_capability"));
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("data_class_not_allowed"));
  const unknown = run([
    node("Send", "whatsApp", 1.1, {
      recipientPhoneNumber: "+15550100100",
      textBody: "Public",
    }),
  ]);
  assert.ok(diagnostics(unknown.rules).includes("unsupported_send_operation"));
  assert.equal(
    codes(unknown.rules).includes("outbound_send_capability"),
    false,
  );
});

test("direct Gemini profiles actual messages and system prompt while credential endpoint stays unknown", () => {
  const model = {
    ...node("Model", "ignored", 1.1, {
      messages: {
        values: [{ content: "={{ $json.body.email }}", role: "user" }],
      },
      options: { systemMessage: "={{ $json.body.password }}" },
      builtInTools: {},
    }),
    type: "@n8n/n8n-nodes-langchain.googleGemini",
  };
  const { rules } = run(
    [webhook(), model],
    { Source: edge("Model") },
    (ctx, hash) =>
      policy(
        ctx,
        hash,
        "gemini",
        ["https://generativelanguage.googleapis.com"],
        ["public", "personal", "secret"],
      ),
  );
  assert.ok(codes(rules).includes("personal_data_candidate_transferred"));
  assert.ok(codes(rules).includes("secret_candidate_transferred"));
  assert.ok(
    diagnostics(rules).includes(
      "provider_endpoint_from_credentials_unverified",
    ),
  );
  assert.ok(diagnostics(rules).includes("trusted_policy_transfer_unresolved"));
  assert.equal(
    diagnostics(rules).includes("model_provider_tools_unverified"),
    false,
  );
  model.parameters.builtInTools = { codeExecution: true };
  assert.ok(
    diagnostics(
      run([webhook(), model], { Source: edge("Model") }).rules,
    ).includes("model_provider_tools_unverified"),
  );
});

test("known Gmail reads have a read capability and no unsupported send warning", () => {
  for (const operation of ["get", "getAll"]) {
    const { rules } = run([node("Read", "gmail", 2.1, { operation })]);
    assert.ok(codes(rules).includes("external_read_capability"));
    assert.equal(codes(rules).includes("outbound_send_capability"), false);
    assert.equal(
      diagnostics(rules).includes("unsupported_send_operation"),
      false,
    );
    assert.ok(
      diagnostics(rules).includes("read_response_classification_unverified"),
    );
  }
});

test("untrusted connector and property identifiers cannot address prototype members", () => {
  const inherited = run([
    { ...node("Unknown", "ignored", 1), type: "toString" },
  ]);
  assert.equal(inherited.rules.flatMap((rule) => rule.findings).length, 0);
  const property = run([
    node("Save", "notion", 2.2, {
      resource: "databasePage",
      databaseId: { mode: "id", value: "synthetic" },
      propertiesUi: {
        propertyValues: [{ key: "x|constructor", textContent: "ignored" }],
      },
    }),
  ]);
  assert.ok(
    diagnostics(property.rules).includes("notion_property_type_unresolved"),
  );
});
