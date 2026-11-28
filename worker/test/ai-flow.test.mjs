import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  analyzeAiFlow,
  aiPromptInputs,
  coveredAiEdge,
  isReviewedAiNode,
} from "../dist/rules/ai-flow.js";
import { parseEvidence } from "../dist/assessment/assessment-evidence.js";
import { createContext } from "../dist/workflow/static-context.js";
import { ruleResultSchema } from "../dist/contracts/static-contract.js";
import { buildValueFlow } from "../dist/workflow/value-flow.js";

const prefix = "@n8n/n8n-nodes-langchain.";
const node = (name, type, typeVersion, parameters = {}) => ({
  id: name,
  name,
  type: type.includes(".") ? type : prefix + type,
  typeVersion,
  parameters,
});
const source = () =>
  node("Source", "n8n-nodes-base.webhook", 2, { authentication: "none" });
const agent = (parameters = {}, name = "Agent") =>
  node(name, "agent", 2.2, {
    promptType: "define",
    text: "public question",
    options: { passthroughBinaryImages: false },
    ...parameters,
  });
const model = (parameters = {}, name = "Model") =>
  node(name, "lmChatOpenAi", 1.2, {
    model: { value: "synthetic-model" },
    options: {},
    ...parameters,
  });
const tool = (parameters = {}, name = "Tool") =>
  node(name, "n8n-nodes-base.httpRequestTool", 4.2, {
    url: "https://example.invalid/action",
    ...parameters,
  });
function wiring(...edges) {
  const connections = {};
  for (const [from, to, channel = "main", output = 0, input = 0] of edges) {
    connections[from] ??= {};
    connections[from][channel] ??= [];
    while (connections[from][channel].length <= output)
      connections[from][channel].push([]);
    connections[from][channel][output].push({
      node: to,
      type: channel,
      index: input,
    });
  }
  return connections;
}
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
  const flow = buildValueFlow(context, { sourceAnnotations });
  const rules = analyzeAiFlow(context, flow, evidence).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  return { rules, context, flow, evidence };
}
const codes = (result) =>
  result.rules.flatMap((rule) =>
    rule.findings.flatMap((finding) =>
      finding.evidence.map((item) => item.code),
    ),
  );
const diagnostics = (result) =>
  result.rules.flatMap((rule) => rule.diagnostics.map((item) => item.code));
const promptCodes = (result) =>
  codes({
    rules: result.rules.filter((rule) => rule.ruleId === "N8N_AI_PROMPT_DATA"),
  });
const baseEdges = () =>
  wiring(["Source", "Agent"], ["Model", "Agent", "ai_languageModel"]);
function sidecar(context, hash, changes = {}) {
  return parseEvidence(
    {
      schemaVersion: "1.0.0",
      inputSha256: hash,
      sources: [
        {
          id: "operator",
          kind: "declaration",
          method: "user_declaration",
          recordedAt: "2026-11-23T00:00:00Z",
        },
      ],
      ...changes,
    },
    hash,
  );
}
function modelPolicy(
  context,
  hash,
  allowedDataClasses = ["public"],
  changes = {},
) {
  return sidecar(context, hash, {
    policy: {
      id: "policy",
      version: "1",
      sourceId: "operator",
      purpose: "Synthetic AI boundary review",
      defaultDecision: "allow",
      unknownDecision: "review",
      egress: [
        {
          id: "model-route",
          nodeKey: context.nodeByName.get("Model").key,
          sink: "ai_model",
          mode: "allowlist",
          destinations: ["https://model.example.invalid"],
          allowedDataClasses,
          purpose: "Synthetic prompt",
        },
      ],
    },
    ...changes,
  });
}

test("ordinary workflows have not-applicable AI rules", () => {
  const result = run([source()]);
  assert.ok(
    result.rules.every((rule) => rule.coverage[0].status === "not_applicable"),
  );
});

test("known AI contracts preserve secret and PII prompt components and mask evidence", () => {
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password + $json.body.email }}" }),
      model(),
    ],
    baseEdges(),
  );
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
  );
  assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    diagnostics(result).includes("ai_model_invocation_and_output_unverified"),
  );
  assert.ok(
    diagnostics(result).includes(
      "ai_model_endpoint_from_credentials_unverified",
    ),
  );
  assert.ok(!JSON.stringify(result.rules).includes("body/password"));
  assert.ok(!JSON.stringify(result.rules).includes("synthetic-model"));
  const report = result.rules.flatMap((rule) => rule.findings);
  assert.ok(report.every((finding) => finding.claim !== "supported_path"));
});

test("a public constant prompt is independent of unrelated upstream secret input", () => {
  const result = run([source(), agent(), model()], baseEdges());
  assert.ok(
    promptCodes(result).includes("ai_prompt_public_component_declared"),
  );
  assert.ok(
    !promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
  );
  assert.ok(!promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    diagnostics(result).includes("ai_model_invocation_and_output_unverified"),
  );
});

test("prompt auto and guardrails modes select their real field and ignore text", () => {
  for (const [mode, field] of [
    ["auto", "chatInput"],
    ["guardrails", "guardrailsInput"],
  ]) {
    const result = run(
      [
        source(),
        agent({ promptType: mode, text: "synthetic@example.invalid" }),
        model(),
      ],
      baseEdges(),
      (context, hash) =>
        sidecar(context, hash, {
          classifications: [
            {
              nodeKey: context.nodeByName.get("Source").key,
              field,
              dataClass: "secret",
              sourceId: "operator",
            },
          ],
        }),
    );
    const selected = aiPromptInputs(result.context.nodeByName.get("Agent"));
    assert.equal(selected.inputs[0].value, `={{ $json.${field} }}`);
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
    );
  }
  const omitted = run(
    [agent({ promptType: undefined }), model()],
    wiring(["Model", "Agent", "ai_languageModel"]),
  );
  assert.equal(
    aiPromptInputs(omitted.context.nodeByName.get("Agent")).inputs[0].value,
    "={{ $json.chatInput }}",
  );
});

test("dynamic and malformed prompt selectors never imply a public prompt", () => {
  for (const promptType of [null, true, 7, "={{ $json.mode }}", "unexpected"]) {
    const result = run([source(), agent({ promptType }), model()], baseEdges());
    assert.ok(diagnostics(result).includes("ai_prompt_selector_unresolved"));
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_public_component_declared"),
    );
  }
});

test("system prompts and unresolved options retain sensitivity independently", () => {
  const mixed = run(
    [
      source(),
      agent({
        options: {
          passthroughBinaryImages: false,
          systemMessage: "={{ $json.body.password }}",
        },
      }),
      model(),
    ],
    baseEdges(),
  );
  assert.ok(promptCodes(mixed).includes("ai_prompt_to_model_secret_candidate"));
  assert.ok(promptCodes(mixed).includes("ai_prompt_public_component_declared"));
  for (const options of [null, [], "={{ $json.body.password }}"]) {
    const result = run([source(), agent({ options }), model()], baseEdges());
    assert.ok(diagnostics(result).includes("ai_prompt_options_unresolved"));
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
  }
});

test("default binary passthrough preserves unknown content and false disables only that uncertainty", () => {
  const defaults = run(
    [agent({ options: {} }), model()],
    wiring(["Model", "Agent", "ai_languageModel"]),
  );
  assert.ok(
    diagnostics(defaults).includes("ai_binary_prompt_content_unverified"),
  );
  assert.ok(
    promptCodes(defaults).includes("ai_prompt_to_model_unknown_component"),
  );
  const fixed = run(
    [agent(), model()],
    wiring(["Model", "Agent", "ai_languageModel"]),
  );
  assert.ok(
    !diagnostics(fixed).includes("ai_binary_prompt_content_unverified"),
  );
  assert.ok(
    !promptCodes(fixed).includes("ai_prompt_to_model_unknown_component"),
  );
});

test("external prompt influence is a tool-selection candidate, not observed invocation", () => {
  const result = run(
    [source(), agent({ text: "={{ $json.body.message }}" }), model(), tool()],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(
    promptCodes(result).includes(
      "ai_external_prompt_may_influence_tool_selection",
    ),
  );
  const finding = result.rules
    .flatMap((rule) => rule.findings)
    .find(
      (item) =>
        item.evidence[0].code ===
        "ai_external_prompt_may_influence_tool_selection",
    );
  assert.equal(finding.claim, "candidate");
  assert.ok(finding.assumptions.includes("ai_invocation_not_observed"));
  assert.ok(
    diagnostics(result).includes("ai_tool_arguments_and_result_unverified"),
  );
});

test("typed edges enforce roles, ports, enablement and fallback multiplicity", () => {
  const good = run(
    [agent(), model(), tool()],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(
    good.context.unsupportedEdges.every((edge) =>
      coveredAiEdge(good.context, edge),
    ),
  );
  for (const edges of [
    wiring(["Tool", "Agent", "ai_languageModel"]),
    wiring(["Model", "Agent", "ai_languageModel", 0, 1]),
    wiring(["Model", "Agent", "ai_languageModel", 1, 0]),
    wiring(["Agent", "Model", "ai_tool"]),
  ]) {
    const result = run([agent(), model(), tool()], edges);
    assert.ok(
      result.context.unsupportedEdges.every(
        (edge) => !coveredAiEdge(result.context, edge),
      ),
    );
    assert.ok(
      diagnostics(result).includes("ai_connection_contract_unresolved"),
    );
  }
  for (const needsFallback of [false, true, "={{ true }}"]) {
    const result = run(
      [agent({ needsFallback }), model(), model({}, "Fallback")],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Fallback", "Agent", "ai_languageModel", 0, 1],
      ),
    );
    assert.equal(
      result.context.unsupportedEdges.every((edge) =>
        coveredAiEdge(result.context, edge),
      ),
      needsFallback === true,
    );
    assert.ok(
      diagnostics(result).includes(
        "ai_model_selection_and_fallback_unverified",
      ),
    );
  }
  const duplicatePort = run(
    [agent({ needsFallback: true }), model(), model({}, "Fallback")],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Fallback", "Agent", "ai_languageModel"],
    ),
  );
  assert.ok(
    duplicatePort.context.unsupportedEdges.every(
      (edge) => !coveredAiEdge(duplicatePort.context, edge),
    ),
  );
});

test("unknown versions and legacy non-tools agents remain unreviewed", () => {
  for (const candidate of [
    node("Agent", "agent", 99),
    node("Agent", "agent", 1.7, { agent: "sqlAgent" }),
    node("Agent", "agent", 1.7, { agent: "={{ 'toolsAgent' }}" }),
  ]) {
    const result = run(
      [candidate, model()],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.equal(
      isReviewedAiNode(result.context, result.context.nodeByName.get("Agent")),
      false,
    );
    assert.equal(
      aiPromptInputs(result.context.nodeByName.get("Agent")),
      undefined,
    );
    assert.ok(diagnostics(result).includes("ai_node_profile_unreviewed"));
  }
});

test("output parser is not a sanitizer and its schema may itself contain personal data", () => {
  const parser = node("Parser", "outputParserStructured", 1.3, {
    schemaType: "manual",
    inputSchema: '{"description":"synthetic@example.invalid","type":"object"}',
  });
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password }}", hasOutputParser: true }),
      model(),
      parser,
    ],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Parser", "Agent", "ai_outputParser"],
    ),
  );
  assert.ok(codes(result).includes("ai_output_parser_is_not_sanitizer"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
  );
  assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    !JSON.stringify(result.rules).includes("synthetic@example.invalid"),
  );
});

test("memory contents and session isolation remain unverified with constant public prompts", () => {
  for (const sessionIdType of ["customKey", "fromInput"]) {
    const memory = node("Memory", "memoryBufferWindow", 1.3, {
      sessionIdType,
      sessionKey: "synthetic-shared-session",
    });
    const result = run(
      [agent(), model(), memory],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Memory", "Agent", "ai_memory"],
      ),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.ok(
      diagnostics(result).includes(
        "ai_memory_content_and_session_isolation_unverified",
      ),
    );
    assert.equal(
      codes(result).includes("ai_memory_constant_session_key_candidate"),
      sessionIdType === "customKey",
    );
    assert.ok(
      !JSON.stringify(result.rules).includes("synthetic-shared-session"),
    );
  }
});

test("retriever provenance is retained without asserting stored document content", () => {
  const qa = node("QA", "chainRetrievalQa", 1.7, {
    promptType: "define",
    text: "public question",
  });
  const retriever = node("Retriever", "retrieverVectorStore", 1, {});
  const store = node("Vector", "vectorStoreInMemory", 1.3, { mode: "load" });
  const result = run(
    [qa, retriever, store, model()],
    wiring(
      ["Model", "QA", "ai_languageModel"],
      ["Retriever", "QA", "ai_retriever"],
      ["Vector", "Retriever", "ai_vectorStore"],
    ),
  );
  assert.ok(
    diagnostics(result).includes("ai_retrieved_context_content_unverified"),
  );
  assert.ok(diagnostics(result).includes("ai_context_connection_unresolved"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
  const vectorKey = result.context.nodeByName.get("Vector").key;
  assert.ok(
    result.rules
      .flatMap((rule) => rule.findings)
      .some((finding) =>
        finding.evidence.some((item) => item.location.nodeKey === vectorKey),
      ),
  );
});

test("tool contracts report HTTP, SQL, Code and subworkflow capabilities without execution", () => {
  globalThis.aiStaticExecutionSentinel = 0;
  const candidates = [
    tool({ url: "={{ $fromAI('target') }}" }),
    node("SQL", "n8n-nodes-base.postgresTool", 2.8, {
      operation: "executeQuery",
      query: "={{ $fromAI('query') }}",
    }),
    node("Code", "toolCode", 1.3, {
      language: "javaScript",
      jsCode: "globalThis.aiStaticExecutionSentinel++; return query;",
    }),
    node("Workflow", "toolWorkflow", 2.2, {
      workflowId: { value: "={{ $fromAI('workflow') }}" },
      workflowInputs: { value: { example: "={{ $fromAI('input') }}" } },
    }),
  ];
  const result = run(
    [agent(), model(), ...candidates],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ...candidates.map((item) => [item.name, "Agent", "ai_tool"]),
    ),
  );
  for (const capability of ["http", "sql", "code", "workflow"])
    assert.ok(
      codes(result).includes(`ai_${capability}_tool_capability_declared`),
    );
  assert.ok(
    codes(result).includes("ai_model_supplied_tool_arguments_declared"),
  );
  assert.ok(diagnostics(result).includes("ai_tool_workflow_target_unresolved"));
  assert.ok(
    diagnostics(result).includes("ai_code_tool_sandbox_and_effects_unverified"),
  );
  assert.equal(globalThis.aiStaticExecutionSentinel, 0);
  delete globalThis.aiStaticExecutionSentinel;
});

test("fromAI declarations do not confer public data, trusted argument schemas or authority", () => {
  const result = run(
    [
      agent(),
      model(),
      tool({
        toolDescription: "synthetic@example.invalid",
        parametersBody: {
          values: [
            { name: "synthetic-sensitive-name", value: "$fromAI('argument')" },
          ],
        },
      }),
    ],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(
    codes(result).includes("ai_model_supplied_tool_arguments_declared"),
  );
  assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
  assert.ok(!JSON.stringify(result.rules).includes("synthetic-sensitive-name"));
});

test("approval declarations must bind both agent and tool and never prove enforcement", () => {
  for (const exact of [false, true]) {
    const result = run(
      [agent(), agent({}, "Other"), model(), tool()],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Tool", "Agent", "ai_tool"],
      ),
      (context, hash) =>
        sidecar(context, hash, {
          aiApprovals: [
            {
              nodeKey: context.nodeByName.get(exact ? "Agent" : "Other").key,
              toolNodeKeys: [context.nodeByName.get("Tool").key],
              required: true,
              sourceId: "operator",
            },
          ],
        }),
    );
    assert.equal(
      codes(result).includes("ai_tool_approval_declared_required"),
      exact,
    );
    assert.ok(
      diagnostics(result).includes(
        exact
          ? "ai_runtime_approval_enforcement_unverified"
          : "ai_approval_evidence_missing",
      ),
    );
  }
});

test("model policy compares only explicit known endpoints and keeps mixed class denial", () => {
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password + $json.body.email }}" }),
      model({ options: { baseURL: "https://model.example.invalid/v1" } }),
    ],
    baseEdges(),
    (context, hash) => modelPolicy(context, hash, ["personal"]),
  );
  assert.ok(promptCodes(result).includes("trusted_policy_transfer_disallowed"));
  assert.ok(promptCodes(result).includes("data_class_not_allowed"));
  const unresolved = run(
    [agent(), model()],
    wiring(["Model", "Agent", "ai_languageModel"]),
    (context, hash) => modelPolicy(context, hash),
  );
  assert.ok(
    diagnostics(unresolved).includes(
      "ai_model_endpoint_from_credentials_unverified",
    ),
  );
  assert.ok(
    diagnostics(unresolved).includes("ai_model_transfer_policy_unresolved"),
  );
  assert.ok(
    !promptCodes(unresolved).includes("trusted_policy_transfer_disallowed"),
  );
});

test("an allowlisted explicit model endpoint cannot resolve memory content or actual calls", () => {
  const memory = node("Memory", "memoryRedisChat", 1.6, {});
  const result = run(
    [
      agent(),
      model({ options: { baseURL: "https://model.example.invalid/v1" } }),
      memory,
    ],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Memory", "Agent", "ai_memory"],
    ),
    (context, hash) => modelPolicy(context, hash, ["public", "unknown"]),
  );
  assert.ok(
    diagnostics(result).includes("ai_model_transfer_policy_unresolved"),
  );
  assert.ok(
    diagnostics(result).includes("ai_model_context_sensitivity_unverified"),
  );
  assert.ok(
    result.rules
      .filter((rule) => rule.ruleId !== "N8N_AI_VECTOR_DATA")
      .every((rule) =>
        rule.coverage.some((coverage) => coverage.status === "partial"),
      ),
  );
});

test("exact internal prompt declarations participate in model allow and deny policy", () => {
  for (const allowed of [true, false]) {
    const result = run(
      [
        source(),
        agent({ text: "={{ $json.body.document }}" }),
        model({ options: { baseURL: "https://model.example.invalid/v1" } }),
      ],
      baseEdges(),
      (context, hash) =>
        modelPolicy(context, hash, allowed ? ["internal"] : ["public"], {
          classifications: [
            {
              nodeKey: context.nodeByName.get("Source").key,
              field: "/body/document",
              dataClass: "internal",
              sourceId: "operator",
            },
          ],
        }),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_internal_component"),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.equal(
      promptCodes(result).includes("trusted_policy_transfer_disallowed"),
      !allowed,
    );
    assert.equal(
      promptCodes(result).includes("data_class_not_allowed"),
      !allowed,
    );
    assert.ok(
      !diagnostics(result).includes("ai_model_transfer_policy_unresolved"),
    );
    assert.ok(
      diagnostics(result).includes("ai_model_invocation_and_output_unverified"),
    );
    assert.ok(!JSON.stringify(result.rules).includes("/body/document"));
  }
});

test("internal, personal, secret, public and unknown prompt components all survive joins", () => {
  for (const denyInternal of [false, true]) {
    const result = run(
      [
        source(),
        agent({
          text: "={{ 'prefix:' + $json.body.document + $json.body.email + $json.body.password + $json.body.unclassified }}",
        }),
        model({ options: { baseURL: "https://model.example.invalid/v1" } }),
      ],
      baseEdges(),
      (context, hash) =>
        modelPolicy(
          context,
          hash,
          denyInternal
            ? ["public", "personal", "secret", "unknown"]
            : ["public", "personal", "secret", "internal", "unknown"],
          {
            classifications: [
              {
                nodeKey: context.nodeByName.get("Source").key,
                field: "body.document",
                dataClass: "internal",
                sourceId: "operator",
              },
            ],
          },
        ),
    );
    for (const code of [
      "ai_prompt_to_model_internal_component",
      "ai_prompt_to_model_pii_candidate",
      "ai_prompt_to_model_secret_candidate",
      "ai_prompt_public_component_declared",
      "ai_prompt_to_model_unknown_component",
    ])
      assert.ok(promptCodes(result).includes(code), code);
    assert.equal(
      promptCodes(result).includes("trusted_policy_transfer_disallowed"),
      denyInternal,
    );
    assert.equal(
      diagnostics(result).includes("ai_model_transfer_policy_unresolved"),
      !denyInternal,
    );
  }
});

test("an exact internal declaration does not resolve a partial prompt transform", () => {
  const result = run(
    [
      source(),
      agent({ text: "={{ unknownTransform($json.body.document) }}" }),
      model({ options: { baseURL: "https://model.example.invalid/v1" } }),
    ],
    baseEdges(),
    (context, hash) =>
      modelPolicy(context, hash, ["internal", "unknown"], {
        classifications: [
          {
            nodeKey: context.nodeByName.get("Source").key,
            field: "/body/document",
            dataClass: "internal",
            sourceId: "operator",
          },
        ],
      }),
  );
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_internal_component"),
  );
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
  assert.ok(
    diagnostics(result).includes("ai_model_transfer_policy_unresolved"),
  );
});

test("internal declarations do not classify ancestor, descendant or different-node prompt origins", () => {
  for (const [field, target] of [
    ["/body", "Source"],
    ["/body/document/section", "Source"],
    ["/body/document", "Model"],
  ]) {
    const result = run(
      [
        source(),
        agent({ text: "={{ $json.body.document }}" }),
        model({ options: { baseURL: "https://model.example.invalid/v1" } }),
      ],
      baseEdges(),
      (context, hash) =>
        modelPolicy(context, hash, ["public"], {
          classifications: [
            {
              nodeKey: context.nodeByName.get(target).key,
              field,
              dataClass: "internal",
              sourceId: "operator",
            },
          ],
        }),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_internal_component"),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.ok(
      !promptCodes(result).includes("trusted_policy_transfer_disallowed"),
    );
    assert.ok(
      diagnostics(result).includes("ai_model_transfer_policy_unresolved"),
    );
  }
});

test("same-field classifications apply only to their declared source in multi-origin prompts", () => {
  for (const classifyOther of [false, true]) {
    const result = run(
      [
        source(),
        { ...source(), id: "Other", name: "Other" },
        agent({
          text: "={{ $('Source').first().json.body.document + $('Other').first().json.body.document }}",
        }),
        model({ options: { baseURL: "https://model.example.invalid/v1" } }),
      ],
      wiring(
        ["Source", "Agent"],
        ["Other", "Agent"],
        ["Model", "Agent", "ai_languageModel"],
      ),
      (context, hash) =>
        modelPolicy(context, hash, ["internal", "public", "unknown"], {
          classifications: [
            {
              nodeKey: context.nodeByName.get("Source").key,
              field: "/body/document",
              dataClass: "internal",
              sourceId: "operator",
            },
            ...(classifyOther
              ? [
                  {
                    nodeKey: context.nodeByName.get("Other").key,
                    field: "/body/document",
                    dataClass: "personal",
                    sourceId: "operator",
                  },
                ]
              : []),
          ],
        }),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_internal_component"),
    );
    assert.equal(
      promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
      classifyOther,
    );
    assert.equal(
      promptCodes(result).includes("trusted_policy_transfer_disallowed"),
      classifyOther,
    );
    if (!classifyOther)
      assert.ok(
        promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
      );
  }
});

test("conflicting declarations for one prompt origin are rejected before analysis", () => {
  assert.throws(
    () =>
      run([source(), agent(), model()], baseEdges(), (context, hash) =>
        sidecar(context, hash, {
          classifications: ["internal", "public"].map((dataClass) => ({
            nodeKey: context.nodeByName.get("Source").key,
            field: "/body/document",
            dataClass,
            sourceId: "operator",
          })),
        }),
      ),
    /duplicate_evidence/,
  );
});

test("disabled models and tools do not create invocation or secret-transfer candidates", () => {
  const disabledModel = { ...model(), disabled: true };
  const disabledTool = { ...tool(), disabled: true };
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password }}" }),
      disabledModel,
      disabledTool,
    ],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(
    diagnostics(result).includes("ai_required_model_connection_missing"),
  );
  assert.ok(
    !promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
  );
  assert.ok(
    !promptCodes(result).includes(
      "ai_external_prompt_may_influence_tool_selection",
    ),
  );
});

test("message collections resolve nested expressions and retain truncated multimodal uncertainty", () => {
  const chain = node("Chain", "chainLlm", 1.7, {
    promptType: "define",
    text: "public",
    messages: {
      messageValues: [
        {
          type: "SystemMessagePromptTemplate",
          message: "={{ $json.body.password }}",
        },
        { type: "HumanMessagePromptTemplate", messageType: "imageBinary" },
      ],
    },
  });
  const result = run(
    [source(), chain, model()],
    wiring(["Source", "Chain"], ["Model", "Chain", "ai_languageModel"]),
  );
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
  );
  assert.ok(
    diagnostics(result).includes("ai_binary_prompt_content_unverified"),
  );
  chain.parameters.messages.messageValues = Array.from({ length: 33 }, () => ({
    message: "public",
  }));
  const limit = run(
    [chain, model()],
    wiring(["Model", "Chain", "ai_languageModel"]),
  );
  assert.ok(diagnostics(limit).includes("ai_prompt_field_limit"));
  assert.ok(
    promptCodes(limit).includes("ai_prompt_to_model_unknown_component"),
  );
});

test("cycles, parameter inspection budgets and arbitrary field names remain bounded and masked", () => {
  const nested = node("Nested", "agentTool", 2.2, { text: "public" });
  const cycle = run(
    [agent(), model(), nested],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Nested", "Agent", "ai_tool"],
      ["Nested", "Nested", "ai_tool"],
    ),
  );
  assert.ok(diagnostics(cycle).includes("ai_context_cycle_unresolved"));
  const fields = Object.fromEntries(
    Array.from({ length: 600 }, (_, index) => [
      `sensitive_field_${index}`,
      "public",
    ]),
  );
  const bounded = run(
    [agent(), model(), tool(fields)],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(diagnostics(bounded).includes("ai_parameter_inspection_limit"));
  assert.ok(!JSON.stringify(bounded.rules).includes("sensitive_field_"));
});

test("rule results are deterministic and finding budgets are explicit", () => {
  const nodes = Array.from({ length: 40 }, (_, index) =>
    node(`Tool${index}`, "toolCode", 1.3, {
      jsCode: "return query;",
      description: "$fromAI('argument')",
    }),
  );
  const connections = wiring(
    ...nodes.map((item) => [item.name, "Agent", "ai_tool"]),
  );
  const first = run([agent(), model(), ...nodes], connections);
  const second = run([agent(), model(), ...nodes], connections);
  assert.deepEqual(first.rules, second.rules);
  assert.ok(diagnostics(first).includes("ai_analysis_result_limit"));
  assert.ok(
    first.rules.every(
      (rule) => rule.findings.length <= 64 && rule.diagnostics.length <= 65,
    ),
  );
});

test("an auto-fixing parser keeps upstream secret candidates at its separate retry model", () => {
  const parser = node("Parser", "outputParserStructured", 1.3, {
    autoFix: true,
    schemaType: "manual",
    inputSchema: '{"type":"object"}',
    prompt: "Fix {error}",
  });
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password }}", hasOutputParser: true }),
      model(),
      model({}, "RetryModel"),
      parser,
    ],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Parser", "Agent", "ai_outputParser"],
      ["RetryModel", "Parser", "ai_languageModel"],
    ),
  );
  const parserKey = result.context.nodeByName.get("Parser").key;
  const findings = result.rules
    .flatMap((rule) => rule.findings)
    .filter((finding) => finding.location.nodeKey === parserKey);
  assert.ok(
    findings.some(
      (finding) =>
        finding.evidence[0].code === "ai_prompt_to_model_secret_candidate",
    ),
  );
  assert.ok(
    findings.some(
      (finding) =>
        finding.evidence[0].code === "ai_prompt_to_model_unknown_component",
    ),
  );
  assert.ok(
    diagnostics(result).includes(
      "ai_output_parser_retry_model_content_unverified",
    ),
  );
});

test("inactive parser examples and automatic tool descriptions do not invent personal transfers", () => {
  const parser = node("Parser", "outputParserStructured", 1.3, {
    schemaType: "manual",
    inputSchema: '{"type":"object"}',
    jsonSchemaExample: '{"email":"synthetic@example.invalid"}',
  });
  const result = run(
    [
      agent({ hasOutputParser: true }),
      model(),
      parser,
      tool({
        descriptionType: "auto",
        toolDescription: "synthetic@example.invalid",
      }),
    ],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Parser", "Agent", "ai_outputParser"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(!promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
});

test("fromAI schema metadata retains literal personal data and unknown generated arguments", () => {
  const result = run(
    [
      agent(),
      model(),
      tool({
        url: "={{ $fromAI('target', 'synthetic@example.invalid', 'string') }}",
      }),
    ],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Tool", "Agent", "ai_tool"],
    ),
  );
  assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
});

test("native Code and Workflow V1 tools expose only their active input schema metadata", () => {
  const inputSchema = JSON.stringify({
    type: "object",
    properties: {
      query: { type: "string", description: "synthetic@example.invalid" },
    },
  });
  for (const type of ["toolCode", "toolWorkflow"])
    for (const version of [1, 1.1, 1.2, 1.3])
      for (const enabled of [true, false]) {
        const native = node("Native", type, version, {
          description: "A synthetic tool",
          specifyInputSchema: enabled,
          schemaType: "manual",
          inputSchema,
          jsonSchemaExample: '{"unused":"unused@example.invalid"}',
        });
        const result = run(
          [agent(), model(), native],
          wiring(
            ["Model", "Agent", "ai_languageModel"],
            ["Native", "Agent", "ai_tool"],
          ),
        );
        assert.equal(
          promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
          enabled,
          `${type} ${version} ${enabled}`,
        );
        assert.ok(
          !JSON.stringify(result.rules).includes("synthetic@example.invalid"),
        );
      }
});

test("fixed native tool JSON examples resolve conversion while unknown selectors stay uncertain", () => {
  for (const schemaType of [undefined, "fromJson", null, "={{ $json.mode }}"])
    for (const type of ["toolCode", "toolWorkflow"]) {
      const native = node("Native", type, 1.3, {
        specifyInputSchema: true,
        schemaType,
        inputSchema:
          '{"type":"string","description":"synthetic@example.invalid"}',
        jsonSchemaExample: '{"value":"example@example.invalid"}',
      });
      const result = run(
        [agent(), model(), native],
        wiring(
          ["Model", "Agent", "ai_languageModel"],
          ["Native", "Agent", "ai_tool"],
        ),
      );
      assert.equal(
        promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
        schemaType === null || (schemaType?.startsWith("=") ?? false),
      );
      assert.ok(
        !diagnostics(result).includes(
          "ai_tool_example_derived_schema_content_unverified",
        ),
      );
      assert.ok(
        promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
      );
    }
});

test("native tool code and inactive fields are not fromAI model schema declarations", () => {
  for (const parameters of [
    {
      language: "javaScript",
      jsCode:
        'const unused="synthetic@example.invalid"; const marker="$fromAI(\'id\',\'public\')"; return "public";',
    },
    {
      language: "python",
      pythonCode:
        'unused="synthetic@example.invalid"\nmarker="$fromAI(\'id\',\'public\')"\nreturn "public"',
    },
    {
      specifyInputSchema: false,
      inputSchema:
        '{"description":"synthetic@example.invalid $fromAI(\'id\')"}',
    },
  ]) {
    const result = run(
      [agent(), model(), node("Native", "toolCode", 1.3, parameters)],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Native", "Agent", "ai_tool"],
      ),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
    );
    assert.ok(
      !codes(result).includes("ai_model_supplied_tool_arguments_declared"),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
  }
});

test("generated tool schemas retain fromAI arguments without surrounding fixed request text", () => {
  for (const description of ["public", "synthetic@example.invalid"]) {
    const result = run(
      [
        agent(),
        model(),
        tool({
          url: `https://example.invalid/unused@example.invalid/{{ $fromAI('path', '${description}') }}`,
        }),
      ],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Tool", "Agent", "ai_tool"],
      ),
    );
    assert.equal(
      promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
      description !== "public",
    );
    assert.ok(
      codes(result).includes("ai_model_supplied_tool_arguments_declared"),
    );
  }
});

test("Workflow V2 fromAI schema construction requires a declared input schema", () => {
  for (const active of [false, true]) {
    const native = node("Native", "toolWorkflow", 2.2, {
      description: "A synthetic workflow",
      workflowInputs: {
        schema: active ? [{ id: "query", type: "string" }] : [],
        value: {
          query: "={{ $fromAI('query', 'synthetic@example.invalid') }}",
        },
      },
    });
    const result = run(
      [agent(), model(), native],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Native", "Agent", "ai_tool"],
      ),
    );
    assert.equal(
      promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
      active,
    );
    assert.equal(
      codes(result).includes("ai_model_supplied_tool_arguments_declared"),
      active,
    );
  }
});

test("fromAI scanning handles quoted parentheses, repeated declarations and malformed suffixes without execution", () => {
  for (const value of [
    "$fromAI('first', 'public (description)') $fromAI('next', 'synthetic@example.invalid')",
    "$fromAI('first', 'synthetic@example.invalid') $fromAI('broken'",
  ]) {
    const result = run(
      [agent(), model(), tool({ url: value })],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Tool", "Agent", "ai_tool"],
      ),
    );
    assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.equal(
      diagnostics(result).includes("ai_from_ai_declaration_unresolved"),
      value.includes("broken"),
    );
  }
});

test("OpenAI model request metadata is selected only for the active Responses mode", () => {
  const settings = [
    { metadata: '{"owner":"synthetic@example.invalid"}' },
    { safetyIdentifier: "synthetic@example.invalid" },
    { promptCacheKey: "synthetic@example.invalid" },
    { conversationId: "synthetic@example.invalid" },
    {
      promptConfig: {
        promptOptions: { variables: '{"owner":"synthetic@example.invalid"}' },
      },
    },
    {
      textFormat: {
        textOptions: {
          type: "json_schema",
          schema: '{"type":"string","description":"synthetic@example.invalid"}',
        },
      },
    },
  ];
  for (const typeVersion of [1, 1.1, 1.2, 1.3])
    for (const responsesApiEnabled of [false, true])
      for (const settingsEntry of settings) {
        const result = run(
          [
            agent(),
            {
              ...model({ responsesApiEnabled, options: settingsEntry }),
              typeVersion,
            },
          ],
          wiring(["Model", "Agent", "ai_languageModel"]),
        );
        assert.equal(
          promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
          responsesApiEnabled,
        );
        assert.ok(
          !JSON.stringify(result.rules).includes("synthetic@example.invalid"),
        );
      }
});

test("model extra body is request data in both API modes and nested expressions remain uncertain", () => {
  for (const responsesApiEnabled of [false, true]) {
    const result = run(
      [
        agent(),
        model({
          responsesApiEnabled,
          options: {
            extraBody: {
              metadata: { user: "synthetic@example.invalid" },
              privateValue: "={{ $env.SECRET }}",
            },
          },
        }),
      ],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
    );
  }
});

test("inactive model schema, Responses fields and local options do not create personal data transfers", () => {
  for (const responsesApiEnabled of [false, true]) {
    const result = run(
      [
        agent(),
        model({
          responsesApiEnabled,
          options: {
            timeout: "synthetic@example.invalid",
            maxRetries: "synthetic@example.invalid",
            textFormat: {
              textOptions: {
                type: "text",
                schema: '{"description":"synthetic@example.invalid"}',
              },
            },
            ...(responsesApiEnabled
              ? {}
              : { metadata: '{"owner":"synthetic@example.invalid"}' }),
          },
        }),
      ],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
    );
  }
});

test("model builtin search settings contribute data and keep remote tool results unknown", () => {
  for (const responsesApiEnabled of [false, true]) {
    const result = run(
      [
        agent(),
        model({
          responsesApiEnabled,
          options: undefined,
          builtInTools: {
            webSearch: { city: "synthetic@example.invalid" },
            fileSearch: { filters: '{"owner":"synthetic@example.invalid"}' },
          },
        }),
      ],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.equal(
      promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
      responsesApiEnabled,
    );
    assert.equal(
      diagnostics(result).includes(
        "ai_builtin_tool_permissions_and_results_unverified",
      ),
      responsesApiEnabled,
    );
    if (responsesApiEnabled)
      assert.ok(
        promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
      );
  }
});

test("fallback model policy receives only that model's own request configuration", () => {
  for (const allowPrimaryPersonal of [false, true]) {
    const result = run(
      [
        agent({ needsFallback: true }),
        model({
          responsesApiEnabled: true,
          options: {
            baseURL: "https://model.example.invalid/v1",
            metadata: '{"owner":"synthetic@example.invalid"}',
          },
        }),
        model(
          { options: { baseURL: "https://fallback.example.invalid/v1" } },
          "Fallback",
        ),
      ],
      wiring(
        ["Model", "Agent", "ai_languageModel"],
        ["Fallback", "Agent", "ai_languageModel", 0, 1],
      ),
      (context, hash) => {
        const evidence = modelPolicy(
          context,
          hash,
          allowPrimaryPersonal ? ["public", "personal"] : ["public"],
        );
        evidence.policy.egress.push({
          ...evidence.policy.egress[0],
          id: "fallback-route",
          nodeKey: context.nodeByName.get("Fallback").key,
          destinations: ["https://fallback.example.invalid"],
          allowedDataClasses: ["public"],
        });
        return evidence;
      },
    );
    const denied = result.rules
      .flatMap((rule) => rule.findings)
      .filter(
        (finding) =>
          finding.evidence[0].code === "trusted_policy_transfer_disallowed",
      );
    assert.equal(denied.length, allowPrimaryPersonal ? 0 : 1);
    if (denied.length) {
      assert.ok(
        denied[0].evidence.some(
          (item) =>
            item.location.nodeKey ===
            result.context.nodeByName.get("Model").key,
        ),
      );
      assert.ok(
        !denied[0].evidence.some(
          (item) =>
            item.location.nodeKey ===
            result.context.nodeByName.get("Fallback").key,
        ),
      );
    }
    assert.ok(promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  }
});

test("model option budgets and unresolved selectors cannot imply fully public request data", () => {
  for (const configuration of [
    {
      responsesApiEnabled: "={{ $json.enabled }}",
      options: { metadata: '{"owner":"synthetic@example.invalid"}' },
    },
    { options: "={{ $json.body.password }}" },
    {
      options: {
        extraBody: Object.fromEntries(
          Array.from({ length: 150 }, (_, index) => [
            `private_field_${index}`,
            "public",
          ]),
        ),
      },
    },
  ]) {
    const result = run(
      [agent(), model(configuration)],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.ok(!JSON.stringify(result.rules).includes("private_field_"));
    assert.ok(result.rules.every((rule) => rule.findings.length <= 64));
  }
});

test("official JSON-parsed model fields retain field-name classes without evaluating their string data", () => {
  for (const json of [
    '{"password":"opaque-value","email":"opaque-value"}',
    '{"nested":{"password":"opaque-value","email":"opaque-value"}}',
  ])
    for (const configuration of [
      { options: { extraBody: json } },
      { options: { metadata: json } },
      { options: { promptConfig: { promptOptions: { variables: json } } } },
      {
        options: {
          textFormat: { textOptions: { type: "json_schema", schema: json } },
        },
      },
      { builtInTools: { fileSearch: { filters: json } } },
      { builtInTools: { fileSearch: { vectorStoreIds: json } } },
    ]) {
      const result = run(
        [agent(), model({ responsesApiEnabled: true, ...configuration })],
        wiring(["Model", "Agent", "ai_languageModel"]),
      );
      assert.ok(
        promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
      );
      assert.ok(
        promptCodes(result).includes("ai_prompt_to_model_pii_candidate"),
      );
      assert.ok(!JSON.stringify(result.rules).includes("opaque-value"));
    }
  for (const metadata of [
    '{"ordinary":"={{ $env.SECRET }}"}',
    '"={{ $env.SECRET }}"',
  ]) {
    const result = run(
      [agent(), model({ responsesApiEnabled: true, options: { metadata } })],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.ok(
      !promptCodes(result).includes("ai_prompt_to_model_secret_candidate"),
    );
  }
});

test("JSON-looking ordinary model strings stay strings while invalid or truncated JSON stays unknown", () => {
  const plain = run(
    [
      agent(),
      model({
        responsesApiEnabled: true,
        options: { safetyIdentifier: '{"password":"opaque-value"}' },
      }),
    ],
    wiring(["Model", "Agent", "ai_languageModel"]),
  );
  assert.ok(
    !promptCodes(plain).includes("ai_prompt_to_model_secret_candidate"),
  );
  for (const metadata of [
    '{"email":"synthetic@example.invalid"',
    JSON.stringify({
      password: "opaque-value",
      ...Object.fromEntries(
        Array.from({ length: 600 }, (_, index) => [
          `private_key_${index}`,
          "public",
        ]),
      ),
    }),
  ]) {
    const result = run(
      [agent(), model({ responsesApiEnabled: true, options: { metadata } })],
      wiring(["Model", "Agent", "ai_languageModel"]),
    );
    assert.ok(
      promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
    );
    assert.ok(
      diagnostics(result).some((code) => code.startsWith("model_json_data_")),
    );
    assert.ok(!JSON.stringify(result.rules).includes("private_key_"));
  }
});

test("JSON examples are transformed into schemas rather than sent as literal example values", () => {
  const parser = node("Parser", "outputParserStructured", 1.3, {
    schemaType: "fromJson",
    jsonSchemaExample: '{"email":"synthetic@example.invalid"}',
  });
  const result = run(
    [agent({ hasOutputParser: true }), model(), parser],
    wiring(
      ["Model", "Agent", "ai_languageModel"],
      ["Parser", "Agent", "ai_outputParser"],
    ),
  );
  assert.ok(!promptCodes(result).includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    promptCodes(result).includes("ai_prompt_to_model_unknown_component"),
  );
  assert.ok(
    diagnostics(result).includes(
      "ai_example_derived_schema_content_unverified",
    ),
  );
});

test("a nested agent model retains selected prompt data and unknown parent generated arguments", () => {
  const nested = node("Nested", "agentTool", 2.2, {
    text: "={{ $fromAI('question') }}",
    options: { passthroughBinaryImages: false },
  });
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.password }}" }),
      model(),
      nested,
      model({}, "NestedModel"),
    ],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Nested", "Agent", "ai_tool"],
      ["NestedModel", "Nested", "ai_languageModel"],
    ),
  );
  const nestedKey = result.context.nodeByName.get("Nested").key;
  const findings = result.rules
    .flatMap((rule) => rule.findings)
    .filter((finding) => finding.location.nodeKey === nestedKey);
  assert.equal(
    aiPromptInputs(result.context.nodeByName.get("Nested")),
    undefined,
  );
  assert.ok(
    findings.some(
      (finding) =>
        finding.evidence[0].code === "ai_prompt_to_model_secret_candidate",
    ),
  );
  assert.ok(
    findings.some(
      (finding) =>
        finding.evidence[0].code === "ai_prompt_to_model_unknown_component",
    ),
  );
});

test("a retrieval tool's separate model receives an unknown query and document boundary", () => {
  const retrieval = node("Retrieval", "toolVectorStore", 1.1, {
    description: "Search synthetic documents",
  });
  const result = run(
    [
      source(),
      agent({ text: "={{ $json.body.email }}" }),
      model(),
      retrieval,
      model({}, "RetrievalModel"),
    ],
    wiring(
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
      ["Retrieval", "Agent", "ai_tool"],
      ["RetrievalModel", "Retrieval", "ai_languageModel"],
    ),
  );
  const key = result.context.nodeByName.get("Retrieval").key;
  const findings = result.rules
    .flatMap((rule) => rule.findings)
    .filter((finding) => finding.location.nodeKey === key);
  assert.ok(
    findings.some(
      (finding) =>
        finding.evidence[0].code === "ai_prompt_to_model_pii_candidate",
    ),
  );
  assert.ok(
    diagnostics(result).includes(
      "ai_retrieval_tool_query_and_context_unverified",
    ),
  );
});
