import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { analyzeAiFlow, coveredAiEdge } from "../dist/ai-flow.js";
import { binaryInputProvenance } from "../dist/binary-provenance.js";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow } from "../dist/value-flow.js";
import { parseEvidence } from "../dist/assessment-evidence.js";
import { ruleResultSchema } from "../dist/static-contract.js";

const ai = "@n8n/n8n-nodes-langchain.";
const base = "n8n-nodes-base.";
const node = (name, type, typeVersion, parameters = {}) => ({
  id: name,
  name,
  type: type.includes(".") ? type : ai + type,
  typeVersion,
  parameters,
});
const source = () => node("Source", base + "webhook", 2.1);
const store = (parameters = {}) =>
  node("Store", "vectorStorePinecone", 1, { mode: "insert", ...parameters });
const loader = (parameters = {}) =>
  node("Loader", "documentDefaultDataLoader", 1.1, parameters);
const embedding = () =>
  node("Embedding", "embeddingsOpenAi", 1.2, {
    options: { baseURL: "https://embedding.example.invalid/v1" },
  });
const agent = (options = {}) =>
  node("Agent", "agent", 2.2, {
    promptType: "define",
    text: "public question",
    options,
  });
const model = () => node("Model", "lmChatOpenAi", 1.2);
const map = (value = "={{ $json.body.password }}") =>
  node("Map", base + "set", 3.4, {
    assignments: {
      assignments: [{ id: "value", name: "selected", value, type: "string" }],
    },
  });
function wiring(edges) {
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
function run(nodes, edges, configure, document = {}) {
  const bytes = Buffer.from(
    JSON.stringify({ ...document, nodes, connections: wiring(edges) }),
  );
  const context = createContext(bytes);
  const evidence = configure?.(
    context,
    createHash("sha256").update(bytes).digest("hex"),
  );
  const flow = buildValueFlow(context);
  const rules = analyzeAiFlow(context, flow, evidence).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  return { rules, context, flow };
}
const codes = (result, ruleId) =>
  result.rules
    .filter((rule) => !ruleId || rule.ruleId === ruleId)
    .flatMap((rule) =>
      rule.findings.flatMap((finding) =>
        finding.evidence.map((entry) => entry.code),
      ),
    );
const diagnostics = (result) =>
  result.rules.flatMap((rule) => rule.diagnostics.map((entry) => entry.code));
const vectorEdges = () => [
  ["Source", "Map"],
  ["Map", "Store"],
  ["Loader", "Store", "ai_document"],
  ["Embedding", "Store", "ai_embedding"],
];
const agentEdges = () => [
  ["Source", "Map"],
  ["Map", "Agent"],
  ["Model", "Agent", "ai_languageModel"],
];
const key = (result, name) => result.context.nodeByName.get(name).key;

test("normal Mongo memory and Groq fallback use reviewed exact typed ports", () => {
  const a = agent({ passthroughBinaryImages: false });
  a.parameters.needsFallback = true;
  const result = run(
    [
      a,
      model(),
      node("Groq", "lmChatGroq", 1),
      node("Memory", "memoryMongoDbChat", 1),
    ],
    [
      ["Model", "Agent", "ai_languageModel"],
      ["Groq", "Agent", "ai_languageModel", 0, 1],
      ["Memory", "Agent", "ai_memory"],
    ],
  );
  assert.ok(
    result.context.unsupportedEdges.every((edge) =>
      coveredAiEdge(result.context, edge),
    ),
  );
  assert.ok(!diagnostics(result).includes("ai_connection_contract_unresolved"));
  assert.ok(
    !diagnostics(result).includes("ai_model_request_profile_unreviewed"),
  );
  assert.ok(
    diagnostics(result).includes("ai_memory_context_content_unverified"),
  );
});

test("fixed utility and lookup tools have bounded metadata contracts", () => {
  const tools = [
    node("Date", base + "dateTimeTool", 2),
    node("Crypto", base + "cryptoTool", 1),
    node("RSS", base + "rssFeedReadTool", 1.2, {
      url: "={{ $fromAI('url') }}",
    }),
    node("Wiki", "toolWikipedia", 1),
  ];
  const result = run(
    [agent({ passthroughBinaryImages: false }), model(), ...tools],
    [
      ["Model", "Agent", "ai_languageModel"],
      ...tools.map((tool) => [tool.name, "Agent", "ai_tool"]),
    ],
  );
  assert.ok(
    result.context.unsupportedEdges.every((edge) =>
      coveredAiEdge(result.context, edge),
    ),
  );
  assert.ok(
    diagnostics(result).includes("ai_lookup_tool_destination_unresolved"),
  );
  assert.ok(
    codes(result).includes("ai_lookup_tool_dynamic_destination_candidate"),
  );
  tools[0].typeVersion = 99;
  const future = run(
    [agent(), ...tools],
    tools.map((tool) => [tool.name, "Agent", "ai_tool"]),
  );
  assert.ok(diagnostics(future).includes("ai_node_profile_unreviewed"));
});

test("document insert retains raw secret candidates at embedding and vector storage without a sidecar", () => {
  const result = run(
    [source(), map(), store(), loader(), embedding()],
    vectorEdges(),
  );
  assert.ok(result.rules.every((rule) => rule.profileVersion === "1.2.0"));
  assert.ok(
    codes(result).includes("ai_document_to_embedding_secret_candidate"),
  );
  assert.ok(
    codes(result).includes("ai_document_to_vector_store_secret_candidate"),
  );
  assert.ok(
    diagnostics(result).includes("ai_vector_transfer_policy_not_configured"),
  );
  assert.ok(
    !diagnostics(result).includes("ai_vector_transfer_policy_unresolved"),
  );
});

test("literal document selection stays independent from sensitive sibling input", () => {
  const result = run(
    [
      source(),
      map(),
      store(),
      loader({ jsonMode: "expressionData", jsonData: "public document" }),
      embedding(),
    ],
    vectorEdges(),
  );
  assert.ok(
    codes(result).includes("ai_document_to_embedding_public_component"),
  );
  assert.ok(
    !codes(result).includes("ai_document_to_embedding_secret_candidate"),
  );
  assert.ok(
    !codes(result).includes("ai_document_to_vector_store_secret_candidate"),
  );
});

test("loader metadata is a storage transfer and is not embedding text", () => {
  const result = run(
    [
      source(),
      map(),
      store(),
      loader({
        jsonMode: "expressionData",
        jsonData: "public document",
        options: {
          metadata: {
            metadataValues: [{ name: "audit", value: "={{ $json.selected }}" }],
          },
        },
      }),
      embedding(),
    ],
    vectorEdges(),
  );
  assert.ok(
    codes(result).includes("ai_document_to_vector_store_secret_candidate"),
  );
  assert.ok(
    !codes(result).includes("ai_document_to_embedding_secret_candidate"),
  );
});

test("known Set binary stripping removes only the binary uncertainty", () => {
  const result = run([source(), map(), agent(), model()], agentEdges());
  assert.equal(
    binaryInputProvenance(
      result.context,
      result.context.nodeByName.get("Agent"),
    ).state,
    "none",
  );
  assert.ok(
    !diagnostics(result).includes("ai_binary_prompt_content_unverified"),
  );
  assert.ok(
    !codes(result, "N8N_AI_PROMPT_DATA").includes(
      "ai_prompt_to_model_secret_candidate",
    ),
  );
});

test("default passthrough on unknown input retains provenance and content uncertainty", () => {
  const result = run(
    [source(), agent(), model()],
    [
      ["Source", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
    ],
  );
  assert.ok(diagnostics(result).includes("binary_provenance_unresolved"));
  assert.ok(
    diagnostics(result).includes("ai_binary_prompt_content_unverified"),
  );
  assert.ok(!diagnostics(result).includes("ai_prompt_expression_partial"));
});

test("JSON-to-file dependencies reach Agent input and subsequent opaque model output", () => {
  const convert = node("File", base + "convertToFile", 1.1, {
    operation: "toText",
    sourceProperty: "body.password",
  });
  const result = run(
    [source(), convert, agent(), model()],
    [
      ["Source", "File"],
      ["File", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
    ],
  );
  assert.ok(codes(result).includes("ai_prompt_to_model_secret_candidate"));
  const output = result.flow.output(key(result, "Agent"), "/output");
  assert.ok(output.sensitivityClasses.includes("secret_candidate"));
  assert.ok(
    output.origins.some((origin) => origin.fieldPath === "/body/password"),
  );
  assert.notEqual(output.status, "resolved");
});

test("unreviewed transform does not erase a preceding JSON-to-file candidate", () => {
  const result = run(
    [
      source(),
      node("File", base + "convertToFile", 1, {
        operation: "toText",
        sourceProperty: "body.password",
      }),
      node("Opaque", "custom.unknown", 1),
      agent(),
      model(),
    ],
    [
      ["Source", "File"],
      ["File", "Opaque"],
      ["Opaque", "Agent"],
      ["Model", "Agent", "ai_languageModel"],
    ],
  );
  assert.ok(codes(result).includes("ai_prompt_to_model_secret_candidate"));
  assert.ok(diagnostics(result).includes("binary_provenance_unresolved"));
});

test("binary document conversion preserves source classes without inspecting file bytes", () => {
  const file = node("Map", base + "convertToFile", 1.2, {
    operation: "toBinary",
    sourceProperty: "body.password",
  });
  const result = run(
    [source(), file, store(), loader({ dataType: "binary" }), embedding()],
    vectorEdges(),
  );
  assert.ok(
    codes(result).includes("ai_document_to_embedding_secret_candidate"),
  );
  assert.ok(
    codes(result).includes("ai_document_to_vector_store_secret_candidate"),
  );
  assert.ok(
    diagnostics(result).includes("ai_document_binary_content_unverified"),
  );
});

test("binary loader after proven stripping is a missing data-path gap", () => {
  const result = run(
    [source(), map(), store(), loader({ dataType: "binary" }), embedding()],
    vectorEdges(),
  );
  assert.ok(diagnostics(result).includes("ai_document_binary_input_missing"));
  assert.ok(
    codes(result).includes("ai_document_to_embedding_unknown_component"),
  );
  assert.ok(
    !codes(result).includes("ai_document_to_embedding_public_component"),
  );
});

test("binary AST proof accepts only fresh constant JSON items and never runs Code", () => {
  delete globalThis.__binarySentinel;
  for (const [jsCode, state] of [
    ["return [{json:{public:'ok'}}];", "none"],
    ["return [{json:$json}];", "unknown"],
    [
      "globalThis.__binarySentinel = true; return [{json:{public:'ok'}}];",
      "unknown",
    ],
  ]) {
    const result = run(
      [source(), node("Map", base + "code", 2, { jsCode }), agent(), model()],
      agentEdges(),
    );
    assert.equal(
      binaryInputProvenance(
        result.context,
        result.context.nodeByName.get("Agent"),
      ).state,
      state,
    );
  }
  assert.equal(globalThis.__binarySentinel, undefined);
});

test("bad typed ports, disabled embedding and future store versions remain gaps", () => {
  const badEdges = vectorEdges();
  badEdges.at(-1)[4] = 1;
  badEdges.at(-1)[3] = 0;
  const bad = run([source(), map(), store(), loader(), embedding()], badEdges);
  assert.ok(diagnostics(bad).includes("ai_embedding_connection_unresolved"));
  assert.ok(codes(bad).includes("ai_document_to_embedding_secret_candidate"));
  const disabled = embedding();
  disabled.disabled = true;
  assert.ok(
    diagnostics(
      run([source(), map(), store(), loader(), disabled], vectorEdges()),
    ).includes("ai_required_embedding_connection_missing"),
  );
  const futureStore = store();
  futureStore.typeVersion = 99;
  const future = run(
    [source(), map(), futureStore, loader(), embedding()],
    vectorEdges(),
  );
  assert.equal(
    future.rules.find((rule) => rule.ruleId === "N8N_AI_VECTOR_DATA")
      .coverage[0].status,
    "unsupported",
  );
});

test("fixed Pinecone retriever ports are supported without claiming document contents", () => {
  const result = run(
    [
      store({ mode: "retrieve" }),
      embedding(),
      node("Retriever", "retrieverVectorStore", 1),
      node("QA", "chainRetrievalQa", 1.3, {
        promptType: "define",
        text: "public question",
      }),
      model(),
    ],
    [
      ["Embedding", "Store", "ai_embedding"],
      ["Store", "Retriever", "ai_vectorStore"],
      ["Retriever", "QA", "ai_retriever"],
      ["Model", "QA", "ai_languageModel"],
    ],
  );
  assert.ok(
    result.context.unsupportedEdges.every((edge) =>
      coveredAiEdge(result.context, edge),
    ),
  );
  assert.ok(!diagnostics(result).includes("ai_connection_contract_unresolved"));
  assert.ok(codes(result).includes("ai_query_to_embedding_unknown_component"));
});

test("query load preserves fixed secret source and insertion metadata remains separate", () => {
  const result = run(
    [
      source(),
      store({ mode: "load", prompt: "={{ $json.body.password }}" }),
      embedding(),
    ],
    [
      ["Source", "Store"],
      ["Embedding", "Store", "ai_embedding"],
    ],
  );
  assert.ok(codes(result).includes("ai_query_to_embedding_secret_candidate"));
  assert.ok(
    !diagnostics(result).includes("ai_required_document_connection_missing"),
  );
});

test("explicit class restriction denies document and embedding transfer despite unknown store endpoint", () => {
  const result = run(
    [source(), map(), store(), loader(), embedding()],
    vectorEdges(),
    (context, hash) =>
      parseEvidence(
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
          policy: {
            id: "test",
            version: "1",
            sourceId: "operator",
            purpose: "Synthetic boundary",
            defaultDecision: "allow",
            unknownDecision: "review",
            egress: [
              ["Store", "ai_vector_store"],
              ["Embedding", "ai_model"],
            ].map(([name, sink]) => ({
              id: name,
              nodeKey: context.nodeByName.get(name).key,
              sink,
              mode: "allowlist",
              destinations: ["https://embedding.example.invalid"],
              allowedDataClasses: ["public"],
              purpose: "Synthetic transfer",
            })),
          },
        },
        hash,
      ),
  );
  const denied = result.rules
    .find((rule) => rule.ruleId === "N8N_AI_VECTOR_DATA")
    .findings.filter((finding) =>
      finding.evidence.some(
        (entry) => entry.code === "trusted_policy_transfer_disallowed",
      ),
    );
  assert.ok(denied.length);
  const related = denied.flatMap((finding) =>
    finding.evidence
      .filter((entry) => entry.code === "ai_connected_definition")
      .map((entry) => entry.location.nodeKey),
  );
  assert.ok(related.includes(key(result, "Store")));
  assert.ok(related.includes(key(result, "Embedding")));
});

test("unknown selectors and pointers retain known candidates and explicit gaps", () => {
  const result = run(
    [
      source(),
      map(),
      store(),
      loader({
        jsonMode: "={{ $json.mode }}",
        jsonData: "public",
        options: { pointers: "/public" },
      }),
      embedding(),
    ],
    vectorEdges(),
  );
  assert.ok(
    codes(result).includes("ai_document_to_embedding_secret_candidate"),
  );
  assert.ok(diagnostics(result).includes("ai_document_selector_unresolved"));
  assert.ok(diagnostics(result).includes("ai_document_selection_unresolved"));
});

test("binary cycles and unsupported assignments cannot be proven empty", () => {
  const mapping = map();
  mapping.parameters.assignments.assignments[0].type = "={{ $json.type }}";
  const result = run(
    [source(), mapping, agent(), model()],
    [...agentEdges(), ["Map", "Map"]],
  );
  assert.equal(
    binaryInputProvenance(
      result.context,
      result.context.nodeByName.get("Agent"),
    ).state,
    "unknown",
  );
  assert.ok(diagnostics(result).includes("binary_provenance_cycle"));
});

test("reports do not disclose document, metadata, endpoint or source field text", () => {
  const marker = "SYNTHETIC_PRIVATE_DOCUMENT_43e9";
  const result = run(
    [
      source(),
      map(),
      store(),
      loader({
        jsonMode: "expressionData",
        jsonData: marker,
        options: {
          metadata: { metadataValues: [{ name: marker, value: marker }] },
        },
      }),
      embedding(),
    ],
    vectorEdges(),
  );
  const serialized = JSON.stringify(result.rules);
  assert.ok(!serialized.includes(marker));
  assert.ok(!serialized.includes("embedding.example.invalid"));
  assert.ok(!serialized.includes("body.password"));
});

test("pinned output, dynamic Set collections and wrong input ports cannot prove no binary", () => {
  const nodes = [source(), map(), agent(), model()];
  const pinned = run(nodes, agentEdges(), undefined, {
    pinData: {
      Map: [
        {
          json: { public: "fixed" },
          binary: {
            attachment: { mimeType: "text/plain", data: "U1lOVEhFVElD" },
          },
        },
      ],
    },
  });
  assert.ok(diagnostics(pinned).includes("binary_pinned_output_unverified"));
  assert.ok(
    diagnostics(pinned).includes("ai_binary_prompt_content_unverified"),
  );
  for (const assignments of ["={{ $json.assignments }}", null, []]) {
    const mapping = map();
    mapping.parameters.assignments = assignments;
    const result = run([source(), mapping, agent(), model()], agentEdges());
    assert.equal(
      binaryInputProvenance(
        result.context,
        result.context.nodeByName.get("Agent"),
      ).state,
      "unknown",
    );
  }
  const mapping = map();
  mapping.parameters.mode = "={{ $json.mode }}";
  assert.ok(
    diagnostics(
      run([source(), mapping, agent(), model()], agentEdges()),
    ).includes("binary_provenance_unresolved"),
  );
  const edges = agentEdges();
  edges[0].push("main", 0, 1);
  assert.ok(
    diagnostics(run(nodes, edges)).includes("binary_connection_unresolved"),
  );
});

test("Chain binary messages preserve conversion candidates and diagnose stripped input", () => {
  const chain = node("Agent", "chainLlm", 1.7, {
    promptType: "define",
    text: "public",
    messages: {
      messageValues: [
        { type: "HumanMessagePromptTemplate", messageType: "imageBinary" },
      ],
    },
  });
  const missing = run([source(), map(), chain, model()], agentEdges());
  assert.ok(diagnostics(missing).includes("ai_binary_prompt_input_missing"));
  const file = node("Map", base + "convertToFile", 1, {
    operation: "toText",
    sourceProperty: "body.password",
  });
  const possible = run([source(), file, chain, model()], agentEdges());
  assert.ok(codes(possible).includes("ai_prompt_to_model_secret_candidate"));
});

test("unknown parameter effects cannot re-use an earlier no-binary proof", () => {
  for (const [type, version] of [
    ["if", 2],
    ["switch", 3.2],
  ]) {
    const branch = node("Branch", base + type, version, {
      conditions: {
        conditions: [{ leftValue: "={{ effect($json) }}", rightValue: true }],
      },
    });
    const result = run(
      [source(), map(), branch, agent(), model()],
      [
        ["Source", "Map"],
        ["Map", "Branch"],
        ["Branch", "Agent"],
        ["Model", "Agent", "ai_languageModel"],
      ],
    );
    assert.ok(
      diagnostics(result).includes("binary_expression_effects_unresolved"),
    );
    assert.ok(
      diagnostics(result).includes("ai_binary_prompt_content_unverified"),
    );
  }
  const mapping = map("={{ effect($json) }}");
  const result = run([source(), mapping, agent(), model()], agentEdges());
  assert.equal(
    binaryInputProvenance(
      result.context,
      result.context.nodeByName.get("Agent"),
    ).state,
    "unknown",
  );
});
