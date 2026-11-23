import assert from "node:assert/strict";
import test from "node:test";
import { analyzeAiFlow } from "../dist/ai-flow.js";
import { createContext } from "../dist/static-context.js";
import { ruleResultSchema } from "../dist/static-contract.js";
import { buildValueFlow } from "../dist/value-flow.js";

const prefix = "@n8n/n8n-nodes-langchain.";
function inspect(example, parameters = {}, type = "toolCode", version = 1.3) {
  const node = (name, type, typeVersion, parameters) => ({
    id: name,
    name,
    type: prefix + type,
    typeVersion,
    parameters,
  });
  const context = createContext(
    Buffer.from(
      JSON.stringify({
        nodes: [
          node("Agent", "agent", 2.2, {
            promptType: "define",
            text: "public question",
            options: { passthroughBinaryImages: false },
          }),
          node("Model", "lmChatOpenAi", 1.2, { options: {} }),
          node("Tool", type, version, {
            description: "public tool",
            specifyInputSchema: true,
            schemaType: "fromJson",
            jsonSchemaExample: example,
            ...parameters,
          }),
        ],
        connections: {
          Model: {
            ai_languageModel: [
              [{ node: "Agent", type: "ai_languageModel", index: 0 }],
            ],
          },
          Tool: { ai_tool: [[{ node: "Agent", type: "ai_tool", index: 0 }]] },
        },
      }),
    ),
  );
  const rules = analyzeAiFlow(context, buildValueFlow(context)).map((rule) =>
    ruleResultSchema.parse(rule),
  );
  const prompt = rules.find(({ ruleId }) => ruleId === "N8N_AI_PROMPT_DATA");
  return {
    rules,
    diagnostics: rules.flatMap((rule) =>
      rule.diagnostics.map(({ code }) => code),
    ),
    codes: prompt.findings.flatMap(({ evidence }) =>
      evidence.map(({ code }) => code),
    ),
  };
}
const unresolved = "ai_tool_example_derived_schema_content_unverified";

test("fixed primitive examples derive schema content for Code and legacy Workflow tools", () => {
  for (const type of ["toolCode", "toolWorkflow"]) {
    for (const version of [1, 1.1, 1.2, 1.3]) {
      for (const example of [
        '{"loan_amount":250000,"annual_rate":6.5,"term_years":30}',
        { active: true, absent: null, label: "public" },
        "{}",
      ]) {
        const result = inspect(example, {}, type, version);
        assert.ok(!result.diagnostics.includes(unresolved));
        assert.ok(
          result.codes.includes("ai_prompt_to_model_unknown_component"),
        );
      }
    }
  }
});

test("literal example personal and secret values are not claimed as transmitted schema data", () => {
  const result = inspect(
    '{"email":"synthetic@example.invalid","password":"fake-example-secret"}',
  );
  assert.ok(!result.diagnostics.includes(unresolved));
  assert.ok(!result.codes.includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(!result.codes.includes("ai_prompt_to_model_secret_candidate"));
  assert.ok(
    !JSON.stringify(result.rules).includes("synthetic@example.invalid"),
  );
  assert.ok(!JSON.stringify(result.rules).includes("fake-example-secret"));
});

test("literal property names can carry personal data but cannot execute expressions", () => {
  const personal = inspect('{"synthetic@example.invalid":"public"}');
  assert.ok(!personal.diagnostics.includes(unresolved));
  assert.ok(personal.codes.includes("ai_prompt_to_model_pii_candidate"));
  assert.ok(
    !JSON.stringify(personal.rules).includes("synthetic@example.invalid"),
  );
  const expressionText = inspect('{"={{ $env.SECRET }}":"public"}');
  assert.ok(!expressionText.diagnostics.includes(unresolved));
  assert.ok(
    !expressionText.codes.includes("ai_prompt_to_model_secret_candidate"),
  );
});

test("unsafe, deep, collection, nonfinite, excessive and malformed examples stay unverified", () => {
  for (const example of [
    '{"__proto__":{"polluted":true}}',
    '{"constructor":"ignored"}',
    '{"prototype":"ignored"}',
    '{"toString":"ignored"}',
    '{"nested":{"value":"public"}}',
    '{"items":["public"]}',
    '[{"value":"public"}]',
    '"public"',
    '{"number":1e999}',
    '{"value":',
    JSON.stringify(
      Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`k${i}`, i])),
    ),
    JSON.stringify({ ["x".repeat(129)]: "public" }),
    JSON.stringify({ value: "x".repeat(8192) }),
    "={{ $json.example }}",
  ]) {
    const result = inspect(example);
    assert.ok(result.diagnostics.includes(unresolved));
    assert.ok(result.codes.includes("ai_prompt_to_model_unknown_component"));
  }
  assert.equal({}.polluted, undefined);
});

test("manual, disabled and uncertain selectors retain their existing dispatch boundaries", () => {
  const manual = inspect('{"ignored":"private@example.invalid"}', {
    schemaType: "manual",
    inputSchema: '{"type":"string","description":"synthetic@example.invalid"}',
  });
  assert.ok(!manual.diagnostics.includes(unresolved));
  assert.ok(manual.codes.includes("ai_prompt_to_model_pii_candidate"));
  const disabled = inspect('{"private@example.invalid":"public"}', {
    specifyInputSchema: false,
  });
  assert.ok(!disabled.codes.includes("ai_prompt_to_model_pii_candidate"));
  const uncertain = inspect('{"value":1}', { schemaType: "={{ $json.mode }}" });
  assert.ok(
    uncertain.diagnostics.includes("ai_tool_schema_selector_unresolved"),
  );
  assert.ok(uncertain.codes.includes("ai_prompt_to_model_unknown_component"));
});
