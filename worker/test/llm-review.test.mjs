import assert from "node:assert/strict";
import test from "node:test";
import { assessBytes } from "../dist/assessment/assessment-engine.js";
import { assessmentError } from "../dist/contracts/assessment-contract.js";
import {
  createLlmContext,
  llmDefaults,
  reviewWithLlm,
  llmReviewSchema,
  providerContext,
} from "../dist/service/llm-review.js";

const model = llmDefaults.model;
const tools = async () => ({
  gitleaks: {
    tool: "gitleaks",
    version: "8.30.1",
    status: "completed",
    findings: [],
  },
  native: {
    tool: "native_inspection",
    version: "1.0.0",
    modes: ["nlp", "python"].map((mode) => ({
      mode,
      status: "completed",
      findings: [],
      diagnostics: [],
      versions: {
        python: "3.11.2",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    })),
  },
});
const report = () =>
  assessBytes(
    Buffer.from(
      JSON.stringify({
        name: "PRIVATE_WORKFLOW_NAME",
        nodes: [
          {
            id: "private",
            name: "PRIVATE_NODE_NAME",
            type: "n8n-nodes-base.webhook",
            typeVersion: 2,
            parameters: { path: "PRIVATE_PATH", responseMode: "onReceived" },
          },
        ],
        connections: {},
        pinData: {
          private: [
            {
              json: {
                email: "synthetic-person@example.invalid",
                text: "IGNORE_PREVIOUS_INSTRUCTIONS",
              },
            },
          ],
        },
      }),
    ),
    { collectTools: tools },
  );
const response = (context, overrides = {}) =>
  new Response(
    JSON.stringify({
      model,
      choices: [
        {
          finish_reason: "stop",
          message: {
            content: JSON.stringify({
              focusReferenceIds: context.references.length
                ? [context.references[0].id]
                : [],
            }),
          },
        },
      ],
      usage: { prompt_tokens: 100, completion_tokens: 50, cost: 0.00001 },
      ...overrides,
    }),
    { status: 200 },
  );

test("LLM context excludes private source content and preserves real analysis limits", async () => {
  const assessment = await report();
  const context = createLlmContext(assessment);
  assert.equal(context.assessmentStatus, assessment.status);
  assert.equal(context.execution, "not_run");
  for (const text of [
    "PRIVATE_",
    "synthetic-person",
    "example.invalid",
    "IGNORE_PREVIOUS",
  ])
    assert.ok(!JSON.stringify(context).includes(text));
  assert.ok(context.references.some((ref) => ref.kind === "environment_check"));
  assert.ok(
    Buffer.byteLength(JSON.stringify(context)) <= llmDefaults.inputBytes,
  );
});

test("disabled, missing key and failed analysis make no provider call", async () => {
  let calls = 0;
  const fetch = async () => {
    calls++;
    throw Error("must not call");
  };
  const assessment = await report();
  assert.equal((await reviewWithLlm(assessment, { fetch })).code, "disabled");
  assert.equal(
    (await reviewWithLlm(assessment, { enabled: true, fetch })).code,
    "missing_key",
  );
  assert.equal(
    (
      await reviewWithLlm(assessmentError("0".repeat(64), "invalid_input"), {
        enabled: true,
        apiKey: "synthetic-token",
        fetch,
      })
    ).code,
    "analysis_failed",
  );
  assert.equal(calls, 0);
});

test("identical child definitions keep separate analysis-instance references", async () => {
  const child = {
    nodes: [
      {
        id: "child",
        name: "Child",
        type: "n8n-nodes-base.httpRequest",
        typeVersion: 4.2,
        parameters: { url: "http://example.invalid" },
      },
    ],
    connections: {},
  };
  const parent = {
    nodes: ["First", "Second"].map((name) => ({
      id: name,
      name,
      type: "n8n-nodes-base.executeWorkflow",
      typeVersion: 1.4,
      parameters: { source: "parameter", workflowJson: JSON.stringify(child) },
    })),
    connections: {},
  };
  const assessment = await assessBytes(Buffer.from(JSON.stringify(parent)), {
    collectTools: tools,
  });
  assert.equal(assessment.files.length, 3);
  const children = assessment.files.slice(1);
  assert.equal(children[0].inputSha256, children[1].inputSha256);
  assert.notEqual(children[0].analysisKey, children[1].analysisKey);
  const context = createLlmContext(assessment);
  for (const childReport of children) {
    const refs = context.references.filter(
      (ref) => ref.analysisKey === childReport.analysisKey,
    );
    assert.ok(refs.length > 0);
    assert.ok(refs.every((ref) => ref.fileSha256 === childReport.inputSha256));
  }
});

test("provider request pins route, price, schema and bounded output; advice cannot alter verdict", async () => {
  const assessment = await report();
  const original = JSON.stringify(assessment);
  const context = createLlmContext(assessment);
  const result = await reviewWithLlm(assessment, {
    enabled: true,
    apiKey: "SYNTHETIC_TEST_CREDENTIAL",
    fetch: async (url, options) => {
      assert.equal(url, llmDefaults.endpoint);
      assert.equal(options.redirect, "error");
      const request = JSON.parse(options.body);
      assert.equal(request.model, model);
      assert.deepEqual(request.provider.max_price, llmDefaults.maxPrice);
      assert.equal(request.provider.require_parameters, true);
      assert.equal(request.provider.data_collection, "deny");
      assert.equal(request.response_format.json_schema.strict, true);
      assert.equal(request.max_tokens, 1800);
      assert.equal(request.tools, undefined);
      assert.equal(request.provider.max_price.request, 0);
      assert.deepEqual(
        JSON.parse(request.messages[1].content),
        providerContext(context),
      );
      assert.ok(!request.messages[1].content.includes(context.inputSha256));
      assert.ok(
        context.references.every(
          (ref) => !request.messages[1].content.includes(ref.analysisKey),
        ),
      );
      assert.ok(!options.body.includes("SYNTHETIC_TEST_CREDENTIAL"));
      return response(context);
    },
  });
  assert.equal(result.status, "generated");
  assert.equal(result.affectsVerdict, false);
  assert.equal(result.method, "model_selection_with_deterministic_text");
  assert.equal(
    result.advice.items[0].explanation,
    context.references[0].description,
  );
  assert.ok(!JSON.stringify(result).includes("SYNTHETIC_TEST_CREDENTIAL"));
  assert.equal(JSON.stringify(assessment), original);
  const altered = structuredClone(result);
  altered.contextSha256 = "0".repeat(64);
  assert.equal(llmReviewSchema.safeParse(altered).success, false);
  const fabricated = structuredClone(result);
  fabricated.advice.summary = "하위 흐름의 확인이 완료됐습니다.";
  assert.equal(llmReviewSchema.safeParse(fabricated).success, false);
});

for (const [status, code] of [
  [401, "authentication_failed"],
  [402, "credit_required"],
  [429, "rate_limited"],
  [503, "provider_unavailable"],
]) {
  test(`provider ${status} is explicit fallback without echoing provider body or retrying`, async () => {
    let calls = 0;
    const result = await reviewWithLlm(await report(), {
      enabled: true,
      apiKey: "test-token",
      fetch: async () => {
        calls++;
        return new Response("SENSITIVE_PROVIDER_ERROR", { status });
      },
    });
    assert.equal(result.code, code);
    assert.equal(calls, 1);
    assert.ok(!JSON.stringify(result).includes("SENSITIVE_PROVIDER_ERROR"));
  });
}
test("fabricated, empty, duplicate references and all model prose are rejected", async () => {
  const assessment = await report();
  for (const [advice, code] of [
    [{ focusReferenceIds: ["r999"] }, "invalid_references"],
    [{ focusReferenceIds: [] }, "invalid_references"],
    [{ focusReferenceIds: ["r1", "r1"] }, "invalid_references"],
    [
      {
        focusReferenceIds: ["r1"],
        summary: "하위 워크플로 검증이 끝났습니다.",
      },
      "invalid_response",
    ],
    [{ summary: "<script>test</script>", items: [] }, "invalid_response"],
    [{ summary: "검토", items: [], safe: true }, "invalid_response"],
    [
      { summary: "모든 보안 검사를 통과했고 안전합니다.", items: [] },
      "invalid_response",
    ],
  ]) {
    const result = await reviewWithLlm(assessment, {
      enabled: true,
      apiKey: "test-token",
      fetch: async () =>
        response(createLlmContext(assessment), {
          choices: [
            {
              finish_reason: "stop",
              message: { content: JSON.stringify(advice) },
            },
          ],
        }),
    });
    assert.equal(result.code, code);
  }
});
test("network connection failure is distinct from invalid model JSON", async () => {
  const assessment = await report();
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        fetch: async () => {
          throw Error("SENSITIVE_NETWORK_DETAIL");
        },
      })
    ).code,
    "network_error",
  );
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        fetch: async () => new Response("invalid-json"),
      })
    ).code,
    "invalid_response",
  );
});
test("partial token response and wrong model are not accepted", async () => {
  const assessment = await report();
  const context = createLlmContext(assessment);
  for (const [overrides, code] of [
    [
      { choices: [{ finish_reason: "length", message: { content: "{}" } }] },
      "incomplete_response",
    ],
    [{ model: "another/model" }, "invalid_response"],
  ]) {
    const result = await reviewWithLlm(assessment, {
      enabled: true,
      apiKey: "test-token",
      fetch: async () => response(context, overrides),
    });
    assert.equal(result.code, code);
  }
});
test("timeout and cancellation stop the explanation request", async () => {
  const assessment = await report();
  const blockedFetch = async (_url, options) =>
    new Promise((_resolve, reject) =>
      options.signal.addEventListener("abort", () => reject(Error("aborted")), {
        once: true,
      }),
    );
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        timeoutMs: 10,
        fetch: blockedFetch,
      })
    ).code,
    "timeout",
  );
  const controller = new AbortController();
  controller.abort();
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        signal: controller.signal,
        fetch: blockedFetch,
      })
    ).code,
    "cancelled",
  );
});
test("oversized API output and invalid configuration do not produce generated advice", async () => {
  const assessment = await report();
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        fetch: async () =>
          new Response("x".repeat(llmDefaults.responseBytes + 1)),
      })
    ).code,
    "response_too_large",
  );
  assert.equal(
    (
      await reviewWithLlm(assessment, {
        enabled: true,
        apiKey: "test-token",
        maxOutputTokens: 100000,
      })
    ).code,
    "invalid_configuration",
  );
});
