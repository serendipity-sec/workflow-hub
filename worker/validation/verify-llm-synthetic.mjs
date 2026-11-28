import assert from "node:assert/strict";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { assessBytes } from "../dist/assessment/assessment-engine.js";
import {
  createLlmContext,
  reviewWithLlm,
  llmDefaults,
  providerContext,
} from "../dist/service/llm-review.js";

// Entirely invented input. This exercises the API adapter, NOT actual scanner
// tools, real workflow quality, external services or workflow execution.
const synthetic = Buffer.from(
  JSON.stringify({
    nodes: [
      {
        id: "synthetic_start",
        name: "SyntheticStart",
        type: "n8n-nodes-base.webhook",
        typeVersion: 2,
        parameters: {},
      },
      {
        id: "synthetic_send",
        name: "SyntheticSend",
        type: "n8n-nodes-base.httpRequest",
        typeVersion: 4.2,
        parameters: {
          url: "https://example.invalid",
          method: "POST",
          sendBody: true,
          bodyParameters: {
            parameters: [
              { name: "message", value: "={{ $json.body.message }}" },
            ],
          },
        },
      },
    ],
    connections: {
      SyntheticStart: {
        main: [[{ node: "SyntheticSend", type: "main", index: 0 }]],
      },
    },
  }),
);
const mockedTools = async () => ({
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
const assessment = await assessBytes(synthetic, { collectTools: mockedTools });
const context = createLlmContext(assessment);
assert.ok(!JSON.stringify(context).includes("example.invalid"));
assert.ok(!JSON.stringify(context).includes("SyntheticStart"));
const destination = resolve(
  process.argv[2] ?? "evidence-local/llm-synthetic.json",
);
await mkdir(dirname(destination), { recursive: true });
if (process.argv.includes("--prepare-only")) {
  await writeFile(
    destination,
    JSON.stringify(
      {
        source: "invented_synthetic_fixture_only",
        destination: llmDefaults.endpoint,
        context: providerContext(context),
      },
      null,
      2,
    ) + "\n",
  );
  console.log(
    JSON.stringify({
      prepared: true,
      path: destination,
      contextBytes: Buffer.byteLength(JSON.stringify(providerContext(context))),
      privateSourceSent: false,
    }),
  );
} else {
  let transport = null;
  const result = await reviewWithLlm(assessment, {
    enabled: true,
    apiKey: process.env.OPENROUTER_API_KEY,
    model: process.env.WORKER_LLM_MODEL,
    maxOutputTokens: Number(process.env.WORKER_LLM_MAX_OUTPUT_TOKENS ?? 1800),
    fetch: async (url, options) => {
      const response = await fetch(url, options);
      if (!response.ok) {
        transport = {
          httpStatus: response.status,
        };
      }
      return response;
    },
  });
  const receipt = {
    schemaVersion: "1.0.0",
    scope: "live_api_synthetic_explanation_only",
    source: "invented_synthetic_fixture_only",
    nativeTools: "mocked_for_adapter_test",
    workflowExecution: "not_run",
    actualTeamApiIntegration: "not_run",
    actualWorkflowDataSent: false,
    maxPriceUsdPerMillionTokens: llmDefaults.maxPrice,
    result,
  };
  await writeFile(destination, JSON.stringify(receipt, null, 2) + "\n", {
    mode: 0o600,
  });
  console.log(
    JSON.stringify({
      status: result.status,
      code: result.status === "unavailable" ? result.code : null,
      model: result.model,
      usage: result.status === "generated" ? result.usage : null,
      transport,
    }),
  );
  if (result.status !== "generated") process.exitCode = 1;
}
