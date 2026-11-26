import assert from "node:assert/strict";
import test from "node:test";
import { assessBytes } from "../dist/assessment-engine.js";
import {
  buildServiceReport,
  serviceReportSchema,
} from "../dist/service-report.js";
import { presentInspection, inspectionSchema } from "../dist/inspection.js";
import { createContext } from "../dist/static-context.js";
import { analyzeFlow } from "../dist/static-flow.js";
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

const mockTools = async () => ({
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

const assess = (workflow) =>
  assessBytes(Buffer.from(JSON.stringify(workflow)), {
    collectTools: mockTools,
    now: "2026-11-26T00:00:00.000Z",
  });

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
