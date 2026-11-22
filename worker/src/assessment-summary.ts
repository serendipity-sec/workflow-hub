import { z } from "zod";
import { limits } from "./contract.js";
import type { Context } from "./static-context.js";
import type { Finding } from "./static-contract.js";

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const kinds = [
  "webhook",
  "schedule",
  "manual",
  "email",
  "http",
  "database",
  "condition",
  "mapping",
  "merge",
  "code",
  "command",
  "ssh",
  "file",
  "message",
  "document",
  "ai",
  "subworkflow",
  "response",
  "note",
  "unknown",
] as const;
const roles = [
  "trigger",
  "read",
  "transform",
  "branch",
  "write",
  "send",
  "execute",
  "respond",
  "annotation",
  "unknown",
] as const;
const nodeSchema = z.strictObject({
  nodeKey: hash,
  pointer: z.string().regex(/^\/nodes\/(0|[1-9][0-9]*)$/),
  identity: z.enum(["explicit_id", "name_derived"]),
  disabled: z.boolean(),
  kind: z.enum(kinds),
  roles: z.array(z.enum(roles)).min(1).max(4),
});
const channels = [
  "main",
  "ai_agent",
  "ai_chain",
  "ai_document",
  "ai_embedding",
  "ai_languageModel",
  "ai_memory",
  "ai_outputParser",
  "ai_retriever",
  "ai_reranker",
  "ai_textSplitter",
  "ai_tool",
  "ai_vectorStore",
] as const;
export const functionSummarySchema = z
  .strictObject({
    summaryVersion: z.literal("1.0.0"),
    meaning: z.literal("declared_structure_only"),
    nodes: z.array(nodeSchema).max(limits.nodes),
    edges: z
      .array(
        z.strictObject({
          from: hash,
          to: hash,
          channel: z.enum(channels),
          output: z.int().min(0),
          input: z.int().min(0),
        }),
      )
      .max(limits.edges),
    limitations: z
      .array(
        z.enum([
          "business_purpose_not_verified",
          "node_roles_are_capabilities",
          "unknown_node_capabilities",
          "name_derived_identity",
          "inactive_nodes_included",
        ]),
      )
      .min(2)
      .max(5),
  })
  .refine((summary) => {
    const keys = new Set(summary.nodes.map((node) => node.nodeKey));
    return (
      keys.size === summary.nodes.length &&
      new Set(summary.nodes.map((node) => node.pointer)).size ===
        summary.nodes.length &&
      summary.edges.every((edge) => keys.has(edge.from) && keys.has(edge.to))
    );
  });
export type FunctionSummary = z.infer<typeof functionSummarySchema>;
type Role = (typeof roles)[number];
type Kind = (typeof kinds)[number];

// Only known fixed codes are exported. Workflow titles, node names, arbitrary
// package names, parameter values and recipients never enter this summary.
const profiles: Record<string, [Kind, Role[]]> = {
  webhook: ["webhook", ["trigger"]],
  scheduleTrigger: ["schedule", ["trigger"]],
  cron: ["schedule", ["trigger"]],
  manualTrigger: ["manual", ["trigger"]],
  gmailTrigger: ["email", ["trigger", "read"]],
  emailReadImap: ["email", ["trigger", "read"]],
  gmail: ["email", ["read", "send"]],
  emailSend: ["email", ["send"]],
  httpRequest: ["http", ["read", "send"]],
  postgres: ["database", ["read", "write"]],
  mySql: ["database", ["read", "write"]],
  microsoftSql: ["database", ["read", "write"]],
  if: ["condition", ["branch"]],
  switch: ["condition", ["branch"]],
  set: ["mapping", ["transform"]],
  noOp: ["mapping", ["transform"]],
  merge: ["merge", ["transform"]],
  code: ["code", ["transform", "execute"]],
  function: ["code", ["transform", "execute"]],
  functionItem: ["code", ["transform", "execute"]],
  executeCommand: ["command", ["execute"]],
  ssh: ["ssh", ["execute", "read", "write"]],
  readWriteFile: ["file", ["read", "write"]],
  slack: ["message", ["send"]],
  telegram: ["message", ["send"]],
  telegramTrigger: ["message", ["trigger", "read"]],
  whatsApp: ["message", ["send"]],
  notion: ["document", ["read", "write"]],
  googleDocs: ["document", ["read", "write"]],
  googleSheets: ["document", ["read", "write"]],
  googleGemini: ["ai", ["send", "transform"]],
  executeWorkflow: ["subworkflow", ["execute"]],
  executeWorkflowTrigger: ["subworkflow", ["trigger"]],
  respondToWebhook: ["response", ["respond"]],
  stickyNote: ["note", ["annotation"]],
};

export function summarizeFunction(context: Context): FunctionSummary {
  const aiTypes = new Set([
    "agent",
    "chainLlm",
    "lmChatGoogleGemini",
    "lmChatOpenAi",
    "lmChatAnthropic",
    "outputParserStructured",
    "toolCode",
    "toolWorkflow",
    "googleGemini",
  ]);
  const nodes = context.nodes.map((node) => {
    const profile = node.type.startsWith("n8n-nodes-base.")
      ? profiles[node.type.slice("n8n-nodes-base.".length)]
      : node.type.startsWith("@n8n/n8n-nodes-langchain.") &&
          aiTypes.has(node.type.slice("@n8n/n8n-nodes-langchain.".length))
        ? (["ai", ["transform", "send"]] as [Kind, Role[]])
        : undefined;
    return {
      nodeKey: node.key,
      pointer: node.pointer,
      identity: node.identity,
      disabled: node.disabled,
      kind: profile?.[0] ?? "unknown",
      roles: profile?.[1] ?? ["unknown" as const],
    };
  });
  const limitations: FunctionSummary["limitations"] = [
    "business_purpose_not_verified",
    "node_roles_are_capabilities",
  ];
  if (nodes.some((node) => node.kind === "unknown"))
    limitations.push("unknown_node_capabilities");
  if (nodes.some((node) => node.identity === "name_derived"))
    limitations.push("name_derived_identity");
  if (nodes.some((node) => node.disabled))
    limitations.push("inactive_nodes_included");
  return functionSummarySchema.parse({
    summaryVersion: "1.0.0",
    meaning: "declared_structure_only",
    nodes,
    edges: [
      ...context.edges.map((edge) => ({ ...edge, channel: "main" })),
      ...context.unsupportedEdges,
    ],
    limitations,
  });
}

export const findingPresentationSchema = z.strictObject({
  observations: z.array(hash).max(8192),
  reviewCandidates: z.array(hash).max(8192),
  vulnerabilityCount: z.literal("not_established"),
});
export function presentFindings(findings: Finding[]) {
  return {
    observations: findings
      .filter((finding) => finding.severity === "info")
      .map((finding) => finding.id),
    reviewCandidates: findings
      .filter((finding) => finding.severity !== "info")
      .map((finding) => finding.id),
    vulnerabilityCount: "not_established" as const,
  };
}
