import { createContext, isObject } from "../workflow/static-context.js";
import type { Context } from "../workflow/static-context.js";
import { locationFor } from "../contracts/static-contract.js";
import { sha256 } from "../runtime/worker-io.js";
import { assessmentLimits } from "../contracts/assessment-contract.js";
import type { SubworkflowLink } from "../contracts/assessment-contract.js";
import type { AssessmentEvidence } from "./assessment-evidence.js";

export interface AssessmentInput {
  bytes: Buffer;
  context: Context;
  inputSha256: string;
  analysisKey: string;
  parentAnalysisKey: string | null;
  caller: SubworkflowLink["caller"] | null;
  depth: number;
  ancestors: string[];
}

/** No database, URL, file path or expression is resolved by the worker. */
export function planSubworkflows(
  bytes: Buffer,
  evidence?: AssessmentEvidence,
): { inputs: AssessmentInput[]; links: SubworkflowLink[] } {
  const inputSha256 = sha256(bytes);
  const root: AssessmentInput = {
    bytes,
    context: createContext(bytes),
    inputSha256,
    analysisKey: sha256(Buffer.from(`root:${inputSha256}`)),
    parentAnalysisKey: null,
    caller: null,
    depth: 0,
    ancestors: [inputSha256],
  };
  const inputs = [root];
  const links: SubworkflowLink[] = [];
  for (const parent of inputs) {
    for (const node of parent.context.nodes.filter(
      (node) => node.type === "n8n-nodes-base.executeWorkflow",
    )) {
      const link: SubworkflowLink = {
        parentAnalysisKey: parent.analysisKey,
        caller: locationFor(node, "/parameters"),
        source: "unavailable",
        status: "unresolved",
        childAnalysisKey: null,
        childInputSha256: null,
        codes: [],
      };
      links.push(link);
      if (node.disabled) {
        link.status = "disabled";
        link.codes = ["disabled_subworkflow_not_analyzed"];
        continue;
      }
      if (![1, 1.1, 1.2, 1.3, 1.4].includes(node.typeVersion)) {
        link.codes = ["subworkflow_profile_unsupported"];
        continue;
      }
      const source = node.parameters.source ?? "database";
      let content: string | undefined;
      if (source === "parameter") {
        const inline = node.parameters.workflowJson;
        if (typeof inline === "string" && !inline.trimStart().startsWith("=")) {
          content = inline;
          link.source = "inline_definition";
        } else link.codes = ["subworkflow_inline_expression_unresolved"];
      } else if (source === "database") {
        const locator = node.parameters.workflowId;
        const reference = isObject(locator) ? locator.value : locator;
        if (
          typeof reference !== "string" ||
          !reference ||
          reference.startsWith("=")
        )
          link.codes = ["subworkflow_reference_dynamic_or_missing"];
        else {
          const matches =
            evidence?.subworkflows.filter(
              (child) =>
                child.parentInputSha256 === parent.inputSha256 &&
                child.callerNodeKey === node.key &&
                child.reference === reference,
            ) ?? [];
          if (matches.length === 1) {
            content = matches[0]!.content;
            link.source = "supplied_definition";
          } else
            link.codes = [
              matches.length
                ? "subworkflow_definition_ambiguous"
                : "subworkflow_definition_not_supplied",
            ];
        }
      } else link.codes = ["subworkflow_external_source_not_fetched"];
      if (content === undefined) continue;
      const childBytes = Buffer.from(content);
      const childHash = sha256(childBytes);
      link.childInputSha256 = childHash;
      if (parent.ancestors.includes(childHash)) {
        link.status = "cycle";
        link.codes = ["subworkflow_cycle_unresolved"];
        continue;
      }
      if (
        inputs.length >= assessmentLimits.children + 1 ||
        parent.depth >= assessmentLimits.depth
      ) {
        link.status = "limit";
        link.codes = ["subworkflow_analysis_limit"];
        continue;
      }
      let context: Context;
      try {
        context = createContext(childBytes);
      } catch {
        link.status = "invalid";
        link.codes = ["subworkflow_definition_invalid"];
        continue;
      }
      const analysisKey = sha256(
        Buffer.from(JSON.stringify([parent.analysisKey, node.key, childHash])),
      );
      inputs.push({
        bytes: childBytes,
        context,
        inputSha256: childHash,
        analysisKey,
        parentAnalysisKey: parent.analysisKey,
        caller: link.caller,
        depth: parent.depth + 1,
        ancestors: [...parent.ancestors, childHash],
      });
      link.status = "definition_analyzed";
      link.childAnalysisKey = analysisKey;
      link.codes = [
        "subworkflow_definition_static_only",
        "subworkflow_argument_and_return_flow_unresolved",
      ];
    }
  }
  return { inputs, links };
}

/** Node-scoped root assertions do not automatically describe nodes in another file. */
export function evidenceForInput(
  input: AssessmentInput,
  evidence: AssessmentEvidence | undefined,
): AssessmentEvidence | undefined {
  if (!evidence || input.depth === 0) return evidence;
  return {
    ...evidence,
    inputSha256: input.inputSha256,
    provenance: undefined,
    classifications: [],
    aiApprovals: [],
    publicationReview:
      evidence.publicationReview?.inputSha256 === input.inputSha256
        ? evidence.publicationReview
        : undefined,
    runtime: evidence.runtime
      ? {
          ...evidence.runtime,
          credentialScopes: [],
          upstreamAuthentication: [],
        }
      : undefined,
    packages: evidence.packages.map((entry) => ({ ...entry, nodeKeys: [] })),
    policy: evidence.policy
      ? {
          ...evidence.policy,
          egress: [],
          exceptions: evidence.policy.exceptions.filter(
            (entry) => entry.inputSha256 === input.inputSha256,
          ),
        }
      : undefined,
  };
}
