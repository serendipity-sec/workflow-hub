import validator from "validator";
import { stableId } from "./static-contract.js";
import type {
  Category,
  Finding,
  RuleResult,
  StaticLocation,
} from "./static-contract.js";
import { isObject } from "./static-context.js";
import type { Context, ScalarField } from "./static-context.js";
import type { GitleaksResult } from "./gitleaks.js";

const rootLocation: StaticLocation = { nodeKey: null, pointer: "" };
const findingLimit = 32;

function result(ruleId: string, category: Category): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.0.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}

function addDiagnostic(rule: RuleResult, code: string): void {
  const id = stableId(rule.ruleId, rootLocation, code);
  if (!rule.diagnostics.some((entry) => entry.id === id))
    rule.diagnostics.push({ id, code, location: rootLocation });
}

function addCandidate(
  rule: RuleResult,
  field: ScalarField,
  code: string,
): void {
  const id = stableId(rule.ruleId, field.location, code);
  if (rule.findings.some((finding) => finding.id === id)) return;
  if (rule.findings.length >= findingLimit) {
    addDiagnostic(rule, "finding_limit");
    return;
  }
  const finding: Finding = {
    id,
    ruleId: rule.ruleId,
    category: rule.category,
    severity: rule.category === "secrets" ? "high" : "medium",
    claim: "candidate",
    location: field.location,
    evidence: [{ code, location: field.location }],
    assumptions: ["static_definition_only", "candidate_not_verified"],
    remediation: {
      code:
        rule.category === "secrets"
          ? "remove_literal_secret"
          : "remove_unnecessary_personal_data",
      checks: [
        "review_original_field_privately",
        "preserve_required_behavior",
        "rescan_changed_file",
      ],
    },
  };
  rule.findings.push(finding);
}

function finish(rule: RuleResult): RuleResult {
  rule.coverage.push({
    location: rootLocation,
    status: rule.diagnostics.length ? "partial" : "checked",
    findingIds: rule.findings.map(({ id }) => id),
    diagnosticIds: rule.diagnostics.map(({ id }) => id),
  });
  return rule;
}

function objectAt(context: Context, pointer: string): unknown {
  let value: unknown = context.document;
  for (const part of pointer.split("/").slice(1)) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(value) && /^\d+$/.test(key)) value = value[Number(key)];
    else if (isObject(value) && Object.hasOwn(value, key)) value = value[key];
    else return undefined;
  }
  return value;
}

function literalCredential(context: Context, field: ScalarField): boolean {
  if (
    field.kind !== "value" ||
    !field.value.trim() ||
    /^\s*=\s*\{\{\s*\$(?:env|json|credentials)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\s*\}\}\s*$/.test(
      field.value,
    )
  )
    return false;
  if (/^\/nodes\/\d+\/credentials(?:\/|$)/.test(field.pointer)) return false;
  const parts = field.pointer.split("/");
  let key = (parts.at(-1) ?? "").replace(/~1/g, "/").replace(/~0/g, "~");
  if (key === "value") {
    const parent = objectAt(context, parts.slice(0, -1).join("/"));
    if (isObject(parent) && typeof parent.name === "string") key = parent.name;
  }
  return /^(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|authorization|x-api-key)$/i.test(
    key,
  );
}

/** Does not execute or decode embedded programs; reports only declared candidate types. */
export function analyzeContent(
  context: Context,
  gitleaks?: GitleaksResult,
): RuleResult[] {
  const secrets = result("CONTENT_SECRET_CANDIDATE", "secrets");
  const pii = result("CONTENT_PII_CANDIDATE", "pii");
  const fields = new Map(context.fields.map((field) => [field.index, field]));
  if (!gitleaks || gitleaks.status !== "completed") {
    addDiagnostic(secrets, gitleaks?.reason ?? "tool_unavailable");
  } else if (
    gitleaks.tool !== "gitleaks" ||
    gitleaks.version !== "8.30.1" ||
    gitleaks.findings.length > 4096
  ) {
    addDiagnostic(secrets, "tool_invalid_report");
  } else {
    for (const match of gitleaks.findings) {
      const field = fields.get(match.fieldIndex);
      if (!field || !/^[a-z0-9][a-z0-9_-]{0,127}$/.test(match.ruleId)) {
        addDiagnostic(secrets, "tool_invalid_report");
        continue;
      }
      // Upstream text and exact secret matches never enter the result contract.
      addCandidate(secrets, field, "gitleaks_secret_candidate");
    }
  }
  for (const field of context.fields) {
    if (literalCredential(context, field))
      addCandidate(secrets, field, "literal_credential_field");
    let candidates = 0;
    const scan = (
      pattern: RegExp,
      valid: (value: string) => boolean,
      code: string,
    ) => {
      for (const match of field.value.matchAll(pattern)) {
        if (++candidates > 128) {
          addDiagnostic(pii, "candidate_limit");
          break;
        }
        if (valid(match[0])) addCandidate(pii, field, code);
      }
    };
    scan(
      /[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}/g,
      (value) => validator.isEmail(value),
      "email_candidate",
    );
    scan(
      /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
      (value) => validator.isCreditCard(value.replace(/[ -]/g, "")),
      "payment_card_candidate",
    );
    scan(
      /(?<!\d)(?:\+82[ -]?1[016789]|01[016789])(?:[ -]?\d){7,8}(?!\d)/g,
      (value) => validator.isMobilePhone(value.replace(/[ -]/g, ""), "ko-KR"),
      "korean_mobile_candidate",
    );
  }
  return [finish(secrets), finish(pii)];
}
