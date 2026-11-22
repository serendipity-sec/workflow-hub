import { staticReportSchema } from "./static-contract.js";
import type { StaticLocation, RuleResult } from "./static-contract.js";

function scopeKey(location: StaticLocation): string {
  const field =
    location.nodeKey === null
      ? location.pointer
      : location.pointer.replace(/^\/nodes\/\d+(?=\/|$)/, "");
  return JSON.stringify([location.nodeKey, field]);
}

function checked(
  rule: RuleResult,
  location: StaticLocation,
  allRules: RuleResult[],
): boolean {
  const nodeStillPresent =
    location.nodeKey === null ||
    allRules.some((item) =>
      item.coverage.some(
        (scope) => scope.location.nodeKey === location.nodeKey,
      ),
    );
  if (!nodeStillPresent) return false;
  return rule.coverage.some(
    (coverage) =>
      coverage.status === "checked" &&
      ((coverage.location.nodeKey === null &&
        coverage.location.pointer === "") ||
        scopeKey(coverage.location) === scopeKey(location) ||
        (location.nodeKey !== null &&
          coverage.location.nodeKey === location.nodeKey &&
          location.pointer
            .replace(/^\/nodes\/\d+(?=\/|$)/, "")
            .startsWith(
              coverage.location.pointer.replace(/^\/nodes\/\d+(?=\/|$)/, "") +
                "/",
            ))),
  );
}

/** Structural observations only: absence is never labeled a proven repair. */
export function compareStatic(beforeValue: unknown, afterValue: unknown) {
  const before = staticReportSchema.safeParse(beforeValue);
  const after = staticReportSchema.safeParse(afterValue);
  if (
    !before.success ||
    !after.success ||
    before.data.status === "error" ||
    after.data.status === "error"
  ) {
    return {
      basis: "incompatible_or_failed",
      rechecks: [],
      newFindings: [],
    } as const;
  }
  const baseline = before.data;
  const candidate = after.data;
  const beforeIds = new Set(
    baseline.rules.flatMap((rule) => rule.findings.map(({ id }) => id)),
  );
  const rechecks = baseline.rules.flatMap((rule) =>
    rule.findings.map((finding) => {
      const next = candidate.rules.find(({ ruleId }) => ruleId === rule.ruleId);
      const comparable =
        next !== undefined && next.profileVersion === rule.profileVersion;
      const present =
        comparable && next.findings.some(({ id }) => id === finding.id);
      const observedScope =
        comparable &&
        checked(rule, finding.location, baseline.rules) &&
        checked(next, finding.location, candidate.rules);
      return {
        id: finding.id,
        status: present
          ? "persisting"
          : observedScope
            ? "not_observed"
            : "inconclusive",
      };
    }),
  );
  const newFindings = candidate.rules.flatMap((rule) =>
    rule.findings
      .filter(({ id }) => !beforeIds.has(id))
      .map((finding) => {
        const earlier = baseline.rules.find(
          ({ ruleId }) => ruleId === rule.ruleId,
        );
        return {
          id: finding.id,
          status:
            earlier?.profileVersion === rule.profileVersion &&
            checked(earlier, finding.location, baseline.rules) &&
            checked(rule, finding.location, candidate.rules)
              ? "newly_observed"
              : "inconclusive",
        };
      }),
  );
  return {
    basis:
      baseline.inputSha256 === candidate.inputSha256
        ? "same_input"
        : "same_report_contract",
    rechecks,
    newFindings,
  };
}
