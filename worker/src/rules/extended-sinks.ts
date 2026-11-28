import { parse } from "acorn";
import type {
  AssessmentEvidence,
  DataClass,
  SinkKind,
} from "../assessment/assessment-evidence.js";
import {
  assessDestination,
  canonicalEvidenceField,
} from "../assessment/assessment-evidence.js";
import type { NormalizedNode } from "../workflow/n8n.js";
import { isObject, stringSelector } from "../workflow/static-context.js";
import type { Context } from "../workflow/static-context.js";
import { locationFor, stableId } from "../contracts/static-contract.js";
import type {
  Finding,
  RuleResult,
  StaticLocation,
} from "../contracts/static-contract.js";
import type { AbstractValue, ValueFlow } from "../workflow/value-flow.js";
import { originIncludesField } from "../workflow/value-flow.js";

const base = "n8n-nodes-base.";
const root: StaticLocation = { nodeKey: null, pointer: "/nodes" };
const httpVersions = [3, 4, 4.1, 4.2, 4.3, 4.4, 4.5];
const responseVersions = [1, 1.1, 1.2, 1.3, 1.4, 1.5];
type Field = {
  pointer: string;
  value: unknown;
  name?: string;
  conditional?: boolean;
  literalData?: boolean;
};
type Profile = {
  sink: SinkKind;
  recipients: Field[];
  content: Field[];
  diagnostics: string[];
  opaqueDestination?: boolean;
  readOnly?: boolean;
  opaqueContent?: boolean;
  responseCode?: string;
};

function makeRule(ruleId: string, category: "egress" | "output"): RuleResult {
  return {
    ruleId,
    category,
    profileVersion: "1.5.0",
    coverage: [],
    findings: [],
    diagnostics: [],
  };
}

class Scope {
  readonly findings = new Set<string>();
  readonly diagnostics = new Set<string>();
  constructor(
    readonly rule: RuleResult,
    readonly node: NormalizedNode,
  ) {}
  diagnostic(code: string): void {
    let location = locationFor(this.node, "/parameters");
    if (this.rule.diagnostics.length >= 128) {
      code = "diagnostic_limit";
      location = root;
    }
    const id = stableId(this.rule.ruleId, location, code);
    if (!this.rule.diagnostics.some((item) => item.id === id))
      this.rule.diagnostics.push({ id, code, location });
    this.diagnostics.add(id);
  }
  finding(
    code: string,
    pointer: string,
    claim: Finding["claim"] = "configuration",
    value?: AbstractValue,
    severity: Finding["severity"] = "info",
    policyCodes: string[] = [],
  ): void {
    const location = locationFor(this.node, pointer);
    const id = stableId(this.rule.ruleId, location, code);
    const existing = this.rule.findings.find((item) => item.id === id);
    if (existing) {
      // One node-level policy finding may cover To, CC and BCC. Preserve every
      // fixed denial reason instead of losing the later destination result.
      for (const policyCode of policyCodes)
        if (
          [
            "destination_not_allowlisted",
            "destination_denylisted",
            "data_class_not_allowed",
          ].includes(policyCode) &&
          existing.evidence.length < 16 &&
          !existing.evidence.some((item) => item.code === policyCode)
        )
          existing.evidence.push({ code: policyCode, location });
      this.findings.add(id);
      return;
    }
    if (this.rule.findings.length >= 128) {
      this.diagnostic("finding_limit");
      return;
    }
    const evidence: Finding["evidence"] = [{ code, location }];
    for (const policyCode of policyCodes)
      if (
        [
          "destination_not_allowlisted",
          "destination_denylisted",
          "data_class_not_allowed",
        ].includes(policyCode)
      )
        evidence.push({ code: policyCode, location });
    for (const origin of value?.origins ?? []) {
      // Field paths contain user-controlled keys and remain private to the flow engine.
      if (evidence.length >= 16) break;
      const source = this.context?.nodeByKey.get(origin.nodeKey);
      if (
        source &&
        !evidence.some((item) => item.location.nodeKey === source.key)
      )
        evidence.push({
          code:
            origin.kind === "database"
              ? "database_result_origin"
              : "data_origin",
          location: locationFor(source, "/parameters"),
        });
    }
    for (const path of value?.paths ?? [])
      for (const key of path) {
        if (evidence.length >= 16) break;
        const hop = this.context?.nodeByKey.get(key);
        if (hop && !evidence.some((item) => item.location.nodeKey === hop.key))
          evidence.push({
            code: "data_flow_hop",
            location: locationFor(hop, "/parameters"),
          });
      }
    this.rule.findings.push({
      id,
      ruleId: this.rule.ruleId,
      category: this.rule.category,
      severity,
      claim,
      location,
      evidence,
      assumptions: [
        "static_definition_only",
        "runtime_values_unverified",
        "transfer_not_proof_of_leak",
      ],
      remediation: {
        code: "review_destination_and_minimize_data",
        checks: [
          "verify_recipient_and_purpose",
          "select_required_fields",
          "rescan_changed_file",
        ],
      },
    });
    this.findings.add(id);
  }
  context?: Context;
  finish(): void {
    this.rule.coverage.push({
      location: locationFor(this.node, "/parameters"),
      status: this.diagnostics.size ? "partial" : "checked",
      findingIds: [...this.findings],
      diagnosticIds: [...this.diagnostics],
    });
  }
}

function add(
  profile: Profile,
  list: "recipients" | "content",
  pointer: string,
  value: unknown,
  required = false,
  name?: string,
): void {
  if (value !== undefined && value !== "")
    profile[list].push({ pointer: "/parameters/" + pointer, value, name });
  else if (required) profile.diagnostics.push("required_send_field_missing");
}
function options(value: unknown, profile: Profile): Record<string, unknown> {
  if (value === undefined) return {};
  if (isObject(value)) return value;
  profile.diagnostics.push("send_options_unresolved");
  profile.opaqueDestination = true;
  return {};
}
function unsupported(profile: Profile, code: string): Profile {
  profile.diagnostics.push(code);
  profile.opaqueDestination = true;
  return profile;
}

/** n8n resolves structured parameter VALUES recursively, unlike JS literals.
 * Keep arbitrary property names internal and never interpret JSON inside a
 * plain string as another expression language. */
function parameterLeaves(fields: Field[]): {
  fields: Field[];
  limited: boolean;
} {
  const pending = fields
    .slice()
    .reverse()
    .map((field) => ({ field, depth: 0, declaredName: field.name }));
  const result: Field[] = [];
  let visits = 0;
  let limited = false;
  while (pending.length && visits++ < 2048 && result.length < 512) {
    const { field, depth, declaredName } = pending.pop()!;
    const value = field.value;
    if (field.literalData) {
      result.push(field);
      continue;
    }
    if (value !== null && typeof value === "object") {
      if (depth >= 16) {
        limited = true;
        continue;
      }
      const entries = Object.entries(value);
      if (!entries.length) result.push(field);
      else
        for (const [key, child] of entries.slice(0, 512).reverse())
          pending.push({
            field: {
              ...field,
              value: child,
              // User-controlled column/property names never become output paths.
              pointer: field.pointer + (Array.isArray(value) ? "/" + key : ""),
              name: declaredName ?? (Array.isArray(value) ? field.name : key),
            },
            depth: depth + 1,
            declaredName,
          });
      if (entries.length > 512) limited = true;
    } else result.push(field);
  }
  return { fields: result, limited: limited || pending.length > 0 };
}

function compositeLocator(
  profile: Profile,
  first: string,
  second: string,
  p: Record<string, unknown>,
): void {
  const fixed: string[] = [];
  for (const key of [first, second]) {
    const value = p[key];
    const selected = isObject(value) ? value.value : value;
    if (
      isObject(value) &&
      ["id", "list"].includes(stringSelector(value.mode)) &&
      ["string", "number"].includes(typeof selected) &&
      String(selected).trim() &&
      !String(selected).trim().startsWith("=") &&
      !String(selected).includes("/")
    )
      fixed.push(String(selected).trim());
    else {
      add(
        profile,
        "recipients",
        key + (isObject(value) ? "/value" : ""),
        selected,
        true,
      );
      profile.opaqueDestination = true;
      profile.diagnostics.push("destination_locator_unresolved");
    }
  }
  if (fixed.length === 2) add(profile, "recipients", first, fixed.join("/"));
}

function mappedColumns(
  profile: Profile,
  p: Record<string, unknown>,
  sheetAppend: boolean,
): void {
  if (!isObject(p.columns)) {
    profile.diagnostics.push("resource_mapping_shape_unresolved");
    profile.opaqueContent = true;
    if (typeof p.columns === "string")
      add(profile, "content", "columns", p.columns);
    return;
  }
  const mode = p.columns.mappingMode ?? "defineBelow";
  if (mode === "defineBelow") {
    if (isObject(p.columns.value))
      add(profile, "content", "columns/value", p.columns.value);
    else {
      profile.diagnostics.push("resource_mapping_values_unresolved");
      profile.opaqueContent = true;
      if (typeof p.columns.value === "string")
        add(profile, "content", "columns/value", p.columns.value);
    }
    if (sheetAppend) {
      // Official append switches to autoMapInputData if the remote sheet is
      // empty. A declared schema is not evidence that remote headers exist.
      profile.content.push({
        pointer: "/parameters/columns",
        value: "={{ $json }}",
        conditional: true,
      });
      profile.diagnostics.push("sheet_empty_header_fallback_possible");
      profile.opaqueContent = true;
    }
  } else if (mode === "autoMapInputData") {
    profile.content.push({
      pointer: "/parameters/columns",
      value: "={{ $json }}",
      conditional: true,
    });
    profile.diagnostics.push("automatic_mapping_selection_unverified");
    profile.opaqueContent = true;
  } else {
    profile.diagnostics.push("resource_mapping_mode_unresolved");
    profile.opaqueContent = true;
  }
}

function tableProfile(node: NormalizedNode): Profile | undefined {
  const kind =
    node.type === base + "airtable"
      ? "airtable"
      : node.type === base + "googleSheets"
        ? "google_sheets"
        : undefined;
  if (!kind) return;
  const p = node.parameters;
  const profile: Profile = {
    sink: kind,
    recipients: [],
    content: [],
    diagnostics: ["destination_access_unverified"],
  };
  const versions =
    kind === "airtable"
      ? [2, 2.1, 2.2]
      : [4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7];
  if (!versions.includes(node.typeVersion))
    return unsupported(profile, "unsupported_node_version");
  const operation = p.operation ?? (kind === "airtable" ? "get" : "read");
  if (kind === "airtable") {
    if (
      (p.resource ?? "record") !== "record" ||
      !["create", "update", "upsert", "get", "search", "deleteRecord"].includes(
        stringSelector(operation),
      )
    )
      return unsupported(profile, "unsupported_send_operation");
    compositeLocator(profile, "base", "table", p);
    profile.readOnly = operation === "get" || operation === "search";
    profile.responseCode =
      profile.readOnly && node.typeVersion < 2.2
        ? "airtable_flattened_response_profile"
        : "airtable_record_response_profile";
    profile.diagnostics.push(
      profile.readOnly
        ? "read_response_classification_unverified"
        : "response_data_sensitivity_unverified",
    );
    const opts = options(p.options, profile);
    if (["create", "update", "upsert"].includes(stringSelector(operation))) {
      const match = isObject(p.columns) ? p.columns.matchingColumns : undefined;
      if (
        operation === "update" &&
        isObject(p.columns) &&
        (p.columns.mappingMode ?? "defineBelow") === "defineBelow" &&
        isObject(p.columns.value) &&
        Array.isArray(match) &&
        match.every((key) => typeof key === "string" && !key.startsWith("=")) &&
        !match.includes("id")
      ) {
        // Non-id matching is done against fetched records locally; n8n removes
        // those match fields from the outgoing PATCH, unlike upsert.
        mappedColumns(
          profile,
          {
            ...p,
            columns: {
              ...p.columns,
              value: Object.fromEntries(
                Object.entries(p.columns.value).filter(
                  ([key]) => !match.includes(key),
                ),
              ),
            },
          },
          false,
        );
      } else mappedColumns(profile, p, false);
      if (operation !== "create")
        profile.diagnostics.push("record_match_selection_unverified");
      if (opts.typecast === true)
        profile.diagnostics.push("resource_value_coercion_unverified");
      if (
        Object.keys(opts).some(
          (key) =>
            !["typecast", "ignoreFields", "updateAllMatches"].includes(key),
        )
      ) {
        profile.diagnostics.push("connector_options_unresolved");
        profile.opaqueContent = true;
      }
    } else if (operation === "search") {
      add(profile, "content", "filterByFormula", p.filterByFormula);
      add(profile, "content", "options/fields", opts.fields);
      add(
        profile,
        "content",
        "sort/property",
        isObject(p.sort) ? p.sort.property : undefined,
      );
      add(
        profile,
        "content",
        "options/view/value",
        isObject(opts.view) ? opts.view.value : undefined,
      );
      if (p.returnAll === false)
        add(profile, "content", "limit", p.limit ?? 100);
      if (
        Object.keys(opts).some(
          (key) => !["fields", "view", "downloadFields"].includes(key),
        )
      )
        profile.diagnostics.push("connector_options_unresolved");
    } else add(profile, "content", "id", p.id, true);
    if (profile.readOnly && opts.downloadFields)
      profile.diagnostics.push("binary_response_content_unavailable");
    return profile;
  }
  if (
    (p.resource ?? "sheet") !== "sheet" ||
    !["append", "update", "appendOrUpdate", "read"].includes(
      stringSelector(operation),
    )
  )
    return unsupported(profile, "unsupported_send_operation");
  compositeLocator(profile, "documentId", "sheetName", p);
  const opts = options(p.options, profile);
  if (operation === "read") {
    profile.readOnly = true;
    profile.responseCode = "sheet_rows_response_profile";
    profile.diagnostics.push("read_response_classification_unverified");
    // Sheets filters are applied to fetched rows locally. Do not manufacture
    // an outbound transmission of lookupValue from that local filter.
    if (p.filtersUI !== undefined)
      profile.diagnostics.push("response_selection_unverified");
    add(
      profile,
      "content",
      "options/dataLocationOnSheet",
      opts.dataLocationOnSheet,
    );
  } else {
    mappedColumns(profile, p, operation === "append");
    profile.responseCode = "sheet_mapped_or_input_response_profile";
    profile.diagnostics.push("sheet_headers_runtime_unverified");
    if (operation !== "append")
      profile.diagnostics.push("record_match_selection_unverified");
    if (
      node.typeVersion >= 4.4 &&
      (!isObject(p.columns) ||
        !Array.isArray(p.columns.schema) ||
        !p.columns.schema.length)
    )
      profile.diagnostics.push("resource_mapping_schema_unresolved");
  }
  const known = [
    "cellFormat",
    "handlingExtraData",
    "useAppend",
    "locationDefine",
    "valueRenderMode",
    "dataLocationOnSheet",
    "outputFormatting",
    "returnFirstMatch",
    "returnAllMatches",
  ];
  if (Object.keys(opts).some((key) => !known.includes(key))) {
    profile.diagnostics.push("connector_options_unresolved");
    profile.opaqueContent = true;
  }
  return profile;
}

function telegramKeyboard(
  profile: Profile,
  kind: string,
  value: unknown,
): void {
  if (value === undefined) return; // n8n fixedCollection default: {}.
  if (!isObject(value)) {
    if (typeof value === "string") add(profile, "content", kind, value);
    profile.diagnostics.push("message_keyboard_shape_unresolved");
    return;
  }
  if (value.rows === undefined) return;
  if (!Array.isArray(value.rows)) {
    profile.diagnostics.push("message_keyboard_shape_unresolved");
    return;
  }
  let fields = 0;
  const field = (path: string, item: unknown): boolean => {
    if (++fields > 256) {
      profile.diagnostics.push("message_keyboard_limit");
      return false;
    }
    if (item !== undefined && typeof item === "object")
      profile.diagnostics.push("message_keyboard_shape_unresolved");
    else add(profile, "content", path, item);
    return true;
  };
  if (value.rows.length > 128)
    profile.diagnostics.push("message_keyboard_limit");
  for (const [rowIndex, row] of value.rows.slice(0, 128).entries()) {
    if (
      isObject(row) &&
      (row.row === undefined ||
        (isObject(row.row) && row.row.buttons === undefined))
    )
      continue; // n8n skips rows with no buttons.
    if (
      !isObject(row) ||
      !isObject(row.row) ||
      !Array.isArray(row.row.buttons)
    ) {
      profile.diagnostics.push("message_keyboard_shape_unresolved");
      continue;
    }
    if (row.row.buttons.length > 128)
      profile.diagnostics.push("message_keyboard_limit");
    for (const [buttonIndex, button] of row.row.buttons
      .slice(0, 128)
      .entries()) {
      if (!isObject(button)) {
        profile.diagnostics.push("message_keyboard_shape_unresolved");
        continue;
      }
      const path = `${kind}/rows/${rowIndex}/row/buttons/${buttonIndex}`;
      if (!field(path + "/text", button.text)) return;
      if (button.additionalFields === undefined) continue;
      if (!isObject(button.additionalFields)) {
        profile.diagnostics.push("message_keyboard_shape_unresolved");
        continue;
      }
      // n8n merges these fields into the transmitted button. Inspect each
      // scalar separately so nested n8n expressions are not treated as literals.
      // Keep both values conservatively if malformed input overrides text.
      for (const [key, item] of Object.entries(button.additionalFields)) {
        if (key === "web_app" && isObject(item)) {
          if (!field(path + "/additionalFields/web_app/url", item.url)) return;
          if (Object.keys(item).some((name) => name !== "url"))
            profile.diagnostics.push("message_keyboard_shape_unresolved");
        } else {
          const known = [
            "text",
            "callback_data",
            "pay",
            "switch_inline_query_current_chat",
            "switch_inline_query",
            "url",
            "request_contact",
            "request_location",
          ].includes(key);
          if (!known)
            profile.diagnostics.push("message_keyboard_shape_unresolved");
          // Untrusted property names may contain secrets. Use their container.
          const pointer = path + "/additionalFields" + (known ? "/" + key : "");
          if (!field(pointer, item)) return;
        }
      }
    }
  }
}

function locator(profile: Profile, key: string, value: unknown): void {
  if (isObject(value)) {
    add(profile, "recipients", key + "/value", value.value, true);
    if (
      !(key === "pageId" ? ["id"] : ["id", "list"]).includes(
        stringSelector(value.mode),
      )
    ) {
      profile.opaqueDestination = true;
      profile.diagnostics.push("destination_locator_unresolved");
    }
  } else {
    add(profile, "recipients", key, value, true);
    profile.opaqueDestination = true;
    profile.diagnostics.push("destination_locator_unresolved");
  }
}

function notionProperties(profile: Profile, value: unknown): void {
  if (value === undefined) return;
  if (!isObject(value) || !Array.isArray(value.propertyValues)) {
    profile.diagnostics.push("notion_properties_unresolved");
    return;
  }
  const selected: Record<string, string[]> = {
    title: ["title"],
    number: ["numberValue"],
    url: ["urlValue"],
    checkbox: ["checkboxValue"],
    relation: ["relationValue"],
    multi_select: ["multiSelectValue"],
    email: ["emailValue"],
    people: ["peopleValue"],
    phone_number: ["phoneValue"],
    select: ["selectValue"],
    status: ["statusValue"],
    files: ["fileUrls"],
  };
  for (const [index, item] of value.propertyValues.entries()) {
    if (
      !isObject(item) ||
      typeof item.key !== "string" ||
      item.key.startsWith("=")
    ) {
      profile.diagnostics.push("notion_property_type_unresolved");
      continue;
    }
    // Official mapProperties derives type from the final pipe in key, not item.type.
    const type = item.key.slice(item.key.lastIndexOf("|") + 1);
    let keys = Object.hasOwn(selected, type) ? selected[type] : undefined;
    if (type === "rich_text") {
      if (item.richText === undefined || item.richText === false)
        keys = ["textContent"];
      else if (item.richText === true) keys = ["text"];
      else profile.diagnostics.push("notion_property_type_unresolved");
    } else if (type === "date") {
      if (item.range === undefined || item.range === false) keys = ["date"];
      else if (item.range === true) keys = ["dateStart", "dateEnd"];
    }
    if (!keys) {
      profile.diagnostics.push("notion_property_type_unresolved");
      continue;
    }
    for (const key of keys)
      add(
        profile,
        "content",
        `propertiesUi/propertyValues/${index}/${key}`,
        item[key],
      );
    if (type === "files")
      profile.diagnostics.push("remote_attachment_content_unavailable");
  }
}

function notionFilters(profile: Profile, value: unknown): void {
  if (!isObject(value) || !Array.isArray(value.conditions)) {
    if (value === undefined || (isObject(value) && !Object.keys(value).length))
      return;
    profile.diagnostics.push("notion_filter_selection_partially_analyzed");
    profile.opaqueContent = true;
    return;
  }
  const keys: Record<string, string> = {
    title: "titleValue",
    rich_text: "richTextValue",
    text: "textValue",
    email: "emailValue",
    url: "urlValue",
    phone_number: "phoneNumberValue",
    number: "numberValue",
    checkbox: "checkboxValue",
    boolean: "booleanValue",
    select: "selectValue",
    multi_select: "multiSelectValue",
    status: "statusValue",
    people: "peopleValue",
    relation: "relationValue",
    date: "date",
    created_time: "createdTimeValue",
    last_edited_time: "lastEditedTime",
    created_by: "createdByValue",
    last_edited_by: "lastEditedByValue",
  };
  for (const item of value.conditions.slice(0, 128)) {
    const pointer = "filters/conditions";
    if (!isObject(item)) {
      profile.diagnostics.push("notion_filter_selection_partially_analyzed");
      profile.opaqueContent = true;
      continue;
    }
    add(profile, "content", pointer, item.key);
    add(profile, "content", pointer, item.condition);
    const type =
      typeof item.key === "string" && !item.key.startsWith("=")
        ? item.key.split("|").at(-1)
        : undefined;
    if (["is_empty", "is_not_empty"].includes(stringSelector(item.condition)))
      continue;
    if (
      type !== "date" &&
      item.type !== "formula" &&
      [
        "past_week",
        "past_month",
        "past_year",
        "next_week",
        "next_month",
        "next_year",
      ].includes(stringSelector(item.condition))
    )
      continue;
    const selected = item.type === "formula" ? item.returnType : type;
    const formulaKeys: Record<string, string> = {
      string: "stringValue",
      number: "numberValue",
      checkbox: "checkboxValue",
      date: "dateValue",
    };
    const selection = item.type === "formula" ? formulaKeys : keys;
    const key =
      typeof selected === "string" && Object.hasOwn(selection, selected)
        ? selection[selected]
        : undefined;
    if (
      !key ||
      typeof item.condition !== "string" ||
      item.condition.startsWith("=")
    ) {
      add(profile, "content", pointer, item);
      const field = profile.content.at(-1);
      if (field) field.conditional = true;
      profile.diagnostics.push("notion_filter_selection_partially_analyzed");
      profile.opaqueContent = true;
    } else {
      add(profile, "content", pointer, item[key]);
      if (
        selected === "date" ||
        selected === "created_time" ||
        selected === "last_edited_time"
      )
        profile.diagnostics.push("notion_date_conversion_unverified");
    }
  }
  if (value.conditions.length > 128) {
    profile.diagnostics.push("parameter_value_analysis_limit");
    profile.opaqueContent = true;
  }
}

/** Data JSON only; callers must select official JSON-parsing fields and must
 * preserve each diagnostic as an unknown remainder alongside any bounded value. */
export function parseLiteralJsonData(value: string): {
  parsed: boolean;
  value?: unknown;
  diagnostics: string[];
} {
  if (value.startsWith("=")) {
    return {
      parsed: false,
      value,
      diagnostics: ["model_json_data_structure_unverified"],
    };
  }
  if (value.length > 65536) {
    return { parsed: false, diagnostics: ["model_json_data_limit"] };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return {
      parsed: false,
      value,
      diagnostics: ["model_json_data_parse_unverified"],
    };
  }
  let visits = 0;
  let limited = false;
  const bounded = (item: unknown, depth: number): unknown => {
    if (++visits > 2048 || depth > 16) {
      limited = true;
      return null;
    }
    if (!isObject(item) && !Array.isArray(item)) return item;
    const entries = Object.entries(item);
    if (entries.length > 512) limited = true;
    const selected: [string, unknown][] = [];
    for (const [key, child] of entries.slice(0, 512)) {
      if (visits >= 2048) {
        limited = true;
        break;
      }
      selected.push([key, bounded(child, depth + 1)]);
    }
    return Array.isArray(item)
      ? selected.map(([, child]) => child)
      : Object.fromEntries(selected);
  };
  const literal = bounded(parsed, 0);
  return {
    parsed: true,
    value: literal,
    diagnostics: limited ? ["model_json_data_limit"] : [],
  };
}

export function resolveLiteralData(
  flow: ValueFlow,
  nodeKey: string,
  value: unknown,
): AbstractValue {
  return typeof value === "string"
    ? flow.resolveExpression(nodeKey, JSON.stringify(value))
    : flow.resolve(nodeKey, value);
}

function jsonDataField(
  profile: Profile,
  pointer: string,
  value: unknown,
): void {
  if (value === undefined) {
    profile.diagnostics.push("model_json_data_parse_unverified");
    profile.opaqueContent = true;
    return;
  }
  if (typeof value !== "string") {
    add(profile, "content", pointer, value);
    return;
  }
  const parsed = parseLiteralJsonData(value);
  if (parsed.diagnostics.length) {
    profile.diagnostics.push(...parsed.diagnostics);
    profile.opaqueContent = true;
  }
  if (!parsed.parsed) {
    if (parsed.value !== undefined)
      add(profile, "content", pointer, parsed.value);
    return;
  }
  profile.content.push({
    pointer: "/parameters/" + pointer,
    value: parsed.value,
    literalData: true,
  });
}

function fieldValue(
  flow: ValueFlow,
  nodeKey: string,
  field: Field,
): AbstractValue {
  return field.literalData
    ? resolveLiteralData(flow, nodeKey, field.value)
    : flow.resolve(nodeKey, field.value, { fieldName: field.name });
}

function openAiResponseProfile(node: NormalizedNode): Profile {
  const p = node.parameters;
  const profile: Profile = {
    sink: "openai",
    recipients: [],
    content: [],
    diagnostics: [],
    opaqueDestination: true,
  };
  const gap = (code: string) => {
    profile.diagnostics.push(code);
    profile.opaqueContent = true;
  };
  if (![2, 2.1, 2.2, 2.3].includes(node.typeVersion))
    return unsupported(profile, "unsupported_node_version");
  if (
    (p.resource ?? "text") !== "text" ||
    (p.operation ?? "response") !== "response"
  )
    return unsupported(profile, "unsupported_send_operation");
  profile.responseCode = "openai_responses_output_profile";
  profile.diagnostics.push(
    "provider_endpoint_from_credentials_unverified",
    "model_processing_and_retention_unverified",
    "model_invocation_and_output_unverified",
  );
  add(
    profile,
    "content",
    "modelId",
    isObject(p.modelId) ? p.modelId.value : p.modelId,
    true,
  );
  const messages = isObject(p.responses) ? p.responses.values : undefined;
  if (!Array.isArray(messages)) gap("model_messages_unresolved");
  else {
    if (
      !messages.some(
        (item) =>
          isObject(item) &&
          (item.type ?? "text") === "text" &&
          typeof item.content === "string" &&
          item.content.trim(),
      )
    )
      gap("model_required_text_prompt_unresolved");
    if (messages.length > 128) gap("parameter_value_analysis_limit");
    for (const [index, item] of messages.slice(0, 128).entries()) {
      if (!isObject(item)) {
        gap("model_messages_unresolved");
        continue;
      }
      const path = `responses/values/${index}/`;
      add(profile, "content", path + "role", item.role);
      const type = item.type ?? "text";
      if (type === "text")
        add(profile, "content", path + "content", item.content, true);
      else if (type === "image" || type === "file") {
        const selected =
          item[type === "image" ? "imageType" : "fileType"] ?? "url";
        if (type === "image")
          add(profile, "content", path + "imageDetail", item.imageDetail);
        if (selected === "url")
          add(
            profile,
            "content",
            path + (type === "image" ? "imageUrl" : "fileUrl"),
            item[type === "image" ? "imageUrl" : "fileUrl"],
            true,
          );
        else if (selected === "fileId")
          add(profile, "content", path + "fileId", item.fileId, true);
        else if (selected === "base64") {
          if (type === "file")
            add(profile, "content", path + "fileName", item.fileName);
          gap("binary_payload_unavailable");
        } else gap("model_message_media_selection_unresolved");
        if (selected === "url" || selected === "fileId")
          gap("remote_attachment_content_unavailable");
      } else gap("model_message_format_unresolved");
    }
  }
  const opts = options(p.options, profile);
  const scalar = [
    "instructions",
    "maxTokens",
    "previousResponseId",
    "promptCacheKey",
    "safetyIdentifier",
    "serviceTier",
    "temperature",
    "topP",
    "topLogprobs",
    "maxToolCalls",
    "parallelToolCalls",
    "store",
    "conversationId",
  ];
  for (const key of scalar)
    add(profile, "content", "options/" + key, opts[key]);
  if (opts.metadata) jsonDataField(profile, "options/metadata", opts.metadata);
  if (Array.isArray(opts.include))
    add(profile, "content", "options/include", opts.include);
  else if (opts.include !== undefined)
    gap("model_options_selection_unresolved");
  for (const key of ["previousResponseId", "conversationId"])
    if (opts[key]) gap("model_remote_history_content_unverified");
  const group = (
    name: string,
    nested: string,
  ): Record<string, unknown> | undefined => {
    if (opts[name] === undefined) return;
    const value = isObject(opts[name]) ? opts[name][nested] : undefined;
    if (!isObject(value)) {
      gap("model_options_selection_unresolved");
      return;
    }
    return value;
  };
  const prompt = group("promptConfig", "promptOptions");
  if (prompt) {
    for (const key of ["promptId", "version"])
      add(
        profile,
        "content",
        "options/promptConfig/promptOptions/" + key,
        prompt[key],
      );
    if (prompt.variables)
      jsonDataField(
        profile,
        "options/promptConfig/promptOptions/variables",
        prompt.variables,
      );
    gap("model_remote_prompt_content_unverified");
  }
  const reasoning = group("reasoning", "reasoningOptions");
  if (reasoning) {
    add(
      profile,
      "content",
      "options/reasoning/reasoningOptions/effort",
      reasoning.effort,
    );
    if (reasoning.summary !== "none")
      add(
        profile,
        "content",
        "options/reasoning/reasoningOptions/summary",
        reasoning.summary,
      );
  }
  const format = group("textFormat", "textOptions");
  if (format) {
    add(
      profile,
      "content",
      "options/textFormat/textOptions/verbosity",
      format.verbosity,
    );
    if (format.type === "json_schema") {
      for (const key of ["name"])
        add(
          profile,
          "content",
          "options/textFormat/textOptions/" + key,
          format[key],
        );
      jsonDataField(
        profile,
        "options/textFormat/textOptions/schema",
        format.schema,
      );
    } else if (
      format.type !== undefined &&
      !["text", "json_object"].includes(stringSelector(format.type))
    )
      gap("model_output_format_unresolved");
  }
  const background = group("backgroundMode", "values");
  if (background)
    add(
      profile,
      "content",
      "options/backgroundMode/values/enabled",
      background.enabled,
    );
  if (opts.truncation !== undefined && typeof opts.truncation !== "boolean")
    profile.diagnostics.push("model_request_control_unresolved");
  const known = new Set([
    ...scalar,
    "metadata",
    "include",
    "promptConfig",
    "reasoning",
    "textFormat",
    "backgroundMode",
    "truncation",
    "maxToolsIterations",
  ]);
  if (Object.keys(opts).some((key) => !known.has(key)))
    gap("connector_options_unresolved");
  const builtins = options(p.builtInTools, profile);
  for (const name of ["webSearch", "fileSearch"]) {
    if (!builtins[name]) continue;
    const value = builtins[name];
    if (!isObject(value)) gap("model_provider_tools_selection_unresolved");
    else
      for (const key of name === "webSearch"
        ? ["searchContextSize", "allowedDomains", "country", "city", "region"]
        : ["vectorStoreIds", "filters", "maxResults"])
        if (
          name === "fileSearch" &&
          ["vectorStoreIds", "filters"].includes(key)
        ) {
          if (value[key] !== undefined && (key !== "filters" || value[key]))
            jsonDataField(profile, `builtInTools/${name}/${key}`, value[key]);
        } else
          add(profile, "content", `builtInTools/${name}/${key}`, value[key]);
    gap("model_provider_tools_unverified");
  }
  if (builtins.codeInterpreter) gap("model_provider_tools_unverified");
  if (
    Object.keys(builtins).some(
      (key) => !["webSearch", "fileSearch", "codeInterpreter"].includes(key),
    )
  )
    gap("model_provider_tools_selection_unresolved");
  return profile;
}

function additionalProfile(node: NormalizedNode): Profile | undefined {
  if (node.type === "@n8n/n8n-nodes-langchain.openAi")
    return openAiResponseProfile(node);
  const p = node.parameters;
  const kinds: Record<string, SinkKind> = {
    "n8n-nodes-base.notion": "notion",
    "n8n-nodes-base.googleDocs": "google_docs",
    "n8n-nodes-base.whatsApp": "whatsapp",
    "@n8n/n8n-nodes-langchain.googleGemini": "gemini",
  };
  const kind = Object.hasOwn(kinds, node.type) ? kinds[node.type] : undefined;
  if (!kind) return;
  const profile: Profile = {
    sink: kind,
    recipients: [],
    content: [],
    diagnostics: [],
  };
  if (kind === "notion") {
    if (![2, 2.1, 2.2].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    const resource = p.resource ?? "page";
    const operation = p.operation ?? "create";
    if (
      (resource === "databasePage" &&
        ["get", "getAll"].includes(stringSelector(operation))) ||
      (resource === "database" && operation === "get")
    ) {
      const identifier =
        resource === "database" || operation === "getAll"
          ? "databaseId"
          : "pageId";
      locator(profile, identifier, p[identifier]);
      profile.readOnly = true;
      profile.responseCode = "notion_remote_properties_response_profile";
      profile.diagnostics.push(
        "read_response_classification_unverified",
        "destination_access_unverified",
      );
      const opts = options(p.options, profile);
      if (operation === "getAll") {
        if (p.filterType === "json")
          add(profile, "content", "filterJson", p.filterJson);
        else if (p.filterType === "manual") {
          notionFilters(profile, p.filters);
        } else if (p.filterType !== undefined && p.filterType !== "none") {
          profile.diagnostics.push(
            "notion_filter_selection_partially_analyzed",
          );
          profile.opaqueContent = true;
        }
        add(
          profile,
          "content",
          "options/sort/sortValue",
          isObject(opts.sort) ? opts.sort.sortValue : undefined,
        );
      }
      if (opts.downloadFiles === true)
        profile.diagnostics.push("binary_response_content_unavailable");
      return profile;
    }
    if (!(
      (resource === "databasePage" &&
        ["create", "update"].includes(stringSelector(operation))) ||
      (resource === "page" && operation === "create")
    ))
      return unsupported(profile, "unsupported_send_operation");
    locator(
      profile,
      resource === "databasePage" && operation === "create"
        ? "databaseId"
        : "pageId",
      resource === "databasePage" && operation === "create"
        ? p.databaseId
        : p.pageId,
    );
    if (operation === "create") add(profile, "content", "title", p.title);
    if (resource === "databasePage") notionProperties(profile, p.propertiesUi);
    if (operation === "create" && p.blockUi !== undefined) {
      add(profile, "content", "blockUi", p.blockUi);
      profile.diagnostics.push("notion_block_selection_partially_analyzed");
    }
    const opts = options(p.options, profile);
    add(profile, "content", "options/icon", opts.icon);
    if (opts.iconType === "file")
      profile.diagnostics.push("remote_attachment_content_unavailable");
    if (Object.keys(opts).some((key) => !["icon", "iconType"].includes(key)))
      profile.diagnostics.push("connector_options_unresolved");
    profile.diagnostics.push("destination_access_unverified");
    return profile;
  }
  if (kind === "google_docs") {
    if (![1, 2].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    const operation = p.operation ?? "create";
    if (
      (p.resource ?? "document") !== "document" ||
      !["create", "update", "get"].includes(stringSelector(operation))
    )
      return unsupported(profile, "unsupported_send_operation");
    if (operation === "get") {
      add(profile, "recipients", "documentURL", p.documentURL, true);
      profile.readOnly = true;
      profile.responseCode = "google_document_response_profile";
      profile.diagnostics.push("read_response_classification_unverified");
    } else if (operation === "create") {
      add(profile, "recipients", "folderId", p.folderId || null);
      add(profile, "content", "title", p.title, true);
    } else {
      add(profile, "recipients", "documentURL", p.documentURL, true);
      if (!isObject(p.actionsUi) || !Array.isArray(p.actionsUi.actionFields))
        profile.diagnostics.push("document_actions_unresolved");
      else
        for (const [index, action] of p.actionsUi.actionFields.entries()) {
          if (
            !isObject(action) ||
            (action.object ?? "text") !== "text" ||
            !["insert", "replaceAll"].includes(stringSelector(action.action))
          ) {
            profile.diagnostics.push("document_action_unsupported");
            continue;
          }
          add(
            profile,
            "content",
            `actionsUi/actionFields/${index}/text`,
            action.text,
            true,
          );
          if (action.action === "replaceAll")
            add(
              profile,
              "content",
              `actionsUi/actionFields/${index}/replaceText`,
              action.replaceText,
              true,
            );
        }
      if (
        p.updateFields !== undefined &&
        (!isObject(p.updateFields) || Object.keys(p.updateFields).length)
      )
        profile.diagnostics.push("document_write_controls_unverified");
    }
    profile.diagnostics.push("destination_access_unverified");
    return profile;
  }
  if (kind === "whatsapp") {
    if (![1, 1.1].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "message") !== "message" ||
      (p.operation ?? "sendTemplate") !== "send"
    )
      return unsupported(profile, "unsupported_send_operation");
    add(
      profile,
      "recipients",
      "recipientPhoneNumber",
      p.recipientPhoneNumber,
      true,
    );
    if ((p.messageType ?? "text") !== "text")
      return unsupported(profile, "unsupported_message_format");
    add(profile, "content", "textBody", p.textBody, true);
    const opts = options(p.additionalFields, profile);
    if (Object.keys(opts).some((key) => key !== "previewUrl"))
      profile.diagnostics.push("connector_options_unresolved");
    if (opts.previewUrl === true)
      profile.diagnostics.push("message_link_preview_unverified");
    return profile;
  }
  if (![1, 1.1, 1.2].includes(node.typeVersion))
    return unsupported(profile, "unsupported_node_version");
  if (
    (p.resource ?? "text") !== "text" ||
    (p.operation ?? "message") !== "message"
  )
    return unsupported(profile, "unsupported_send_operation");
  // GooglePalm credentials permit an operator-defined host. JSON alone cannot
  // establish the endpoint, even when the shipped credential default is Google.
  add(profile, "recipients", "modelId", null);
  profile.diagnostics.push(
    "provider_endpoint_from_credentials_unverified",
    "model_processing_and_retention_unverified",
  );
  if (!isObject(p.messages) || !Array.isArray(p.messages.values))
    profile.diagnostics.push("model_messages_unresolved");
  else
    for (const [index, message] of p.messages.values.entries()) {
      if (!isObject(message)) {
        profile.diagnostics.push("model_messages_unresolved");
        continue;
      }
      add(
        profile,
        "content",
        `messages/values/${index}/content`,
        message.content,
      );
      if (!["user", "model"].includes(stringSelector(message.role ?? "user")))
        profile.diagnostics.push("model_message_role_unresolved");
    }
  const opts = options(p.options, profile);
  add(profile, "content", "options/systemMessage", opts.systemMessage);
  if (
    p.builtInTools !== undefined &&
    (!isObject(p.builtInTools) ||
      Object.values(p.builtInTools).some(
        (item) => item !== false && item !== null,
      ))
  ) {
    add(profile, "content", "builtInTools", p.builtInTools);
    profile.diagnostics.push("model_provider_tools_unverified");
  }
  if (
    node.typeVersion === 1 &&
    opts.codeExecution !== undefined &&
    opts.codeExecution !== false
  )
    profile.diagnostics.push("model_provider_tools_unverified");
  return profile;
}

/** Exact field semantics are pinned to n8n 86dff76e10efba250a4d3e57760e4eb5d2bbea25. */
function sendProfile(node: NormalizedNode): Profile | undefined {
  const table = tableProfile(node);
  if (table) return table;
  const additional = additionalProfile(node);
  if (additional) return additional;
  const p = node.parameters;
  const type = node.type.slice(base.length);
  if (
    ![
      "emailSend",
      "gmail",
      "slack",
      "telegram",
      "httpRequest",
      "httpRequestTool",
    ].includes(type) ||
    !node.type.startsWith(base)
  )
    return;
  const profile: Profile = {
    sink:
      type === "httpRequest" || type === "httpRequestTool"
        ? "http"
        : type === "emailSend" || type === "gmail"
          ? "email"
          : (type as "slack" | "telegram"),
    recipients: [],
    content: [],
    diagnostics: [],
  };
  if (type === "httpRequest" || type === "httpRequestTool") {
    if (!httpVersions.includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    add(profile, "recipients", "url", p.url, true);
    // The URL's query/path can themselves contain transferred data.
    add(profile, "content", "url", p.url);
    for (const [enabled, mode, pairs, json] of [
      ["sendQuery", "specifyQuery", "queryParameters", "jsonQuery"],
      ["sendHeaders", "specifyHeaders", "headerParameters", "jsonHeaders"],
    ]) {
      if (p[enabled!] === undefined || p[enabled!] === false) continue;
      if (p[enabled!] !== true) {
        profile.diagnostics.push("http_send_switch_unresolved");
        continue;
      }
      const selected = p[mode!] ?? "keypair";
      if (selected === "json") add(profile, "content", json!, p[json!], true);
      else if (selected === "keypair") pairsContent(profile, pairs!, p[pairs!]);
      else profile.diagnostics.push("http_parameter_mode_unresolved");
    }
    if (p.sendBody === true) {
      const contentType = p.contentType ?? "json";
      const selected = p.specifyBody ?? "keypair";
      if (contentType === "binaryData")
        profile.diagnostics.push("binary_payload_unavailable");
      else if (
        contentType === "raw" ||
        (contentType === "form-urlencoded" && selected === "string")
      )
        add(profile, "content", "body", p.body, true);
      else if (contentType === "json" && selected === "json")
        add(profile, "content", "jsonBody", p.jsonBody, true);
      else if (
        ["json", "form-urlencoded", "multipart-form-data"].includes(
          stringSelector(contentType),
        ) &&
        (selected === "keypair" || contentType === "multipart-form-data")
      )
        pairsContent(profile, "bodyParameters", p.bodyParameters);
      else profile.diagnostics.push("http_body_mode_unresolved");
    } else if (p.sendBody !== undefined && p.sendBody !== false)
      profile.diagnostics.push("http_send_switch_unresolved");
    const opts = options(p.options, profile);
    const redirects =
      isObject(opts.redirect) && isObject(opts.redirect.redirect)
        ? opts.redirect.redirect.followRedirects
        : undefined;
    if (redirects !== false)
      profile.diagnostics.push("redirect_destination_unverified");
    return profile;
  }
  if (type === "emailSend") {
    if (![1, 2, 2.1].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (node.typeVersion === 1) {
      // V1 has no resource/operation/format switch. Both bodies and top-level
      // CC/BCC are passed to nodemailer, unlike V2's selected body/options.
      const opts = options(p.options, profile);
      add(profile, "recipients", "toEmail", p.toEmail, true);
      for (const key of ["ccEmail", "bccEmail"])
        add(profile, "recipients", key, p[key]);
      for (const key of ["fromEmail", "subject", "text", "html"])
        add(profile, "content", key, p[key]);
      add(profile, "content", "options/replyTo", opts.replyTo);
      if (p.attachments) profile.diagnostics.push("binary_payload_unavailable");
      return profile;
    }
    if (
      (p.resource ?? "email") !== "email" ||
      (p.operation ?? "send") !== "send"
    )
      return unsupported(profile, "unsupported_send_operation");
    const opts = options(p.options, profile);
    add(profile, "recipients", "toEmail", p.toEmail, true);
    for (const key of ["ccEmail", "bccEmail"])
      add(profile, "recipients", "options/" + key, opts[key]);
    add(profile, "content", "subject", p.subject);
    const format = p.emailFormat ?? (node.typeVersion === 2 ? "text" : "html");
    if (format === "text" || format === "both")
      add(profile, "content", "text", p.text);
    if (format === "html" || format === "both")
      add(profile, "content", "html", p.html);
    if (!["text", "html", "both"].includes(stringSelector(format)))
      profile.diagnostics.push("email_format_unresolved");
    if (opts.attachments || opts.fileAttachments)
      profile.diagnostics.push("binary_payload_unavailable");
    return profile;
  }
  if (type === "gmail") {
    if (![2, 2.1, 2.2].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "message") === "message" &&
      ["get", "getAll"].includes(
        typeof p.operation === "string" ? p.operation : "",
      )
    ) {
      profile.readOnly = true;
      profile.opaqueDestination = true;
      profile.diagnostics.push("read_response_classification_unverified");
      const simple = p.simple ?? true;
      profile.responseCode =
        simple === true
          ? "gmail_metadata_response_profile"
          : simple === false
            ? "gmail_parsed_message_response_profile"
            : "gmail_response_selection_unresolved";
      const opts = options(p.options, profile);
      if (p.operation === "get")
        add(profile, "content", "messageId", p.messageId, true);
      else {
        // prepareQuery transforms but retains these filter values in the
        // provider request. It does not forward the fetched mail as a request.
        add(profile, "content", "filters", p.filters);
        if (p.returnAll !== true)
          add(profile, "content", "limit", p.limit ?? 50);
      }
      if (simple === false && opts.downloadAttachments === true)
        profile.diagnostics.push("binary_response_content_unavailable");
      if (simple !== true && simple !== false)
        profile.diagnostics.push("response_selection_unverified");
      return profile;
    }
    if (
      (p.resource ?? "message") !== "message" ||
      (p.operation ?? "send") !== "send"
    )
      return unsupported(profile, "unsupported_send_operation");
    const opts = options(p.options, profile);
    add(profile, "recipients", "sendTo", p.sendTo, true);
    for (const key of ["ccList", "bccList"])
      add(profile, "recipients", "options/" + key, opts[key]);
    add(profile, "content", "subject", p.subject);
    add(profile, "content", "message", p.message, true);
    add(profile, "content", "options/senderName", opts.senderName);
    add(profile, "content", "options/replyTo", opts.replyTo);
    if (opts.attachmentsUi)
      profile.diagnostics.push("binary_payload_unavailable");
    return profile;
  }
  if (type === "slack") {
    if (![2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7].includes(node.typeVersion))
      return unsupported(profile, "unsupported_node_version");
    if (
      (p.resource ?? "message") !== "message" ||
      !["post", "schedule"].includes(
        typeof p.operation === "string"
          ? p.operation
          : p.operation === undefined
            ? "post"
            : "",
      )
    )
      return unsupported(profile, "unsupported_send_operation");
    const destinationField =
      p.select === "channel"
        ? "channelId"
        : p.select === "user"
          ? "user"
          : undefined;
    if (!destinationField)
      profile.diagnostics.push("message_recipient_mode_unresolved");
    else {
      const locator = p[destinationField];
      if (
        isObject(locator) &&
        ["id", "list"].includes(stringSelector(locator.mode))
      )
        add(
          profile,
          "recipients",
          destinationField + "/value",
          locator.value,
          true,
        );
      else {
        add(
          profile,
          "recipients",
          destinationField,
          isObject(locator) ? locator.value : locator,
          true,
        );
        profile.opaqueDestination = true;
        profile.diagnostics.push("recipient_identity_unresolved");
      }
    }
    const messageType = p.messageType ?? "text";
    if (messageType === "text" || messageType === "block")
      add(profile, "content", "text", p.text);
    if (messageType === "block") {
      add(profile, "content", "blocksUi", p.blocksUi, true);
      profile.diagnostics.push("structured_message_overrides_unverified");
      profile.opaqueDestination = true;
    } else if (messageType === "attachment")
      add(profile, "content", "attachments", p.attachments, true);
    else if (messageType !== "text")
      profile.diagnostics.push("message_format_unresolved");
    const opts = options(p.otherOptions, profile);
    const known = new Set([
      "includeLinkToWorkflow",
      "thread_ts",
      "reply_broadcast",
      "unfurl_links",
      "unfurl_media",
      "mrkdwn",
      "link_names",
      "sendAsUser",
      "ephemeral",
      "botProfile",
    ]);
    // These values are merged into the actual request, including expression
    // values inside thread and bot profile options.
    if (isObject(opts.thread_ts) && isObject(opts.thread_ts.replyValues)) {
      add(
        profile,
        "content",
        "otherOptions/thread_ts/replyValues/thread_ts",
        opts.thread_ts.replyValues.thread_ts,
      );
      add(
        profile,
        "content",
        "otherOptions/thread_ts/replyValues/reply_broadcast",
        opts.thread_ts.replyValues.reply_broadcast,
      );
    } else if (opts.thread_ts !== undefined) {
      profile.diagnostics.push("message_options_overrides_unverified");
      profile.opaqueContent = true;
    }
    if (isObject(opts.botProfile) && isObject(opts.botProfile.imageValues)) {
      const selected =
        opts.botProfile.imageValues.profilePhotoType === "image"
          ? "icon_url"
          : "icon_emoji";
      add(
        profile,
        "content",
        "otherOptions/botProfile/imageValues/" + selected,
        opts.botProfile.imageValues[selected],
      );
    } else if (opts.botProfile !== undefined) {
      profile.diagnostics.push("message_options_overrides_unverified");
      profile.opaqueContent = true;
    }
    if (opts.ephemeral !== undefined && (p.operation ?? "post") === "post") {
      if (
        p.select === "channel" &&
        isObject(opts.ephemeral) &&
        isObject(opts.ephemeral.ephemeralValues)
      ) {
        const recipient = opts.ephemeral.ephemeralValues.user;
        if (isObject(recipient)) {
          add(
            profile,
            "recipients",
            "otherOptions/ephemeral/ephemeralValues/user/value",
            recipient.value,
            true,
          );
          if (!["id", "list"].includes(stringSelector(recipient.mode)))
            profile.opaqueDestination = true;
        } else profile.opaqueDestination = true;
      } else if (p.select !== "user") profile.opaqueDestination = true;
      profile.diagnostics.push("ephemeral_recipient_authorization_unverified");
    }
    for (const [key, value] of Object.entries(opts)) {
      if (
        [
          "thread_ts",
          "ephemeral",
          "botProfile",
          "includeLinkToWorkflow",
        ].includes(key)
      )
        continue;
      add(
        profile,
        "content",
        "otherOptions" + (known.has(key) ? "/" + key : ""),
        value,
      );
    }
    if (Object.keys(opts).some((key) => !known.has(key))) {
      profile.diagnostics.push("message_options_overrides_unverified");
      profile.opaqueDestination = true;
    }
    if ((opts.includeLinkToWorkflow ?? node.typeVersion >= 2.1) !== false)
      profile.diagnostics.push("instance_workflow_link_included");
    return profile;
  }
  if (![1, 1.1, 1.2].includes(node.typeVersion))
    return unsupported(profile, "unsupported_node_version");
  if (
    (p.resource ?? "message") !== "message" ||
    !["sendMessage", "sendDocument"].includes(
      typeof p.operation === "string"
        ? p.operation
        : p.operation === undefined
          ? "sendMessage"
          : "",
    )
  )
    return unsupported(profile, "unsupported_send_operation");
  add(profile, "recipients", "chatId", p.chatId, true);
  const extra = options(p.additionalFields, profile);
  const document = p.operation === "sendDocument";
  if (document) {
    add(profile, "content", "additionalFields/caption", extra.caption);
    if (p.binaryData === true) {
      add(profile, "content", "additionalFields/fileName", extra.fileName);
      profile.diagnostics.push("binary_payload_unavailable");
    } else if (p.binaryData === false || p.binaryData === undefined) {
      add(profile, "content", "file", p.file, true);
      // A Telegram file ID or remote URL is a reference, not the file bytes.
      profile.diagnostics.push("remote_attachment_content_unavailable");
    } else {
      profile.diagnostics.push(
        "binary_payload_mode_unresolved",
        "binary_payload_unavailable",
      );
    }
  } else add(profile, "content", "text", p.text, true);
  const known = new Set([
    "appendAttribution",
    "disable_notification",
    "disable_web_page_preview",
    "parse_mode",
    "reply_to_message_id",
    "message_thread_id",
    ...(document
      ? ["caption", "fileName", "disable_content_type_detection"]
      : []),
  ]);
  if (Object.keys(extra).some((key) => !known.has(key))) {
    profile.diagnostics.push("message_options_overrides_unverified");
    profile.opaqueDestination = true;
  }
  if ((p.replyMarkup ?? "none") !== "none") {
    const markup = p.replyMarkup;
    if (markup === "inlineKeyboard" || markup === "replyKeyboard")
      telegramKeyboard(profile, markup, p[markup]);
    profile.diagnostics.push("message_reply_markup_unverified");
  }
  return profile;
}

function pairsContent(profile: Profile, key: string, value: unknown): void {
  if (value === undefined) return;
  if (!isObject(value) || !Array.isArray(value.parameters)) {
    profile.diagnostics.push("http_parameters_shape_unresolved");
    return;
  }
  for (const [index, pair] of value.parameters.entries()) {
    if (!isObject(pair)) {
      profile.diagnostics.push("http_parameters_shape_unresolved");
      continue;
    }
    if (pair.parameterType === "formBinaryData")
      profile.diagnostics.push("binary_payload_unavailable");
    else
      add(
        profile,
        "content",
        `${key}/parameters/${index}/value`,
        pair.value,
        false,
        typeof pair.name === "string" ? pair.name : undefined,
      );
    add(profile, "content", `${key}/parameters/${index}/name`, pair.name);
  }
}

export function transferDataClasses(
  value: AbstractValue,
  evidence?: AssessmentEvidence,
): DataClass[] {
  const values = new Set<DataClass>();
  let unclassified = false;
  for (const origin of value.origins) {
    const matching = evidence?.classifications?.filter((item) => {
      if (item.nodeKey !== origin.nodeKey) return false;
      const field = canonicalEvidenceField(item.field);
      return originIncludesField(origin, field);
    });
    if (matching?.length)
      for (const item of matching) values.add(item.dataClass);
    else if (origin.kind !== "literal") unclassified = true;
    // A subtree candidate can contain any known classified descendant, while
    // its actual selected element and all unclassified descendants stay unknown.
    if (origin.includesDescendants) {
      unclassified = true;
      values.add("unknown");
    }
  }
  // Policies are sets, not a severity ranking: a secret can be permitted while
  // personal data is forbidden in the same object or serialized string.
  for (const sensitivity of value.sensitivityClasses) {
    if (sensitivity === "secret_candidate") values.add("secret");
    else if (sensitivity === "pii_candidate") values.add("personal");
    else if (sensitivity === "public_literal") values.add("public");
  }
  // Exact annotations classify their origin only. They cannot make unknown joins public.
  if (
    value.sensitivityClasses.includes("unknown") &&
    (!values.size ||
      unclassified ||
      value.fullObject ||
      value.status !== "resolved")
  )
    values.add("unknown");
  if (value.fullObject && !value.fields && !value.contentComplete)
    values.add("unknown");
  // A known sensitive part must not hide an unclassified origin in a join.
  if (
    unclassified &&
    !value.sensitivityClasses.every((kind) => kind === "public_literal")
  )
    values.add("unknown");
  if (value.status !== "resolved") values.add("unknown");
  return [...values];
}

function data(
  scope: Scope,
  field: Field,
  value: AbstractValue,
  evidence?: AssessmentEvidence,
  forceCandidate = false,
): DataClass[] {
  const classified = transferDataClasses(value, evidence);
  if (value.status !== "resolved")
    scope.diagnostic("payload_provenance_unresolved");
  const path =
    value.status === "resolved" &&
    value.origins.some((origin) => origin.kind !== "literal") &&
    !forceCandidate;
  const claim = path ? "supported_path" : "candidate";
  if (classified.includes("secret"))
    scope.finding(
      "secret_candidate_transferred",
      field.pointer,
      claim,
      value,
      "high",
    );
  if (classified.includes("personal"))
    scope.finding(
      "personal_data_candidate_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  if (
    !classified.includes("secret") &&
    !classified.includes("personal") &&
    value.fullObject
  )
    scope.finding(
      "whole_object_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  else if (
    !classified.includes("secret") &&
    !classified.includes("personal") &&
    value.origins.some((origin) => origin.kind !== "literal")
  )
    scope.finding("data_field_transferred", field.pointer, claim, value);
  if (value.origins.some((origin) => origin.kind === "database"))
    scope.finding(
      "database_result_transferred",
      field.pointer,
      claim,
      value,
      "medium",
    );
  if (classified.includes("unknown"))
    scope.diagnostic("transferred_data_sensitivity_unverified");
  return classified;
}

function destinations(sink: SinkKind, value: unknown): (string | null)[] {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    String(value).trim().startsWith("=")
  )
    return [null];
  const text = String(value).trim();
  if (!text) return [null];
  if (sink === "email") {
    const recipients = text.split(",");
    if (recipients.length > 128) return [null];
    return recipients.map((part) =>
      /^[^\s<>(),;@]+@[^\s<>(),;@]+\.[^\s<>(),;@]+$/.test(part.trim())
        ? part.trim()
        : null,
    );
  }
  if (sink === "http") {
    try {
      const url = new URL(text);
      return [
        url.protocol === "https:" || url.protocol === "http:" ? url.href : null,
      ];
    } catch {
      return [null];
    }
  }
  if (sink === "whatsapp") return /^\+?\d{7,15}$/.test(text) ? [text] : [null];
  if (sink === "google_docs" && /^https?:/i.test(text)) {
    // Avoid claiming a URL is an opaque approved document ID. URL-to-ID parsing
    // is left to a later profile; the actual JSON transfer remains visible.
    return [null];
  }
  return [text];
}

function policy(
  scope: Scope,
  sink: SinkKind,
  destination: string | null,
  dataClasses: DataClass[],
  evidence?: AssessmentEvidence,
): void {
  const assessment = assessDestination(
    evidence,
    scope.node.key,
    sink,
    destination,
    dataClasses,
  );
  if (assessment.status === "disallowed")
    scope.finding(
      "trusted_policy_transfer_disallowed",
      "/parameters",
      "configuration",
      undefined,
      "high",
      assessment.codes,
    );
  if (assessment.status === "unknown")
    scope.diagnostic(
      assessment.codes.some(
        (code) =>
          code === "policy_not_provided" || code === "policy_rule_missing",
      )
        ? "transfer_policy_not_configured"
        : "trusted_policy_transfer_unresolved",
    );
}

function outgoing(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const result = makeRule("N8N_EXTENDED_OUTBOUND_DATA", "egress");
  for (const node of context.nodes) {
    const profile = sendProfile(node);
    if (!profile) continue;
    if (
      profile.sink === "openai" &&
      node.parameters.hideTools !== "hide" &&
      context.unsupportedEdges.some(
        (edge) => edge.to === node.key && edge.channel === "ai_tool",
      )
    ) {
      profile.diagnostics.push(
        "model_custom_tool_schema_and_result_unverified",
      );
      profile.opaqueContent = true;
    }
    const scope = new Scope(result, node);
    scope.context = context;
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    scope.finding(
      profile.readOnly
        ? "external_read_capability"
        : profile.diagnostics.some(
              (code) =>
                code === "unsupported_send_operation" ||
                code === "unsupported_node_version",
            )
          ? "external_connector_declared"
          : "outbound_send_capability",
      "/type",
    );
    profile.diagnostics.forEach((code) => scope.diagnostic(code));
    if (profile.responseCode)
      scope.finding(profile.responseCode, "/parameters");
    const allClasses = new Set<DataClass>();
    if (
      profile.opaqueContent ||
      profile.diagnostics.some((code) =>
        [
          "binary_payload_unavailable",
          "remote_attachment_content_unavailable",
          "message_reply_markup_unverified",
          "message_keyboard_shape_unresolved",
          "message_keyboard_limit",
        ].includes(code),
      )
    )
      allClasses.add("unknown");
    const leafValues = parameterLeaves(profile.content);
    if (leafValues.limited) {
      scope.diagnostic("parameter_value_analysis_limit");
      allClasses.add("unknown");
    }
    for (const field of leafValues.fields) {
      const value = fieldValue(flow, node.key, field);
      data(scope, field, value, evidence, field.conditional).forEach((kind) =>
        allClasses.add(kind),
      );
    }
    for (const field of profile.recipients) {
      const value = flow.resolve(node.key, field.value);
      if (value.status !== "resolved")
        scope.diagnostic("recipient_provenance_unresolved");
      if (typeof field.value === "string" && field.value.startsWith("="))
        scope.finding(
          "dynamic_recipient_or_destination",
          field.pointer,
          value.status === "resolved" &&
            value.origins.some((origin) => origin.kind !== "literal")
            ? "supported_path"
            : "candidate",
          value,
          "medium",
        );
      // Only flow-proven literal constants may resolve expression destinations.
      // Public classifications or runtime values do not establish an address.
      const selectedDestination =
        value.status === "resolved" && value.constant !== undefined
          ? value.constant
          : field.value;
      for (const destination of destinations(profile.sink, selectedDestination))
        policy(
          scope,
          profile.sink,
          profile.opaqueDestination ? null : destination,
          [...allClasses],
          evidence,
        );
    }
    if (profile.opaqueDestination || !profile.recipients.length)
      policy(scope, profile.sink, null, [...allClasses], evidence);
    if (
      node.raw.continueOnFail === true ||
      node.raw.onError !== undefined ||
      node.raw.alwaysOutputData === true
    )
      scope.diagnostic("nonstandard_execution_semantics");
    scope.finish();
  }
  return finish(result);
}

function response(
  context: Context,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult {
  const result = makeRule("N8N_EXTENDED_OUTPUT_DATA", "output");
  for (const node of context.nodes) {
    const respond = node.type === base + "respondToWebhook";
    const last =
      node.type === base + "webhook" &&
      node.parameters.responseMode === "lastNode";
    const code = node.type === base + "code";
    if (!respond && !last && !code) continue;
    const scope = new Scope(result, node);
    scope.context = context;
    if (node.disabled) {
      scope.diagnostic("disabled_node_not_executed");
      scope.finish();
      continue;
    }
    if (code) {
      logFields(scope, flow, evidence);
      scope.finish();
      continue;
    }
    const versions = respond ? responseVersions : [2, 2.1, 2.2];
    if (!versions.includes(node.typeVersion)) {
      scope.diagnostic("unsupported_node_version");
      scope.finish();
      continue;
    }
    const p = node.parameters;
    const mode = respond
      ? (p.respondWith ?? "firstIncomingItem")
      : (p.responseData ?? "firstEntryJson");
    const opts = isObject(p.options) ? p.options : {};
    const values: { field: Field; value: AbstractValue }[] = [];
    const fields: Field[] = [];
    let unknownContent = false;
    const noBody =
      mode === "noData" ||
      (last && p.responseData === undefined && opts.noResponseBody === true);
    // Response headers are transmitted even when no response body is selected.
    // Parameter objects are already n8n structures; plain JSON strings stay literal.
    if (respond && opts.responseHeaders !== undefined) {
      const entries = isObject(opts.responseHeaders)
        ? opts.responseHeaders.entries
        : undefined;
      if (Array.isArray(entries)) {
        for (const entry of entries.slice(0, 128)) {
          if (!isObject(entry)) {
            unknownContent = true;
            scope.diagnostic("response_headers_shape_unresolved");
            continue;
          }
          for (const key of ["name", "value"])
            if (entry[key] !== undefined)
              fields.push({
                pointer: "/parameters/options/responseHeaders",
                value: entry[key],
              });
        }
        if (entries.length > 128) {
          unknownContent = true;
          scope.diagnostic("response_headers_limit");
        }
      } else {
        unknownContent = true;
        scope.diagnostic("response_headers_shape_unresolved");
      }
    }
    if (
      !noBody &&
      respond &&
      (mode === "firstIncomingItem" || mode === "allIncomingItems")
    ) {
      values.push({
        field: { pointer: "/parameters/respondWith", value: "" },
        value: flow.resolve(
          node.key,
          mode === "allIncomingItems" ? "={{ $input.all() }}" : "={{ $json }}",
        ),
      });
      if (opts.responseKey !== undefined)
        fields.push({
          pointer: "/parameters/options/responseKey",
          value: opts.responseKey,
        });
    } else if (!noBody && respond && (mode === "json" || mode === "text"))
      fields.push({
        pointer: "/parameters/responseBody",
        value: p.responseBody ?? "",
      });
    else if (!noBody && respond && mode === "jwt") {
      fields.push({ pointer: "/parameters/payload", value: p.payload ?? {} });
      scope.finding(
        "signed_response_payload_not_encrypted",
        "/parameters/respondWith",
      );
      scope.diagnostic("jwt_signing_credentials_unverified");
    } else if (!noBody && respond && mode === "redirect") {
      fields.push({
        pointer: "/parameters/redirectURL",
        value: p.redirectURL ?? "",
      });
      scope.finding("redirect_location_response", "/parameters/respondWith");
      scope.diagnostic("redirect_target_authorization_unverified");
    } else if (!noBody && respond && mode === "binary") {
      unknownContent = true;
      scope.diagnostic("binary_response_content_unavailable");
    } else if (
      !noBody &&
      last &&
      (mode === "allEntries" || mode === "firstEntryJson")
    ) {
      const terminal = terminalNodes(context, node.key);
      if (!terminal.length) scope.diagnostic("last_response_source_unresolved");
      const field =
        typeof opts.responsePropertyName === "string" &&
        !opts.responsePropertyName.startsWith("=")
          ? opts.responsePropertyName
          : "";
      if (opts.responsePropertyName !== undefined && !field)
        scope.diagnostic("response_projection_unresolved");
      for (const source of terminal)
        values.push({
          field: { pointer: "/parameters/responseData", value: "" },
          value: flow.output(source.key, field),
        });
      if (terminal.length > 1)
        scope.diagnostic("last_response_order_unverified");
    } else if (!noBody) {
      unknownContent = true;
      scope.diagnostic("response_mode_unresolved");
    }
    const leafValues = parameterLeaves(fields);
    if (leafValues.limited) {
      unknownContent = true;
      scope.diagnostic("parameter_value_analysis_limit");
    }
    for (const field of leafValues.fields)
      values.push({
        field,
        value: flow.resolve(node.key, field.value, { fieldName: field.name }),
      });
    if (noBody && !values.length && !unknownContent) {
      scope.finish();
      continue;
    }
    const allClasses = new Set<DataClass>();
    if (unknownContent) allClasses.add("unknown");
    for (const { field, value } of values)
      data(scope, field, value, evidence).forEach((kind) =>
        allClasses.add(kind),
      );
    policy(scope, "response", "caller", [...allClasses], evidence);
    scope.diagnostic("response_recipient_authorization_unverified");
    scope.finish();
  }
  return finish(result);
}

function terminalNodes(context: Context, start: string): NormalizedNode[] {
  const visited = new Set<string>();
  const queue = [start];
  const leaves: NormalizedNode[] = [];
  while (queue.length && visited.size <= 128) {
    const key = queue.shift()!;
    if (visited.has(key)) continue;
    visited.add(key);
    const next = context.edges.filter((edge) => edge.from === key);
    if (!next.length && key !== start) {
      const node = context.nodeByKey.get(key);
      if (node) leaves.push(node);
    }
    for (const edge of next) queue.push(edge.to);
  }
  return leaves;
}

function logFields(
  scope: Scope,
  flow: ValueFlow,
  evidence?: AssessmentEvidence,
): void {
  const node = scope.node;
  if (
    ![1, 2].includes(node.typeVersion) ||
    (node.parameters.language ?? "javaScript") !== "javaScript" ||
    typeof node.parameters.jsCode !== "string"
  ) {
    scope.diagnostic("unsupported_log_code_profile");
    return;
  }
  const source = node.parameters.jsCode;
  try {
    const ast: unknown = parse(source, {
      ecmaVersion: "latest",
      sourceType: "script",
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
    });
    const pending: unknown[] = [ast];
    let count = 0;
    const argumentsToInspect: { start: number; end: number }[] = [];
    while (pending.length && count++ < 10000) {
      const item = pending.pop();
      if (!isObject(item)) continue;
      if (
        item.type === "CallExpression" &&
        isObject(item.callee) &&
        item.callee.type === "MemberExpression" &&
        isObject(item.callee.object) &&
        item.callee.object.type === "Identifier" &&
        item.callee.object.name === "console" &&
        isObject(item.callee.property) &&
        ["log", "info", "warn", "error", "debug", "table", "dir"].includes(
          String(
            item.callee.computed === true &&
              item.callee.property.type === "Literal"
              ? item.callee.property.value
              : item.callee.computed === false
                ? item.callee.property.name
                : undefined,
          ),
        )
      ) {
        for (const arg of Array.isArray(item.arguments) ? item.arguments : [])
          if (
            isObject(arg) &&
            Number.isInteger(arg.start) &&
            Number.isInteger(arg.end)
          )
            argumentsToInspect.push({
              start: arg.start as number,
              end: arg.end as number,
            });
      }
      for (const child of Object.values(item)) {
        if (Array.isArray(child)) pending.push(...child);
        else if (isObject(child)) pending.push(child);
      }
    }
    if (pending.length) scope.diagnostic("javascript_ast_limit");
    for (const arg of argumentsToInspect.slice(0, 128)) {
      const value = flow.resolveExpression(
        node.key,
        source.slice(arg.start, arg.end),
      );
      const kinds = data(
        scope,
        { pointer: "/parameters/jsCode", value: "" },
        value,
        evidence,
        true,
      );
      scope.finding(
        "console_output_call_candidate",
        "/parameters/jsCode",
        "candidate",
        value,
        "low",
      );
      policy(scope, "log", "execution_log", kinds, evidence);
    }
    if (argumentsToInspect.length > 128) scope.diagnostic("log_argument_limit");
    // Parse-only AST matching does not establish lexical bindings or all logging APIs.
    scope.diagnostic("code_logging_semantics_partial");
  } catch {
    scope.diagnostic("javascript_parse_unavailable");
  }
}

function finish(result: RuleResult): RuleResult {
  if (!result.coverage.length)
    result.coverage.push({
      location: root,
      status: "not_applicable",
      findingIds: [],
      diagnosticIds: [],
    });
  return result;
}

export function analyzeExtendedSinks(
  context: Context,
  valueFlow: ValueFlow,
  evidence?: AssessmentEvidence,
): RuleResult[] {
  return [
    outgoing(context, valueFlow, evidence),
    response(context, valueFlow, evidence),
  ];
}
