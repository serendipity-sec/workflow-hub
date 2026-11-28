import assert from "node:assert/strict";
import test from "node:test";
import { assessmentError } from "../dist/contracts/assessment-contract.js";
import {
  presentInspection,
  inspectionSchema,
} from "../dist/service/inspection.js";

test("inspection binds failure, service display and unavailable model to one hash", async () => {
  const report = assessmentError("1".repeat(64), "invalid_input");
  const result = await presentInspection(report);
  assert.equal(result.inspectionVersion, "1.1.0");
  assert.equal(result.serviceReport.executionStatus, "failed");
  assert.equal(result.llm.code, "disabled");
  const changed = structuredClone(result);
  changed.serviceReport.headline = "검사 완료";
  assert.equal(inspectionSchema.safeParse(changed).success, false);
  const another = structuredClone(result);
  another.inputSha256 = "2".repeat(64);
  assert.equal(inspectionSchema.safeParse(another).success, false);
});
