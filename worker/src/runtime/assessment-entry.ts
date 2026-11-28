import { z } from "zod";
import { assessBytes } from "../assessment/assessment-engine.js";
import { assessmentLimits } from "../contracts/assessment-contract.js";
import { limits } from "../contracts/contract.js";
import { runGitleaks } from "./gitleaks.js";
import { runNativeInspection } from "./native-inspection.js";

const encoded = (maxBytes: number) =>
  z
    .string()
    .max(Math.ceil(maxBytes / 3) * 4)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const inputSchema = z.strictObject({
  workflow: encoded(limits.fileBytes),
  evidence: encoded(1024 * 1024).optional(),
});
const chunks: Buffer[] = [];
let total = 0;
try {
  for await (const chunk of process.stdin) {
    const bytes = Buffer.from(chunk as Buffer);
    total += bytes.length;
    if (total > assessmentLimits.inputBytes) throw new Error("input_limit");
    chunks.push(bytes);
  }
  const input = inputSchema.parse(
    JSON.parse(Buffer.concat(chunks).toString("utf8")),
  );
  const bytes = Buffer.from(input.workflow, "base64");
  const evidenceBytes =
    input.evidence === undefined
      ? undefined
      : Buffer.from(input.evidence, "base64");
  if (
    bytes.length > limits.fileBytes ||
    (evidenceBytes?.length ?? 0) > 1024 * 1024
  )
    throw new Error("input_limit");
  const report = await assessBytes(bytes, {
    evidenceBytes,
    collectTools: async (context) => {
      // Run native scanners sequentially inside the 1-CPU / 96-PID container so
      // Go runtime threads and Python/spaCy initialization never contend.
      const gitleaks = await runGitleaks(context.fields, {
        executable: "/usr/local/bin/gitleaks",
      });
      const native = await runNativeInspection(context, {
        pythonExecutable: "/opt/nlp/bin/python",
      });
      return { gitleaks, native };
    },
  });
  process.stdout.write(JSON.stringify(report) + "\n");
} catch {
  process.stderr.write('{"status":"error","code":"invalid_input"}\n');
  process.exitCode = 1;
}
