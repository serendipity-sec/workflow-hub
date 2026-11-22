import { limits } from "./contract.js";
import { analyzeStatic, scannerResultSchema } from "./static-engine.js";
import { sha256 } from "./worker-io.js";
import { z } from "zod";

const headerSchema = z.strictObject({
  inputSha256: z.string().regex(/^[0-9a-f]{64}$/),
  scanner: scannerResultSchema,
});

try {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limits.fileBytes + limits.resultBytes + 1) throw Error();
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks);
  const newline = input.indexOf(10);
  if (newline < 1 || newline > limits.resultBytes) throw Error();
  const header = headerSchema.parse(
    JSON.parse(input.subarray(0, newline).toString("utf8")),
  );
  const bytes = input.subarray(newline + 1);
  if (bytes.length > limits.fileBytes || sha256(bytes) !== header.inputSha256)
    throw Error();
  process.stdout.write(JSON.stringify(analyzeStatic(bytes, header.scanner)));
} catch {
  process.exitCode = 1;
}
