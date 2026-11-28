import { analyzeWorkflow } from "../analysis/analysis.js";
import { identitySchema, limits } from "../contracts/contract.js";
import { parseJson, sha256 } from "./worker-io.js";

const maxHeaderBytes = 1024;

async function analyzeStdin(): Promise<void> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > maxHeaderBytes + limits.fileBytes) throw Error();
    chunks.push(chunk);
  }
  const input = Buffer.concat(chunks, size);
  const newline = input.indexOf(10);
  if (newline < 1 || newline >= maxHeaderBytes) throw Error();
  const identity = identitySchema.parse(parseJson(input.subarray(0, newline)));
  const bytes = input.subarray(newline + 1);
  if (
    bytes.length > limits.fileBytes ||
    sha256(bytes) !== identity.inputSha256
  ) {
    throw Error();
  }
  const result = analyzeWorkflow(bytes, identity);
  process.stdout.write(JSON.stringify(result));
}

try {
  await analyzeStdin();
} catch {
  process.exitCode = 1;
}
