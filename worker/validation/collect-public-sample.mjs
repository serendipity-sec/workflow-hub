import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";

assert.ok(
  process.argv[2] && process.argv[3],
  "Supply a new local directory and comma-separated official template IDs",
);
const directory = resolve(process.argv[2]);
const ids = process.argv[3].split(",").map(Number);
assert.ok(
  ids.length > 0 &&
    ids.length <= 30 &&
    ids.every((id) => Number.isSafeInteger(id) && id > 0) &&
    new Set(ids).size === ids.length,
);
await mkdir(directory, { recursive: true });
const hash = (value) => createHash("sha256").update(value).digest("hex");
const samples = [],
  failures = [];
for (const id of ids) {
  const source = `https://api.n8n.io/templates/workflows/${id}`;
  try {
    const response = await fetch(source, {
      signal: AbortSignal.timeout(20000),
      redirect: "error",
    });
    assert.equal(response.status, 200);
    const chunks = [];
    let count = 0;
    for await (const chunk of response.body) {
      count += chunk.byteLength;
      assert.ok(count <= 2 * 1024 * 1024);
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks);
    const envelope = JSON.parse(raw.toString("utf8"));
    const definition = envelope.workflow?.workflow;
    assert.ok(
      definition &&
        Array.isArray(definition.nodes) &&
        definition.connections &&
        typeof definition.connections === "object",
    );
    const bytes = Buffer.from(JSON.stringify(definition));
    assert.ok(bytes.length <= 256 * 1024);
    await writeFile(join(directory, `${id}.response.json`), raw, {
      flag: "wx",
      mode: 0o600,
    });
    await writeFile(join(directory, `${id}.workflow.json`), bytes, {
      flag: "wx",
      mode: 0o600,
    });
    samples.push({
      id,
      source,
      publicPage: `https://n8n.io/workflows/${id}`,
      sha256: hash(bytes),
      bytes: bytes.length,
      acquisition: "official_api_definition_extraction",
      responseSha256: hash(raw),
      license: "not_verified",
      nodes: definition.nodes.length,
    });
    console.log(
      JSON.stringify({
        id,
        downloaded: true,
        bytes: bytes.length,
        nodes: definition.nodes.length,
      }),
    );
  } catch {
    failures.push({ id, code: "collection_failed" });
    console.log(JSON.stringify({ id, downloaded: false }));
  }
}
await writeFile(
  join(directory, "downloads.json"),
  JSON.stringify(
    {
      schemaVersion: "1.0.0",
      retrievedAt: new Date().toISOString(),
      scope:
        "additional_official_discovery_page_snapshot_not_accuracy_benchmark",
      originalRedistribution: "not_authorized_or_performed",
      requestedIds: ids,
      failures,
      samples,
    },
    null,
    2,
  ) + "\n",
  { flag: "wx", mode: 0o600 },
);
if (failures.length) process.exitCode = 1;
