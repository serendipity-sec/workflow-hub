import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
for (const name of [
  "verify-llm-service",
  "verify-inspection",
  "verify-public-assessment",
]) {
  test(`${name} cannot certify an empty or failed collection`, async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "worker-manifest-test-"));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const output = join(directory, "receipt.json");
    for (const [manifest, expectedError] of [
      [{ samples: [] }, "A nonempty collected sample set is required"],
      [
        { samples: [{ id: 1 }], failures: [{ id: 2, code: "test_failure" }] },
        "Collection failures must",
      ],
    ]) {
      await writeFile(
        join(directory, "downloads.json"),
        JSON.stringify(manifest),
      );
      const args =
        name !== "verify-inspection"
          ? [directory, output]
          : [output, directory];
      await assert.rejects(
        execute(
          process.execPath,
          [
            fileURLToPath(
              new URL(`../validation/${name}.mjs`, import.meta.url),
            ),
            ...args,
          ],
          { env: {}, timeout: 10_000 },
        ),
        (error) =>
          error.code === 1 &&
          !error.killed &&
          error.stderr.includes(expectedError),
      );
      await assert.rejects(access(output), { code: "ENOENT" });
    }
  });
}
