import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm, access } from "node:fs/promises";
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

test("coverage comparison preserves frozen baselines and rejects incomplete comparison sets", async (t) => {
  const directory = await mkdtemp(
    join(tmpdir(), "worker-coverage-manifest-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const before = join(directory, "before"),
    after = join(directory, "after");
  await mkdir(before);
  await mkdir(after);
  const output = join(directory, "receipt.json");
  const run = (left, right) =>
    execute(
      process.execPath,
      [
        fileURLToPath(
          new URL("../validation/compare-coverage-causes.mjs", import.meta.url),
        ),
        output,
        left,
        right,
      ],
      { env: {}, timeout: 10_000 },
    );
  await assert.rejects(
    run(before, before),
    (error) =>
      error.code === 1 &&
      error.stderr.includes("Before and after must be different"),
  );
  for (const [left, right, expected] of [
    [{ samples: [] }, { samples: [] }, "nonempty complete"],
    [
      { samples: [{ id: 1, sha256: "a".repeat(64) }], failures: [{ id: 2 }] },
      { samples: [] },
      "nonempty complete",
    ],
    [
      { samples: [{ id: 1, sha256: "a".repeat(64) }] },
      { samples: [{ id: 2, sha256: "a".repeat(64) }] },
      "Do not silently drop",
    ],
    [
      { samples: [{ id: 1, sha256: "a".repeat(64) }] },
      { samples: [{ id: 1, sha256: "b".repeat(64) }] },
      "Do not silently drop",
    ],
  ]) {
    await writeFile(join(before, "downloads.json"), JSON.stringify(left));
    await writeFile(join(after, "downloads.json"), JSON.stringify(right));
    await assert.rejects(
      run(before, after),
      (error) =>
        error.code === 1 && !error.killed && error.stderr.includes(expected),
    );
  }
  await assert.rejects(access(output), { code: "ENOENT" });
});
