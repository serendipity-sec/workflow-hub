import assert from "node:assert/strict";
import { lstat, mkdir, realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

/** Resolve through existing symlink ancestors before creating anything. */
export async function newOutputPath(path, frozenDirectories) {
  const target = resolve(path);
  let ancestor = dirname(target);
  let canonical;
  for (;;) {
    try {
      canonical = await realpath(ancestor);
      break;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) throw error;
      ancestor = parent;
    }
  }
  const output = join(
    canonical,
    relative(ancestor, dirname(target)),
    basename(target),
  );
  for (const directory of frozenDirectories) {
    const rel = relative(await realpath(directory), output);
    assert.ok(
      isAbsolute(rel) ||
        rel === ".." ||
        rel.startsWith("..\\") ||
        rel.startsWith("../"),
      "Output must be outside frozen input directories",
    );
  }
  try {
    await lstat(output);
    assert.fail("Output already exists");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await mkdir(dirname(output), { recursive: true });
  return output;
}
