import { rm } from "node:fs/promises";

// This fixed package-relative directory contains generated TypeScript output.
// Clear old module paths before building after a source move.
await rm(new URL("../dist/", import.meta.url), {
  recursive: true,
  force: true,
});
