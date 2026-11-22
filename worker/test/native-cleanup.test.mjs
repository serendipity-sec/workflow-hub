import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { readJson, root } from "../validation/corpus.mjs";

const mockDocker = `
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { PassThrough } from "node:stream";

let pending = false;
let database;
const signal = process.env.NATIVE_TEST_SIGNAL;
const interruptDuring = process.env.NATIVE_TEST_INTERRUPT_DURING;
childProcess.spawnSync = () => assert.fail("Unexpected synchronous Docker command");
childProcess.spawn = (file, args, options) => {
  assert.equal(file, "docker");
  assert.equal(options.detached, true);
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  child.kill = () => assert.fail("Interruption killed an in-flight Docker command");
  const finish = (status, output = "") => {
    child.stdout.end(output);
    child.stderr.end();
    child.emit("close", status);
  };
  setImmediate(() => {
    const [command, action, , name] = args;
    if (command === "run") {
      assert.equal(database, undefined);
      pending = true;
      if (interruptDuring === "launch") process.emit(signal, signal);
      setImmediate(() => {
        database = args[args.indexOf("--name") + 1];
        pending = false;
        finish(0, "a".repeat(64));
      });
      return;
    }
    assert.equal(pending, false, "Cleanup started before Docker reported completion");
    if (command === "inspect" && args[2] === "{{.HostConfig.NetworkMode}}") {
      assert.equal(interruptDuring, "cleanup");
      finish(1);
    } else if (command === "inspect" && args[2] === "{{json .State}}") {
      if (interruptDuring === "cleanup") process.emit(signal, signal);
      finish(0, "malformed inspect output");
    } else if (command === "logs") finish(1);
    else if (command === "container" && action === "rm") {
      if (name === database) database = undefined;
      finish(0);
    } else if (command === "ps") finish(0, database);
    else assert.fail("Unexpected command after interruption: " + command);
  });
  return child;
};
syncBuiltinESMExports();
`;

test("native validation removes synthetic resources after an interruption during launch or cleanup", (t) => {
  const directory = mkdtempSync(resolve(tmpdir(), "worker-native-cleanup-"));
  t.after(() => rmSync(directory, { force: true, recursive: true }));
  const validation = resolve(directory, "validation");
  mkdirSync(validation);
  for (const file of [
    "native-bound-control.mjs",
    "corpus.mjs",
    "case-sha256.json",
  ]) {
    cpSync(resolve(root, "validation", file), resolve(validation, file));
  }
  cpSync(resolve(root, "fixtures"), resolve(directory, "fixtures"), {
    recursive: true,
  });
  const preloader = resolve(directory, "mock-docker.mjs");
  writeFileSync(preloader, mockDocker);

  for (const [signal, exitCode, phase] of [
    ["SIGINT", 130, "launch"],
    ["SIGTERM", 143, "cleanup"],
  ]) {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        pathToFileURL(preloader).href,
        resolve(validation, "native-bound-control.mjs"),
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          NATIVE_TEST_SIGNAL: signal,
          NATIVE_TEST_INTERRUPT_DURING: phase,
        },
        timeout: 5_000,
        windowsHide: true,
      },
    );
    assert.equal(
      result.status,
      exitCode,
      result.stderr || result.error?.message,
    );
    const reports = resolve(directory, "evidence-local/native-normal-parity");
    const report = readJson(resolve(reports, "report.json"));
    assert.equal(report.outcome, "error");
    assert.equal(report.error, `Validation interrupted by ${signal}`);
    assert.equal(report.cleanup.verifiedRemoved, true);
    assert.equal(report.cleanup.n8n, 0);
    assert.equal(report.cleanup.postgres, 0);
    assert.equal(report.cleanup.temporaryFilesRemoved, true);
    assert.equal(report.cleanup.errors.length, 1);
    assert.deepEqual(readdirSync(reports).sort(), [
      "n8n.stderr.txt",
      "n8n.stdout.txt",
      "report.json",
    ]);
  }
});
