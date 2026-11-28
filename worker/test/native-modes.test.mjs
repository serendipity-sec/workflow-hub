import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import test from "node:test";
import { createContext } from "../dist/workflow/static-context.js";
import { runNativeInspection } from "../dist/runtime/native-inspection.js";

const context = () =>
  createContext(
    Buffer.from(
      JSON.stringify({ nodes: [], connections: {}, notes: "synthetic" }),
    ),
  );
const result = (mode) => ({
  mode,
  status: "completed",
  findings: [],
  diagnostics: [],
  versions: {
    python: "3.12.10",
    presidio: mode === "nlp" ? "2.2.366" : null,
    spacy: mode === "nlp" ? "3.8.18" : null,
    model: mode === "nlp" ? "en_core_web_sm@3.8.0" : null,
  },
});
function helper(t, options = {}) {
  const children = [];
  const waiters = new Map();
  t.mock.method(childProcess, "spawn", (_executable, args) => {
    const mode = args.at(-1);
    assert.equal(mode, children.length === 0 ? "nlp" : "python");
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = new EventEmitter();
    child.stdin.end = () => {};
    child.kill = () => {
      queueMicrotask(() => child.emit("close", null));
      return true;
    };
    children.push(child);
    waiters.get(children.length - 1)?.(child);
    return child;
  });
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = runNativeInspection(context(), {
    pythonExecutable: process.execPath,
    timeoutMs: 100,
    ...options,
  });
  const next = (index) =>
    children[index]
      ? Promise.resolve(children[index])
      : new Promise((resolve) => waiters.set(index, resolve));
  const finish = (child, mode, value = result(mode)) => {
    child.stdout.emit("data", Buffer.from(JSON.stringify(value)));
    child.emit("close", 0);
  };
  return { pending, next, finish };
}

test("native modes receive separate process time budgets", async (t) => {
  const { pending, next, finish } = helper(t);
  t.mock.timers.tick(80);
  finish(await next(0), "nlp");
  const python = await next(1);
  t.mock.timers.tick(80);
  finish(python, "python");
  assert.deepEqual(
    (await pending).modes.map((mode) => mode.status),
    ["completed", "completed"],
  );
});

test("completed NLP evidence survives a later Python timeout", async (t) => {
  const { pending, next, finish } = helper(t);
  finish(await next(0), "nlp");
  await next(1);
  t.mock.timers.tick(101);
  const modes = (await pending).modes;
  assert.equal(modes[0].status, "completed");
  assert.equal(modes[1].diagnostics[0].code, "native_timeout");
});

test("invalid NLP output does not discard a valid Python result", async (t) => {
  const { pending, next, finish } = helper(t);
  finish(await next(0), "nlp", { invalid: true });
  finish(await next(1), "python");
  const modes = (await pending).modes;
  assert.equal(modes[0].diagnostics[0].code, "native_invalid_report");
  assert.equal(modes[1].status, "completed");
});

test("each native mode counts stdout and stderr against the same byte budget", async (t) => {
  const { pending, next, finish } = helper(t, { maxOutputBytes: 300 });
  finish(await next(0), "nlp");
  const python = await next(1);
  python.stdout.emit("data", Buffer.from(JSON.stringify(result("python"))));
  python.stderr.emit("data", Buffer.alloc(200, 32));
  python.emit("close", 0);
  const modes = (await pending).modes;
  assert.equal(modes[0].status, "completed");
  assert.equal(modes[1].diagnostics[0].code, "native_output_limit");
});

test("an NLP timeout still gives Python its own process and budget", async (t) => {
  const { pending, next, finish } = helper(t);
  t.mock.timers.tick(101);
  finish(await next(1), "python");
  const modes = (await pending).modes;
  assert.equal(modes[0].diagnostics[0].code, "native_timeout");
  assert.equal(modes[1].status, "completed");
});
