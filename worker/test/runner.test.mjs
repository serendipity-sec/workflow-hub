import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { WorkerApiClient } from "../dist/api-client.js";
import { identityOf, limits, resultVersions } from "../dist/contract.js";
import { runLocal, runRemoteOnce } from "../dist/runner.js";
import { runLocalChild } from "../dist/subprocess.js";
import { sha256 } from "../dist/worker-io.js";

const execute = promisify(execFile);
const task = JSON.parse(await readFile("fixtures/task.json", "utf8"));
const bytes = await readFile(task.file.path);
const token = "synthetic-fixture-token";
const identity = identityOf(task);
const claimPath = "/internal/worker/v1/claim";
const resultPath = `/internal/worker/v1/tasks/${task.taskId}/attempts/${task.attemptId}/result`;
const filePath = "/fixture.json?ticket=synthetic-file-ticket";

async function temporary(t) {
  const root = await mkdtemp(join(tmpdir(), "workflow-worker-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function mock(t, options = {}) {
  let origin;
  const requests = [];
  const statuses = [...(options.submitStatuses ?? [201])];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const { url, method, headers } = request;
    requests.push({ url, method, headers, body: Buffer.concat(chunks) });
    if (url === claimPath && method === "POST") {
      const code = options.claimStatus ?? 200;
      if (code === 0) return request.socket.destroy();
      response.writeHead(code, { "Content-Type": "application/json" });
      if (options.stallClaim) return response.flushHeaders();
      const claimed = {
        ...task,
        file: { kind: "download", url: origin + filePath },
        leaseExpiresAt: new Date(Date.now() + 30000).toISOString(),
        ...options.claim,
      };
      response.end(code === 200 ? JSON.stringify(claimed) : "");
    } else if (url === filePath && method === "GET") {
      const code = options.fileStatus ?? 200;
      response.writeHead(code, {
        Location: `${origin}/should-not-fetch`,
        "Content-Encoding": options.fileEncoding ?? "identity",
      });
      if (options.stallFile) return response.flushHeaders();
      response.end(code === 200 ? (options.fileBytes ?? bytes) : "");
    } else if (url === resultPath && method === "PUT") {
      const code = statuses.shift() ?? 500;
      if (code === 0) return request.socket.destroy();
      response.writeHead(code, { "Retry-After": options.retryAfter ?? "0" });
      if (options.stallSubmit) return response.flushHeaders();
      response.end();
    } else {
      response.writeHead(404);
      response.end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  origin = `http://127.0.0.1:${server.address().port}`;
  return {
    client: new WorkerApiClient({
      mode: "mock",
      apiOrigin: origin,
      fileOrigin: origin,
      token,
    }),
    requests,
    origin,
  };
}

test("local CLI runs a child on exactly the fixture bytes", async () => {
  const { stdout, stderr } = await execute(process.execPath, [
    "dist/cli.js",
    "local",
    "fixtures/task.json",
  ]);
  const output = JSON.parse(stdout);
  assert.deepEqual(identityOf(output), identity);
  assert.notEqual(output.status, "error");
  assert.equal(stderr, "");
});

test("local processing distinguishes a changed hash, missing file, oversized file and wrong contract", async (t) => {
  const root = await temporary(t);
  const path = join(root, "fixture.json");
  const input = { ...task, file: { kind: "local", path } };
  assert.equal((await runLocal(input)).code, "file_not_found");
  await writeFile(path, Buffer.concat([bytes, Buffer.from("\r\n")]));
  assert.equal((await runLocal(input)).code, "hash_mismatch");
  await writeFile(path, Buffer.alloc(limits.fileBytes + 1));
  assert.equal((await runLocal(input)).code, "file_too_large");
  await assert.rejects(runLocal({ ...task, contractVersion: "invalid" }), {
    code: "invalid_task",
  });
  await assert.rejects(
    runLocal({ ...task, leaseExpiresAt: "2000-01-01T00:00:00Z" }),
    { code: "lease_expired" },
  );
});

test("child process is constrained and receives no caller environment or writable filesystem grant", async (t) => {
  const root = await temporary(t);
  const path = join(root, "diagnostic.mjs");
  const sample = {
    ...identity,
    ...resultVersions,
    status: "error",
    code: "invalid_json",
  };
  await writeFile(
    path,
    `
    for await (const chunk of process.stdin) { void chunk; }
    if (process.env.WORKER_API_TOKEN || process.env.AWS_SECRET_ACCESS_KEY ||
        !process.permission || process.permission.has('fs.write') || process.permission.has('child')) process.exit(2);
    process.stdout.write(${JSON.stringify(JSON.stringify(sample))});
  `,
  );
  const previous = process.env.WORKER_API_TOKEN;
  process.env.WORKER_API_TOKEN = token;
  try {
    assert.deepEqual(
      await runLocalChild(bytes, identity, undefined, pathToFileURL(path)),
      sample,
    );
  } finally {
    if (previous === undefined) delete process.env.WORKER_API_TOKEN;
    else process.env.WORKER_API_TOKEN = previous;
  }
});

test("child wall, output, non-zero exit, invalid output and cancellation are distinct", async (t) => {
  const root = await temporary(t);
  const processCases = [
    ["analyzer_exit", "process.exitCode = 5"],
    ["invalid_result", "process.stdout.write('not-json')"],
    [
      "invalid_result",
      `process.stdout.write(${JSON.stringify(JSON.stringify({ ...identity, taskId: "other-task", ...resultVersions, status: "error", code: "invalid_json" }))})`,
    ],
    [
      "analyzer_output_limit",
      `process.stderr.write(Buffer.alloc(${limits.resultBytes + 1}))`,
    ],
    ["analyzer_timeout", "setTimeout(() => {}, 10000)"],
    ["cancelled", "setTimeout(() => {}, 10000)", AbortSignal.timeout],
  ];
  await Promise.all(
    processCases.map(async ([code, source, signalFactory], index) => {
      const path = join(root, `fixture-${index}.mjs`);
      await writeFile(
        path,
        `for await (const chunk of process.stdin) { void chunk; }\n${source};`,
      );
      await assert.rejects(
        runLocalChild(
          bytes,
          identity,
          signalFactory?.(200),
          pathToFileURL(path),
        ),
        { code },
      );
    }),
  );
});

test("loopback CLI claims, downloads without bearer and returns an idempotent duplicate receipt", async (t) => {
  const { origin, requests } = await mock(t, { submitStatuses: [503, 200] });
  const { stdout, stderr } = await execute(
    process.execPath,
    ["dist/cli.js", "mock-once"],
    {
      env: {
        ...process.env,
        WORKER_API_ORIGIN: origin,
        WORKER_FILE_ORIGIN: origin,
        WORKER_API_TOKEN: token,
      },
    },
  );
  const receipt = JSON.parse(stdout);
  assert.equal(receipt.status, "duplicate");
  assert.deepEqual(identityOf(receipt.result), identity);
  assert.notEqual(receipt.result.status, "error");
  assert.equal(stderr, "");
  assert.doesNotMatch(stdout, /synthetic-fixture-token|synthetic-file-ticket/);
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath, filePath, resultPath, resultPath],
  );
  const [claim, file, first, second] = requests;
  assert.equal(claim.headers.authorization, `Bearer ${token}`);
  assert.equal(claim.body.length, 0);
  assert.equal(file.headers.authorization, undefined);
  assert.equal(file.headers["accept-encoding"], "identity");
  assert.equal(first.headers.authorization, `Bearer ${token}`);
  assert.deepEqual(first.body, second.body);
  assert.equal(first.headers["idempotency-key"], sha256(first.body));
  assert.equal(
    second.headers["idempotency-key"],
    first.headers["idempotency-key"],
  );
});

test("claim authentication and retryable errors do not repeat a claim", async (t) => {
  for (const [code, wanted] of [
    [401, "auth_rejected"],
    [403, "auth_rejected"],
    [503, "api_retryable"],
    [0, "api_unreachable"],
  ]) {
    const { client, requests } = await mock(t, { claimStatus: code });
    await assert.rejects(runRemoteOnce(client), { code: wanted });
    assert.deepEqual(
      requests.map(({ url }) => url),
      [claimPath],
    );
  }
  const { client, requests } = await mock(t, { claimStatus: 204 });
  assert.deepEqual(await runRemoteOnce(client), { status: "idle" });
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath],
  );
});

test("uncertain submission transport retries the identical result and no extra claim", async (t) => {
  const { client, requests } = await mock(t, { submitStatuses: [0, 200] });
  const outcome = await runRemoteOnce(client);
  assert.equal(outcome.status, "duplicate");
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath, filePath, resultPath, resultPath],
  );
  assert.deepEqual(requests[2].body, requests[3].body);
  assert.equal(
    requests[2].headers["idempotency-key"],
    requests[3].headers["idempotency-key"],
  );
});

test(
  "the claim timeout includes a stalled response body and does not retry",
  { timeout: 10_000 },
  async (t) => {
    const { client, requests } = await mock(t, { stallClaim: true });
    await assert.rejects(runRemoteOnce(client), { code: "api_timeout" });
    assert.deepEqual(
      requests.map(({ url }) => url),
      [claimPath],
    );
  },
);

test("injected launcher receives a deadline and its late output is never accepted", async (t) => {
  const { client, requests } = await mock(t);
  let resolveLate;
  let launcherSignal;
  const analyze = async (_bytes, actualIdentity, controls) => {
    assert.deepEqual(actualIdentity, identity);
    assert.equal(
      controls.limits.productionMemoryMiB,
      limits.productionMemoryMiB,
    );
    launcherSignal = controls.signal;
    return new Promise((resolve) => {
      resolveLate = resolve;
    });
  };
  const outcome = await runRemoteOnce(client, { analyzer: analyze });
  assert.equal(outcome.status, "accepted");
  assert.equal(outcome.result.code, "analyzer_timeout");
  assert.equal(launcherSignal.aborted, true);
  resolveLate({
    ...identity,
    ...resultVersions,
    status: "error",
    code: "invalid_json",
  });
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath, filePath, resultPath],
  );
  assert.equal(JSON.parse(requests[2].body).code, "analyzer_timeout");
});

test("a standalone mock runner completes a pending analyzer with a timeout", async (t) => {
  const { origin, requests } = await mock(t);
  const program = `
    import { WorkerApiClient } from "./dist/api-client.js";
    import { runRemoteOnce } from "./dist/runner.js";
    const origin = ${JSON.stringify(origin)};
    const api = new WorkerApiClient({mode: "mock", apiOrigin: origin, fileOrigin: origin, token: "synthetic"});
    console.log(JSON.stringify(await runRemoteOnce(api, {analyzer: () => new Promise(() => {})})));
  `;
  const { stdout } = await execute(process.execPath, [
    "--input-type=module",
    "-e",
    program,
  ]);
  assert.equal(JSON.parse(stdout).result.code, "analyzer_timeout");
  assert.equal(JSON.parse(requests.at(-1).body).code, "analyzer_timeout");
});

test(
  "uses Retry-After beyond an individual HTTP timeout when lease permits",
  { timeout: 12_000 },
  async (t) => {
    const { client, requests } = await mock(t, {
      submitStatuses: [503, 200],
      retryAfter: "6",
    });
    assert.equal((await runRemoteOnce(client)).status, "duplicate");
    assert.deepEqual(
      requests.map(({ url }) => url),
      [claimPath, filePath, resultPath, resultPath],
    );
  },
);

test("lease expiry stops a stalled download and a stalled submission", async (t) => {
  for (const scenario of [{ stallFile: true }, { stallSubmit: true }]) {
    const { client, requests } = await mock(t, {
      ...scenario,
      claim: { leaseExpiresAt: new Date(Date.now() + 850).toISOString() },
    });
    await assert.rejects(
      runRemoteOnce(client, {
        analyzer: async (_bytes, ids) => ({
          ...ids,
          ...resultVersions,
          status: "error",
          code: "invalid_json",
        }),
      }),
      { code: "lease_expired" },
    );
    assert.deepEqual(
      requests.map(({ url }) => url),
      scenario.stallFile
        ? [claimPath, filePath]
        : [claimPath, filePath, resultPath],
    );
  }
});

test("lease rejection, expired lease and rejected retry wait are explicit", async (t) => {
  for (const [code, wanted] of [
    [409, "lease_rejected"],
    [410, "lease_expired"],
    [429, "api_retryable"],
  ]) {
    const { client, requests } = await mock(t, {
      submitStatuses: [code],
      retryAfter: "120",
    });
    await assert.rejects(runRemoteOnce(client), { code: wanted });
    assert.deepEqual(
      requests.map(({ url }) => url),
      [claimPath, filePath, resultPath],
    );
  }
  const { client, requests } = await mock(t, {
    claim: { leaseExpiresAt: "2000-01-01T00:00:00Z" },
  });
  await assert.rejects(runRemoteOnce(client), { code: "lease_expired" });
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath],
  );
});

test("remote file failure reports one bounded result and follows no redirect", async (t) => {
  const scenarios = [
    [{ fileBytes: Buffer.from("{}") }, "hash_mismatch"],
    [{ fileBytes: Buffer.alloc(limits.fileBytes + 1) }, "file_too_large"],
    [{ fileStatus: 404 }, "file_not_found"],
    [{ fileStatus: 302 }, "file_access"],
    [{ fileEncoding: "gzip" }, "file_access"],
  ];
  for (const [options, code] of scenarios) {
    const { client, requests } = await mock(t, options);
    const outcome = await runRemoteOnce(client);
    assert.equal(outcome.status, "accepted");
    assert.equal(outcome.result.status, "error");
    assert.equal(outcome.result.code, code);
    assert.deepEqual(
      requests.map(({ url }) => url),
      [claimPath, filePath, resultPath],
    );
  }
});

test("remote local paths, unapproved download origins and missing team sandbox are refused", async (t) => {
  const { client: localPathClient } = await mock(t, {
    claim: { file: task.file },
  });
  await assert.rejects(runRemoteOnce(localPathClient), {
    code: "invalid_task",
  });
  const { client: foreignFileClient, requests } = await mock(t, {
    claim: {
      file: { kind: "download", url: "https://example.invalid/fixture.json" },
    },
  });
  assert.equal(
    (await runRemoteOnce(foreignFileClient)).result.code,
    "file_access",
  );
  assert.deepEqual(
    requests.map(({ url }) => url),
    [claimPath, resultPath],
  );
  assert.throws(
    () =>
      new WorkerApiClient({
        mode: "mock",
        apiOrigin: "http://localhost:9876",
        fileOrigin: "http://127.0.0.1:9876",
        token,
      }),
    { code: "invalid_configuration" },
  );
  const team = new WorkerApiClient({
    apiOrigin: "https://example.invalid",
    fileOrigin: "https://example.invalid",
    token,
  });
  await assert.rejects(runRemoteOnce(team), { code: "isolation_unverified" });
  await assert.rejects(
    runRemoteOnce(team, {
      analyzer: () => {
        assert.fail("Mock analyzer was invoked in team mode");
      },
    }),
    { code: "isolation_unverified" },
  );
});
