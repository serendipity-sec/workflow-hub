import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { frozenCorpus, root } from "./corpus.mjs";

assert.equal(process.argv.length, 2, "This check accepts no arguments");
const corpus = frozenCorpus();
const versions = [
  {
    role: "original",
    caseId: "interpolated",
    inputSha256:
      "fc5b6f72454ccd175bb629fffe445273c9e7a440ab0128ea65f4d675fc4d64b8",
    workflowId: "W18OrigFixture01",
  },
  {
    role: "repaired",
    caseId: "bound",
    inputSha256:
      "e2118900c9f4eef2c17fbc69f9e59941b5e424df10a29b0d8b68e7d45f6e454e",
    workflowId: "W18BoundFixture1",
  },
];

const n8nImage =
  "docker.n8n.io/n8nio/n8n@sha256:fabce3e9678a07d2dde83bd8f5124017f3ec457d0a3fc6b63bb4cec465d63861";
const pgImage =
  "postgres@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015";
const postgresDataDirectory = "/var/lib/postgresql";
const runName = `w18-parity-${randomBytes(5).toString("hex")}`;
const database = `${runName}-postgres`;
const n8n = `${runName}-n8n`;
const credentialId = "W18Credential001";
const adminPassword = randomBytes(18).toString("hex");
const password = randomBytes(18).toString("hex");
const fixtures = versions.map(({ role, caseId, inputSha256, workflowId }) => {
  const source = corpus.cases.find(({ id }) => id === caseId);
  assert.equal(source?.inputSha256, inputSha256);
  const fixture = structuredClone(source.workflow);
  assert.deepEqual(
    fixture.nodes.map(({ type }) => type),
    ["n8n-nodes-base.webhook", "n8n-nodes-base.postgres"],
  );
  assert.equal(fixture.active, false);
  fixture.id = workflowId;
  fixture.nodes[1].credentials = {
    postgres: { id: credentialId, name: "Synthetic read-only Postgres" },
  };
  return {
    role,
    inputSha256,
    caseId,
    workflowId,
    fixture,
    route: `/webhook/${workflowId}/webhook/synthetic-lookup`,
  };
});
const evidence = resolve(root, "evidence-local/native-normal-parity");
assert.ok(
  !evidence.includes(","),
  "Docker bind mount paths cannot contain commas",
);
const interruption = new AbortController();
const { signal } = interruption;
function stop(signalName) {
  if (signal.aborted) return;
  process.exitCode = signalName === "SIGINT" ? 130 : 143;
  interruption.abort(new Error(`Validation interrupted by ${signalName}`));
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);

mkdirSync(evidence, { recursive: true });
const temp = mkdtempSync(resolve(evidence, "fixture-"));
const credentialFile = resolve(temp, "credential.json");
const inputFiles = fixtures.map(({ role }) => resolve(temp, `${role}.json`));
function writeSyntheticInputs() {
  for (const [index, { fixture }] of fixtures.entries()) {
    writeFileSync(inputFiles[index], JSON.stringify(fixture), "utf8");
  }
  writeFileSync(
    credentialFile,
    JSON.stringify([
      {
        id: credentialId,
        name: "Synthetic read-only Postgres",
        type: "postgres",
        data: {
          host: "127.0.0.1",
          database: "fixture",
          user: "fixture_reader",
          password,
          port: 5432,
          ssl: "disable",
        },
      },
    ]),
    "utf8",
  );
}

function run(args, input) {
  return new Promise((resolve) => {
    // Let an in-flight Docker command settle before trying to remove its resources.
    const child = spawn("docker", args, { detached: true, windowsHide: true });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let error;
    function terminate(message) {
      error ??= new Error(message);
      child.kill("SIGKILL");
    }
    function collect(chunks, chunk) {
      if (error) return;
      bytes += chunk.length;
      if (bytes > 1024 * 1024) terminate("Docker output limit exceeded");
      else chunks.push(chunk);
    }
    const timer = setTimeout(
      () => terminate("Docker command timed out"),
      45_000,
    );
    child.stdout.on("data", (chunk) => collect(stdout, chunk));
    child.stderr.on("data", (chunk) => collect(stderr, chunk));
    child.on("error", (cause) => {
      error ??= cause;
    });
    child.stdin.on("error", (cause) => {
      error ??= cause;
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({
        status: error ? null : status,
        error,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
    child.stdin.end(input);
  }).catch((error) => ({ status: null, error, stdout: "", stderr: "" }));
}
async function runActive(args, input) {
  signal.throwIfAborted();
  const result = await run(args, input);
  signal.throwIfAborted();
  return result;
}
async function checked(args, input) {
  const result = await runActive(args, input);
  if (result.status !== 0) {
    throw new Error(
      `docker ${args[0]} failure: ${result.stderr?.trim() || result.error?.message}`,
    );
  }
  return result.stdout.trim();
}
async function waitFor(args) {
  for (let tries = 0; tries < 35; tries += 1) {
    if ((await runActive(args)).status === 0) return;
    await delay(800, undefined, { signal });
  }
  throw new Error("disposable service failed to become ready");
}

const sanitize = (s) =>
  (s ?? "")
    .replaceAll(password, "<synthetic credential>")
    .replaceAll(adminPassword, "<synthetic credential>")
    .replaceAll(temp, "<temporary fixture directory>")
    .replaceAll(temp.replaceAll("\\", "/"), "<temporary fixture directory>");
const native = {
  outcome: "error",
  fixtures: fixtures.map(
    ({ role, inputSha256, caseId, workflowId, route }) => ({
      role,
      inputSha256,
      caseId,
      workflowId,
      route,
    }),
  ),
  probes: [],
  responses: { original: [], repaired: [] },
};
const checkInterfaces =
  'const addresses=Object.values(require("node:os").networkInterfaces()).flat(); if(!addresses.some(a=>a.address==="127.0.0.1")||addresses.some(a=>!a.internal))process.exit(1); console.log(JSON.stringify(addresses.map(a=>a.address).sort()));';
const checkPublished =
  'const equal=require("node:assert/strict").deepEqual; const read=(p)=>JSON.parse(require("node:fs").readFileSync(p)); const select=(nodes)=>nodes.map(({id,name,type,typeVersion,parameters,credentials})=>({id,name,type,typeVersion,parameters,credentials})); const [published]=read(process.argv[1]); const fixture=read(process.argv[2]); equal(published.id,fixture.id); equal(select(published.nodes),select(fixture.nodes)); equal(published.connections,fixture.connections); equal(published.settings.executionOrder,fixture.settings.executionOrder);';
const bootstrap = [
  "set -eu",
  'step() { stage="$1"; shift; if "$@"; then printf "\\nBOOTSTRAP %s exit=0\\n" "$stage"; else code="$?"; printf "\\nBOOTSTRAP %s exit=%s\\n" "$stage" "$code" >&2; exit "$code"; fi; }',
  `step loopback node -e '${checkInterfaces}'`,
  "step credentials n8n import:credentials --input=/credential.json",
  ...fixtures.flatMap(({ role, workflowId }) => [
    `step import-${role} n8n import:workflow --input=/${role}.json --activeState=false`,
    `step publish-${role} n8n publish:workflow --id=${workflowId}`,
    `step export-${role} n8n export:workflow --id=${workflowId} --published --output=/tmp/${role}-published.json`,
    `step inspect-${role} node -e '${checkPublished}' /tmp/${role}-published.json /${role}.json`,
  ]),
  'printf "BOOTSTRAP complete\\n"',
  "exec n8n start",
].join("\n");

const digestQuery =
  "SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(demo_items) ORDER BY id)::text, 'UTF8')), 'hex') FROM demo_items";
const psql = [
  "exec",
  "-i",
  database,
  "psql",
  "-U",
  "fixture_admin",
  "-d",
  "fixture",
  "-X",
  "-qAt",
  "-v",
  "ON_ERROR_STOP=1",
];
try {
  writeSyntheticInputs();
  const databaseId = await checked([
    "run",
    "--detach",
    "--rm",
    "--pull=never",
    "--tmpfs",
    `${postgresDataDirectory}:rw,nosuid,nodev,size=96m`,
    "--network",
    "none",
    "--name",
    database,
    "--env",
    "POSTGRES_DB=fixture",
    "--env",
    "POSTGRES_USER=fixture_admin",
    "--env",
    `POSTGRES_PASSWORD=${adminPassword}`,
    pgImage,
  ]);
  assert.match(databaseId, /^[0-9a-f]{64}$/);
  assert.equal(
    await checked([
      "inspect",
      "--format",
      "{{.HostConfig.NetworkMode}}",
      database,
    ]),
    "none",
  );
  async function assertNoPorts(name) {
    const bindings = JSON.parse(
      await checked([
        "inspect",
        "--format",
        "{{json .HostConfig.PortBindings}}",
        name,
      ]),
    );
    assert.deepEqual(bindings ?? {}, {});
    assert.equal(
      await checked([
        "inspect",
        "--format",
        "{{.HostConfig.PublishAllPorts}}",
        name,
      ]),
      "false",
    );
  }
  await assertNoPorts(database);
  const postgresTempMounts = JSON.parse(
    await checked([
      "inspect",
      "--format",
      "{{json .HostConfig.Tmpfs}}",
      database,
    ]),
  );
  const postgresMountedVolumes = JSON.parse(
    await checked(["inspect", "--format", "{{json .Mounts}}", database]),
  ).filter(({ Type }) => Type === "volume");
  assert.ok(postgresTempMounts[postgresDataDirectory]);
  assert.equal(postgresMountedVolumes.length, 0);
  native.postgresDataMount = {
    target: postgresDataDirectory,
    type: "tmpfs",
    attachedVolumes: postgresMountedVolumes.length,
  };
  await waitFor([
    "exec",
    database,
    "pg_isready",
    "-h",
    "127.0.0.1",
    "-U",
    "fixture_admin",
    "-d",
    "fixture",
  ]);
  await checked(
    psql,
    [
      "CREATE TABLE demo_items (id integer PRIMARY KEY, label text NOT NULL);",
      "INSERT INTO demo_items VALUES (7, 'book'), (9, 'pen');",
      `CREATE ROLE fixture_reader LOGIN PASSWORD '${password}';`,
      "GRANT SELECT ON demo_items TO fixture_reader;",
      "ALTER ROLE fixture_reader SET default_transaction_read_only TO on;",
    ].join("\n"),
  );
  const before = await checked(psql, digestQuery + ";");
  const readerAccess = await checked(
    [
      "exec",
      "-i",
      database,
      "psql",
      "-U",
      "fixture_reader",
      "-d",
      "fixture",
      "-X",
      "-qAt",
      "-v",
      "ON_ERROR_STOP=1",
    ],
    "SELECT current_setting('transaction_read_only'), has_table_privilege(current_user, 'demo_items', 'SELECT'), has_table_privilege(current_user, 'demo_items', 'INSERT,UPDATE,DELETE,TRUNCATE');",
  );
  assert.equal(readerAccess, "on|t|f");
  native.reader = { transactionReadOnly: true, select: true, writes: false };
  native.versions = {
    postgres: (await checked(psql, "SHOW server_version;")).split(" ")[0],
  };
  assert.equal(native.versions.postgres, "18.7");
  await checked([
    "run",
    "--detach",
    "--pull=never",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--network",
    `container:${databaseId}`,
    "--name",
    n8n,
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=192m,uid=1000,gid=1000",
    "--env",
    "N8N_USER_FOLDER=/tmp/n8n-state",
    "--env",
    "N8N_LISTEN_ADDRESS=127.0.0.1",
    "--env",
    "N8N_DIAGNOSTICS_ENABLED=false",
    "--env",
    "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
    "--env",
    "N8N_TEMPLATES_ENABLED=false",
    "--env",
    "N8N_DISABLE_UI=true",
    "--env",
    "N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true",
    "--mount",
    `type=bind,source=${credentialFile},target=/credential.json,readonly`,
    ...fixtures.flatMap(({ role }, index) => [
      "--mount",
      `type=bind,source=${inputFiles[index]},target=/${role}.json,readonly`,
    ]),
    "--entrypoint",
    "sh",
    n8nImage,
    "-ec",
    bootstrap,
  ]);
  assert.equal(
    await checked(["inspect", "--format", "{{.HostConfig.NetworkMode}}", n8n]),
    `container:${databaseId}`,
  );
  await assertNoPorts(n8n);
  const addresses = JSON.parse(
    await checked(["exec", n8n, "node", "-e", checkInterfaces]),
  );
  native.isolation = {
    databaseNetwork: "none",
    sharedNamespace: true,
    addresses,
    publishedPorts: 0,
  };
  const local = "http://127.0.0.1:5678";
  const bootExpiresAt = Date.now() + 120_000;
  let bootstrapped = false;
  while (Date.now() < bootExpiresAt) {
    const logs = await runActive(["logs", "--tail", "35", n8n]);
    if ((logs.stdout + logs.stderr).includes("BOOTSTRAP complete")) {
      bootstrapped = true;
      break;
    }
    if (
      (
        await runActive(["inspect", "--format", "{{.State.Running}}", n8n])
      ).stdout.trim() === "false"
    )
      break;
    await delay(2_000, undefined, { signal });
  }
  assert.equal(bootstrapped, true, "n8n bootstrap did not complete");
  const bootstrapLines = (await checked(["logs", n8n])).split(/\r?\n/);
  native.publication = Object.fromEntries(
    fixtures.map(({ role }) => {
      const markers = ["import", "publish", "export", "inspect"].map(
        (stage) => `BOOTSTRAP ${stage}-${role} exit=0`,
      );
      for (const marker of markers)
        assert.ok(bootstrapLines.includes(marker), marker);
      return [role, markers];
    }),
  );
  const readyExpiresAt = Date.now() + 150_000;
  let ready = false;
  while (Date.now() < readyExpiresAt) {
    const probe = await runActive([
      "exec",
      n8n,
      "node",
      "-e",
      `fetch('${local}/healthz/readiness',{signal:AbortSignal.timeout(3000)}).then(async r=>{console.log(JSON.stringify({status:r.status,body:(await r.text()).slice(0,512)}));if(!r.ok) process.exitCode=1}).catch(e=>{console.error(e.cause?.code??e.name);process.exitCode=2})`,
    ]);
    native.probes.push({
      exit: probe.status,
      stdout: sanitize(probe.stdout).trim(),
      stderr: sanitize(probe.stderr).trim(),
    });
    if (probe.status === 0) {
      ready = true;
      break;
    }
    if (
      (
        await runActive(["inspect", "--format", "{{.State.Running}}", n8n])
      ).stdout.trim() === "false"
    )
      break;
    await delay(2_000, undefined, { signal });
  }
  assert.equal(ready, true, "n8n /healthz/readiness did not return success");
  native.versions.n8n = await checked(["exec", n8n, "n8n", "--version"]);
  assert.equal(native.versions.n8n, corpus.n8nVersion);
  native.digests = { before };
  for (const { role, route } of fixtures) {
    for (const id of [7, 9, 13]) {
      const response = JSON.parse(
        await checked([
          "exec",
          n8n,
          "node",
          "-e",
          `fetch('${local}${route}',{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/json'},body:JSON.stringify({id:${id}})}).then(async r=>console.log(JSON.stringify({status:r.status,contentType:r.headers.get('content-type'),body:await r.text()})))`,
        ]),
      );
      native.responses[role].push({ id, ...response });
    }
    native.digests[role] = await checked(psql, digestQuery + ";");
  }
  assert.match(before, /^[a-f0-9]{64}$/);
  for (const { role } of fixtures) {
    assert.equal(native.digests[role], before);
    const responses = native.responses[role].map(
      ({ id, status, contentType, body }) => {
        assert.ok(contentType.startsWith("application/json"));
        return { id, status, body: JSON.parse(body) };
      },
    );
    assert.deepEqual(responses, [
      { id: 7, status: 200, body: { label: "book" } },
      { id: 9, status: 200, body: { label: "pen" } },
      {
        id: 13,
        status: 500,
        body: { code: 0, message: "No item to return was found" },
      },
    ]);
  }
  native.outcome = "passed";
} catch (error) {
  native.error = sanitize(error.message);
  if (!signal.aborted) process.exitCode = 1;
} finally {
  const state = await run(["inspect", "--format", "{{json .State}}", n8n]);
  const logs = await run(["logs", n8n]);
  const n8nRemoval = await run(["container", "rm", "-fv", n8n]);
  const postgresRemoval = await run(["container", "rm", "-fv", database]);
  const remaining = await run([
    "ps",
    "--all",
    "--filter",
    `name=${runName}-`,
    "--format",
    "{{.Names}}",
  ]);
  const verifiedRemoved = remaining.status === 0 && !remaining.stdout.trim();
  const cleanupErrors = [];
  for (const file of [credentialFile, ...inputFiles, temp]) {
    try {
      if (file === temp) rmdirSync(file);
      else rmSync(file, { force: true });
    } catch (error) {
      cleanupErrors.push(sanitize(error.message));
    }
  }
  const temporaryFilesRemoved = cleanupErrors.length === 0;
  let container = null;
  if (state.status === 0) {
    try {
      container = JSON.parse(state.stdout);
    } catch (error) {
      cleanupErrors.push(sanitize(error.message));
    }
  }
  native.cleanup = {
    n8n: n8nRemoval.status,
    postgres: postgresRemoval.status,
    verifiedRemoved,
    postgresDataRemoved:
      verifiedRemoved && native.postgresDataMount?.type === "tmpfs",
    temporaryFilesRemoved,
    errors: cleanupErrors,
  };
  if (signal.aborted) {
    native.outcome = "error";
    native.error = signal.reason.message;
  } else if (
    native.outcome === "passed" &&
    (n8nRemoval.status !== 0 ||
      postgresRemoval.status !== 0 ||
      !verifiedRemoved ||
      cleanupErrors.length > 0)
  ) {
    native.outcome = "error";
    native.error = "Cleanup failed or could not be verified";
    process.exitCode = 1;
  }
  native.container = container
    ? {
        status: container.Status,
        exit: container.ExitCode,
        oomKilled: container.OOMKilled,
        error: sanitize(container.Error),
      }
    : null;
  writeFileSync(resolve(evidence, "n8n.stdout.txt"), sanitize(logs.stdout));
  writeFileSync(resolve(evidence, "n8n.stderr.txt"), sanitize(logs.stderr));
  writeFileSync(
    resolve(evidence, "report.json"),
    JSON.stringify(native, null, 2) + "\n",
  );
  console.log(
    JSON.stringify(
      {
        outcome: native.outcome,
        error: native.error,
        lastProbe: native.probes.at(-1),
        fixtures: native.fixtures,
        publication: native.publication,
        isolation: native.isolation,
        versions: native.versions,
        reader: native.reader,
        responses: native.responses,
        digests: native.digests,
        container: native.container,
        postgresDataMount: native.postgresDataMount,
        cleanup: native.cleanup,
      },
      null,
      2,
    ),
  );
}
