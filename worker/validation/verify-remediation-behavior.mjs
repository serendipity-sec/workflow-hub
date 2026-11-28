import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  applyRemediation,
  createRemediationPlans,
} from "../dist/assessment/assessment-change.js";
import { createContext } from "../dist/workflow/static-context.js";
import { analyzeFlow } from "../dist/rules/static-flow.js";

// This is deliberately not a general workflow execution harness. Only these
// immutable, repository-authored synthetic bytes may reach n8n or PostgreSQL.
assert.equal(
  process.argv.length,
  2,
  "This check accepts no inputs or arguments",
);
const root = fileURLToPath(new URL("..", import.meta.url));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const original = readFileSync(
  resolve(root, "fixtures/workflows/interpolated.json"),
);
assert.equal(
  hash(original),
  "fc5b6f72454ccd175bb629fffe445273c9e7a440ab0128ea65f4d675fc4d64b8",
  "Only the frozen synthetic fixture may be executed",
);
const context = createContext(original);
const plans = createRemediationPlans(
  context,
  analyzeFlow(context).flatMap(({ findings }) => findings),
  hash(original),
).filter(({ kind }) => kind === "bind_postgres_lookup_value");
assert.equal(plans.length, 1);
const generated = applyRemediation(original, plans[0]);
const generatedSql = analyzeFlow(createContext(generated)).find(
  ({ category }) => category === "sql",
);
assert.ok(generatedSql);
assert.equal(
  generatedSql.findings.some(({ evidence }) =>
    evidence.some(({ code }) => code.includes("interpolation")),
  ),
  false,
);
const before = JSON.parse(original);
const after = JSON.parse(generated);
const originalQuery = before.nodes[1].parameters.query;
const generatedQuery = after.nodes[1].parameters.query;
assert.equal(
  originalQuery,
  "SELECT label FROM demo_items WHERE id = {{ $json.body.id }}",
);
assert.equal(generatedQuery, "SELECT label FROM demo_items WHERE id = $1");
assert.equal(
  after.nodes[1].parameters.options.queryReplacement,
  "={{ [$json.body.id] }}",
);
const expected = structuredClone(before);
expected.nodes[1].parameters.query = generatedQuery;
expected.nodes[1].parameters.options = {
  queryReplacement: "={{ [$json.body.id] }}",
};
assert.deepEqual(
  after,
  expected,
  "Only the recognized binding edit is executable",
);
assert.deepEqual(
  before.nodes.map(({ type }) => type),
  ["n8n-nodes-base.webhook", "n8n-nodes-base.postgres"],
);
assert.equal(before.active, false);

const pgImage =
  "postgres@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015";
const n8nImage =
  "docker.n8n.io/n8nio/n8n@sha256:fabce3e9678a07d2dde83bd8f5124017f3ec457d0a3fc6b63bb4cec465d63861";
const runName = `worker-remediation-${randomBytes(6).toString("hex")}`;
const database = `${runName}-postgres`;
const n8n = `${runName}-n8n`;
const adminPassword = randomBytes(18).toString("hex");
const password = randomBytes(18).toString("hex");
const credentialId = "SyntheticRemediationPg01";
const evidenceDirectory = resolve(root, "evidence-local/remediation-behavior");
mkdirSync(evidenceDirectory, { recursive: true });
const temp = mkdtempSync(resolve(evidenceDirectory, "fixture-"));
assert.ok(!temp.includes(","));
const credentialFile = resolve(temp, "credential.json");
const fixtures = [
  { role: "original", bytes: original, workflowId: "RemediateOriginal01" },
  { role: "generated", bytes: generated, workflowId: "RemediateGenerated1" },
].map(({ role, bytes, workflowId }) => {
  const definition = JSON.parse(bytes);
  definition.id = workflowId;
  definition.nodes[1].credentials = {
    postgres: { id: credentialId, name: "Synthetic read-only database" },
  };
  const prepared = Buffer.from(JSON.stringify(definition));
  const path = resolve(temp, `${role}.json`);
  return {
    role,
    bytes,
    workflowId,
    prepared,
    path,
    route: `/webhook/${workflowId}/webhook/synthetic-lookup`,
  };
});
const controllerFiles = [
  "dist/assessment/assessment-change.js",
  "dist/workflow/static-context.js",
  "dist/rules/static-flow.js",
  "validation/verify-remediation-behavior.mjs",
];
const artifacts = Object.fromEntries(
  controllerFiles.map((path) => [
    path,
    hash(readFileSync(resolve(root, path))),
  ]),
);
const report = {
  schemaVersion: "1.0.0",
  generatedAt: new Date().toISOString(),
  outcome: "error",
  scope: "frozen_repository_synthetic_fixture_only",
  workflowExecution: "not_started",
  uploadedWorkflowExecution: "not_run",
  teamApiIntegration: "not_tested",
  generalBehaviorPreservation: "not_claimed",
  command: "node validation/verify-remediation-behavior.mjs",
  artifacts,
  remediation: {
    kind: plans[0].kind,
    planId: plans[0].id,
    originalSha256: hash(original),
    generatedSha256: hash(generated),
    originalBytes: original.length,
    generatedBytes: generated.length,
    onlyRecognizedBindingChanged: true,
    generatedBytesStaticallyRechecked: true,
    interpolationFindingPresentAfterPatch: false,
    importedDefinitions: fixtures.map(({ role, bytes, prepared }) => ({
      role,
      definitionSha256: hash(bytes),
      preparedSha256: hash(prepared),
      preparation:
        "fixed_synthetic_workflow_id_and_generated_credential_reference",
    })),
  },
  images: { postgres: pgImage, n8n: n8nImage },
  versions: { node: process.version },
  databaseChecks: [],
  workflowChecks: [],
  publication: [],
  diagnostics: [],
};
const interruption = new AbortController();
const { signal } = interruption;
let stage = "prepare";
const owned = new Set();
function stop() {
  interruption.abort();
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
function run(args, input, cleanup = false) {
  return new Promise((resolveResult) => {
    const child = spawn("docker", args, {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let bytes = 0;
    let failed = false;
    const stdout = [];
    const stderr = [];
    function kill() {
      failed = true;
      child.kill("SIGKILL");
    }
    function collect(target, chunk) {
      bytes += chunk.length;
      if (bytes > 1024 * 1024) kill();
      else target.push(chunk);
    }
    const timer = setTimeout(kill, 45_000);
    if (!cleanup) {
      signal.addEventListener("abort", kill, { once: true });
      if (signal.aborted) kill();
    }
    child.stdout.on("data", (chunk) => collect(stdout, chunk));
    child.stderr.on("data", (chunk) => collect(stderr, chunk));
    child.on("error", () => {
      failed = true;
    });
    child.stdin.on("error", () => {
      failed = true;
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", kill);
      resolveResult({
        status: failed ? null : status,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      });
    });
    child.stdin.end(input);
  });
}
async function checked(args, input) {
  signal.throwIfAborted();
  const result = await run(args, input);
  signal.throwIfAborted();
  assert.equal(result.status, 0, "Disposable validation command failed");
  return result.stdout.trim();
}
async function ready(args, attempts = 40) {
  for (let index = 0; index < attempts; index++) {
    signal.throwIfAborted();
    if ((await run(args)).status === 0) return;
    await delay(1000, undefined, { signal });
  }
  throw new Error("readiness_failed");
}
const psql = (user) => [
  "exec",
  "-i",
  database,
  "psql",
  "-U",
  user,
  "-d",
  "fixture",
  "-X",
  "-qAt",
  "-v",
  "ON_ERROR_STOP=1",
];
const digestQuery =
  "SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(demo_items) ORDER BY id)::text, 'UTF8')), 'hex') FROM demo_items;";
const networkCheck =
  'const addresses=Object.values(require("node:os").networkInterfaces()).flat();if(!addresses.some(a=>a.address==="127.0.0.1")||addresses.some(a=>!a.internal))process.exit(1);console.log("loopback_only");';
const publicationCheck =
  'const equal=require("node:assert/strict").deepEqual;const read=p=>JSON.parse(require("node:fs").readFileSync(p));const select=nodes=>nodes.map(({id,name,type,typeVersion,parameters,credentials})=>({id,name,type,typeVersion,parameters,credentials}));const[published]=read(process.argv[1]);const fixture=read(process.argv[2]);equal(published.id,fixture.id);equal(select(published.nodes),select(fixture.nodes));equal(published.connections,fixture.connections);equal(published.settings.executionOrder,fixture.settings.executionOrder);';
const bootstrap = [
  "set -eu",
  `node -e '${networkCheck}'`,
  "n8n import:credentials --input=/credential.json",
  ...fixtures.flatMap(({ role, workflowId }) => [
    `n8n import:workflow --input=/${role}.json --activeState=false`,
    `n8n publish:workflow --id=${workflowId}`,
    `n8n export:workflow --id=${workflowId} --published --output=/tmp/${role}-published.json`,
    `node -e '${publicationCheck}' /tmp/${role}-published.json /${role}.json`,
    `printf '\\nPUBLISHED_VERIFIED_${role}\\n'`,
  ]),
  "printf '\\nBOOTSTRAP_COMPLETE\\n'",
  "exec n8n start",
].join("\n");
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
async function probe(route, value) {
  // route/value are fixed synthetic values above; no user input or uploaded URL.
  return JSON.parse(
    await checked([
      "exec",
      n8n,
      "node",
      "-e",
      `fetch(${JSON.stringify(`http://127.0.0.1:5678${route}`)},{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/json'},body:JSON.stringify({id:${JSON.stringify(value)}})}).then(async r=>console.log(JSON.stringify({status:r.status,contentType:r.headers.get('content-type'),body:await r.text()})))`,
    ]),
  );
}
try {
  for (const { path, prepared } of fixtures) writeFileSync(path, prepared);
  writeFileSync(
    credentialFile,
    JSON.stringify([
      {
        id: credentialId,
        name: "Synthetic read-only database",
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
  );
  stage = "postgres_start";
  owned.add(database);
  const databaseId = await checked([
    "run",
    "--detach",
    "--pull=never",
    "--network=none",
    "--name",
    database,
    "--label",
    `worker.remediation-run=${runName}`,
    "--memory=256m",
    "--memory-swap=256m",
    "--pids-limit=64",
    "--cpus=1",
    "--tmpfs",
    "/var/lib/postgresql:rw,nosuid,nodev,size=96m",
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
  await assertNoPorts(database);
  const mounts = JSON.parse(
    await checked(["inspect", "--format", "{{json .Mounts}}", database]),
  );
  assert.equal(
    mounts.filter(({ Type }) => ["bind", "volume"].includes(Type)).length,
    0,
  );
  const tmpfs = JSON.parse(
    await checked([
      "inspect",
      "--format",
      "{{json .HostConfig.Tmpfs}}",
      database,
    ]),
  );
  assert.ok(tmpfs["/var/lib/postgresql"]);
  await ready([
    "exec",
    database,
    "pg_isready",
    "-U",
    "fixture_admin",
    "-d",
    "fixture",
  ]);
  stage = "postgres_initialize";
  await checked(
    psql("fixture_admin"),
    [
      "CREATE TABLE demo_items (id integer PRIMARY KEY, label text NOT NULL);",
      "INSERT INTO demo_items VALUES (7, 'book'), (9, 'pen');",
      `CREATE ROLE fixture_reader LOGIN PASSWORD '${password}';`,
      "GRANT SELECT ON demo_items TO fixture_reader;",
      "ALTER ROLE fixture_reader SET default_transaction_read_only TO on;",
    ].join("\n"),
  );
  const permissions = await checked(
    psql("fixture_reader"),
    "SELECT current_setting('transaction_read_only'), has_table_privilege(current_user, 'demo_items', 'SELECT'), has_table_privilege(current_user, 'demo_items', 'INSERT,UPDATE,DELETE,TRUNCATE');",
  );
  assert.equal(permissions, "on|t|f");
  report.databaseAccess = {
    readOnly: true,
    select: true,
    writes: false,
    syntheticDataOnly: true,
  };
  report.versions.postgres = (
    await checked(psql("fixture_admin"), "SHOW server_version;")
  ).split(" ")[0];
  assert.equal(report.versions.postgres, "18.7");
  const initialDigest = await checked(psql("fixture_admin"), digestQuery);
  assert.match(initialDigest, /^[a-f0-9]{64}$/);
  stage = "postgres_normal_cases";
  for (const id of [7, 9, 13]) {
    const raw = await checked(
      psql("fixture_reader"),
      originalQuery.replace("{{ $json.body.id }}", String(id)) + ";",
    );
    const bound = await checked(
      psql("fixture_reader"),
      `PREPARE synthetic_lookup(integer) AS ${generatedQuery};\nEXECUTE synthetic_lookup(${id});`,
    );
    assert.equal(raw, id === 7 ? "book" : id === 9 ? "pen" : "");
    assert.equal(bound, raw);
    report.databaseChecks.push({
      case: `normal_${id}`,
      originalRows: raw ? raw.split("\n").length : 0,
      generatedRows: bound ? bound.split("\n").length : 0,
      equal: true,
      outputs: "masked",
    });
  }
  stage = "postgres_attack_case";
  const attack = "7 OR 1=1";
  const rawAttack = await checked(
    psql("fixture_reader"),
    originalQuery.replace("{{ $json.body.id }}", attack) + ";",
  );
  assert.deepEqual(rawAttack.split("\n").sort(), ["book", "pen"]);
  const boundAttack = await run(
    psql("fixture_reader"),
    `\\set VERBOSITY sqlstate\nPREPARE synthetic_lookup(integer) AS ${generatedQuery};\nEXECUTE synthetic_lookup('${attack}');`,
  );
  assert.notEqual(boundAttack.status, 0);
  assert.match(boundAttack.stderr, /\b22P02\b/);
  assert.equal(boundAttack.stdout.trim(), "");
  report.databaseChecks.push({
    case: "read_only_boolean_expression",
    originalRows: 2,
    originalPredicateBroadened: true,
    generatedRejected: true,
    generatedRows: 0,
    sqlstate: "22P02",
    outputs: "masked",
  });
  stage = "n8n_start";
  owned.add(n8n);
  await checked([
    "run",
    "--detach",
    "--pull=never",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--network",
    `container:${databaseId}`,
    "--name",
    n8n,
    "--label",
    `worker.remediation-run=${runName}`,
    "--memory=768m",
    "--memory-swap=768m",
    "--pids-limit=96",
    "--cpus=1",
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
    ...fixtures.flatMap(({ role, path }) => [
      "--mount",
      `type=bind,source=${path},target=/${role}.json,readonly`,
    ]),
    "--entrypoint",
    "sh",
    n8nImage,
    "-ec",
    bootstrap,
  ]);
  await assertNoPorts(n8n);
  assert.equal(
    await checked(["inspect", "--format", "{{.HostConfig.NetworkMode}}", n8n]),
    `container:${databaseId}`,
  );
  assert.equal(
    await checked(["exec", n8n, "node", "-e", networkCheck]),
    "loopback_only",
  );
  report.isolation = {
    databaseNetwork: "none",
    n8nSharesDatabaseNamespace: true,
    loopbackOnly: true,
    publishedPorts: 0,
    databaseStorage: "tmpfs",
    persistentDatabaseVolumes: 0,
    fixtureMounts: "read_only",
    n8nReadOnlyRoot: true,
  };
  stage = "n8n_bootstrap";
  let bootstrapVerified = false;
  for (let index = 0; index < 90; index++) {
    const logs = await run(["logs", n8n]);
    const output = logs.stdout + logs.stderr;
    if (output.includes("BOOTSTRAP_COMPLETE")) {
      for (const { role } of fixtures) {
        assert.ok(output.includes(`PUBLISHED_VERIFIED_${role}`));
        report.publication.push({
          role,
          publishedNodesAndConnectionsMatchPreparedBytes: true,
        });
      }
      bootstrapVerified = true;
      break;
    }
    assert.equal(
      await checked(["inspect", "--format", "{{.State.Running}}", n8n]),
      "true",
    );
    await delay(1500, undefined, { signal });
  }
  assert.equal(bootstrapVerified, true);
  await ready(
    [
      "exec",
      n8n,
      "node",
      "-e",
      "fetch('http://127.0.0.1:5678/healthz/readiness',{signal:AbortSignal.timeout(3000)}).then(r=>{if(!r.ok)process.exitCode=1}).catch(()=>{process.exitCode=2})",
    ],
    90,
  );
  report.versions.n8n = await checked(["exec", n8n, "n8n", "--version"]);
  assert.equal(report.versions.n8n, "2.48.7");
  report.workflowExecution = "frozen_synthetic_original_and_generated_patch";
  stage = "n8n_normal_cases";
  const observed = new Map();
  for (const { role, route } of fixtures) {
    for (const id of [7, 9, 13]) {
      const response = await probe(route, id);
      assert.ok(response.contentType.startsWith("application/json"));
      const body = JSON.parse(response.body);
      if (id === 13) {
        assert.equal(response.status, 500);
        assert.deepEqual(body, {
          code: 0,
          message: "No item to return was found",
        });
      } else {
        assert.equal(response.status, 200);
        assert.deepEqual(body, { label: id === 7 ? "book" : "pen" });
      }
      if (role === "original") observed.set(id, response);
      else assert.deepEqual(response, observed.get(id));
      report.workflowChecks.push({
        role,
        case: `normal_${id}`,
        httpStatus: response.status,
        matchesExpected: true,
        result: id === 13 ? "no_item_response" : "one_expected_item",
        body: "masked",
      });
    }
  }
  stage = "n8n_attack_case";
  for (const { role, route } of fixtures) {
    const response = await probe(route, attack);
    assert.ok(response.contentType.startsWith("application/json"));
    const body = JSON.parse(response.body);
    if (role === "original") {
      assert.equal(response.status, 200);
      assert.deepEqual(body, { label: "book" });
    } else {
      assert.equal(response.status, 500);
      assert.equal(typeof body.message, "string");
      assert.equal(Object.hasOwn(body, "label"), false);
    }
    report.workflowChecks.push({
      role,
      case: "read_only_boolean_expression",
      httpStatus: response.status,
      result:
        role === "original"
          ? "returned_first_item_of_broadened_query"
          : "rejected_without_result_item",
      body: "masked",
    });
  }
  stage = "postconditions";
  assert.equal(
    await checked(psql("fixture_admin"), digestQuery),
    initialDigest,
  );
  for (const [path, expectedHash] of Object.entries(artifacts))
    assert.equal(
      hash(readFileSync(resolve(root, path))),
      expectedHash,
      "Validation code changed during the run",
    );
  assert.equal(
    hash(readFileSync(resolve(root, "fixtures/workflows/interpolated.json"))),
    hash(original),
  );
  report.postconditions = {
    databaseContentUnchanged: true,
    originalFixtureUnchanged: true,
    validationArtifactsUnchanged: true,
    normalCasesPreserved: 3,
    attackRejectedAfterPatch: true,
  };
  report.diagnostics.push(
    "fixed_cases_are_not_general_workflow_equivalence",
    "no_item_http_500_behavior_intentionally_preserved",
    "original_webhook_returns_first_item_so_database_check_proves_broadened_predicate",
  );
  report.outcome = "passed";
} catch {
  report.diagnostics.push(
    signal.aborted ? "validation_cancelled" : "validation_failed",
  );
  report.failedStage = stage;
  process.exitCode = 1;
} finally {
  const cleanup = [];
  for (const name of [n8n, database]) {
    if (!owned.has(name)) continue;
    const ownership = await run(
      [
        "inspect",
        "--format",
        '{{index .Config.Labels "worker.remediation-run"}}',
        name,
      ],
      undefined,
      true,
    );
    const ownershipVerified =
      ownership.status === 0 && ownership.stdout.trim() === runName;
    const result = ownershipVerified
      ? await run(["container", "rm", "-fv", name], undefined, true)
      : { status: null };
    const remaining = await run(
      ["ps", "--all", "--filter", `name=^/${name}$`, "--format", "{{.Names}}"],
      undefined,
      true,
    );
    cleanup.push({
      role: name === n8n ? "n8n" : "postgres",
      ownershipVerified,
      removalExit: result.status,
      absent: remaining.status === 0 && remaining.stdout.trim() === "",
    });
  }
  let temporaryFilesRemoved = true;
  for (const path of [credentialFile, ...fixtures.map(({ path }) => path)]) {
    try {
      rmSync(path, { force: true });
    } catch {
      temporaryFilesRemoved = false;
    }
  }
  try {
    rmdirSync(temp);
  } catch {
    temporaryFilesRemoved = false;
  }
  report.cleanup = { containers: cleanup, temporaryFilesRemoved };
  if (
    cleanup.some(
      ({ absent, ownershipVerified, removalExit }) =>
        !absent || !ownershipVerified || removalExit !== 0,
    ) ||
    !temporaryFilesRemoved
  ) {
    report.outcome = "error";
    report.diagnostics.push("cleanup_not_verified");
    process.exitCode = 1;
  }
  writeFileSync(
    resolve(root, "validation/remediation-behavior-results.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(
    JSON.stringify({
      outcome: report.outcome,
      failedStage: report.failedStage,
      databaseChecks: report.databaseChecks.length,
      workflowChecks: report.workflowChecks.length,
      cleanup: report.cleanup,
    }),
  );
}
