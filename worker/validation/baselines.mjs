import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { metrics, readJson, root, sha256 } from "./corpus.mjs";

const flowguardCommit = "03b348d008eaafdebc3650973561d8091af1d8c8";
const flowguardBundleSha =
  "e7e079a09c8f95937abf477735359573485b53a50ab0bcdd6c1332d9f90af240";
const images = {
  node: "node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293",
  n8n: "docker.n8n.io/n8nio/n8n@sha256:fabce3e9678a07d2dde83bd8f5124017f3ec457d0a3fc6b63bb4cec465d63861",
  postgres:
    "postgres@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015",
};
const common = ["run", "--rm", "--pull=never", "--network=none", "--read-only"];
const sqlSection = 'Expressions in "Execute Query" fields in SQL nodes';
const unusedSection = 'Unused "Query Parameters" fields in SQL nodes';
const fixedQuery = "SELECT label FROM demo_items WHERE id = $1";

function mount(source, target) {
  assert.equal(
    source.includes(","),
    false,
    "Docker mount source contains a comma",
  );
  return ["--mount", `type=bind,source=${source},target=${target},readonly`];
}

export function runExternal(corpus, flowguard, directory) {
  const version = spawnSync("git", ["-C", flowguard, "rev-parse", "HEAD"], {
    encoding: "utf8",
  });
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), flowguardCommit);
  const clean = spawnSync("git", ["-C", flowguard, "diff", "--quiet", "HEAD"]);
  assert.equal(clean.status, 0, "FlowGuard tracked source was modified");
  const bundle = readFileSync(
    resolve(flowguard, "dist/cli.js"),
    "utf8",
  ).replaceAll("\r\n", "\n");
  assert.equal(
    sha256(bundle),
    flowguardBundleSha,
    "rebuild the pinned FlowGuard CLI",
  );
  assert.equal(
    corpus.cases
      .find(({ id }) => id === corpus.behavior.candidate)
      .workflow.nodes.find(({ type }) => type === "n8n-nodes-base.postgres")
      .parameters.query,
    fixedQuery,
  );
  mkdirSync(directory, { recursive: true });
  const statuses = {};
  const prefix = "w18-static-" + randomBytes(6).toString("hex");
  const run = (name, args) => {
    const container = `${prefix}-${name}`;
    const result = spawnSync(
      "docker",
      [...common, "--name", container, ...args],
      {
        maxBuffer: 1024 * 1024,
        timeout: 120_000,
        windowsHide: true,
      },
    );
    writeFileSync(
      resolve(directory, `${name}.stdout.txt`),
      result.stdout ?? "",
    );
    writeFileSync(
      resolve(directory, `${name}.stderr.txt`),
      result.stderr ?? "",
    );
    let error = result.error?.code ?? null;
    if (error || result.status !== 0) {
      spawnSync("docker", ["container", "rm", "-fv", container], {
        timeout: 15_000,
        windowsHide: true,
      });
      const remaining = spawnSync(
        "docker",
        ["container", "ls", "-aq", "--filter", `name=^/${container}$`],
        { encoding: "utf8", timeout: 15_000, windowsHide: true },
      );
      if (remaining.status !== 0 || remaining.stdout.trim())
        error = "docker_cleanup_failed";
    }
    statuses[name] = { exit: result.status, error };
  };
  run("flowguard-version", [
    ...mount(flowguard, "/tool"),
    "--entrypoint",
    "node",
    images.node,
    "/tool/dist/cli.js",
    "--version",
  ]);
  run("node-version", ["--entrypoint", "node", images.node, "--version"]);
  for (const { id, path } of corpus.cases) {
    const target = `/fixtures/${id}.json`;
    run(`flowguard-${id}`, [
      ...mount(flowguard, "/tool"),
      ...mount(path, target),
      "--entrypoint",
      "node",
      images.node,
      "/tool/dist/cli.js",
      "scan",
      target,
      "--json",
    ]);
  }
  run("n8n-version", ["--entrypoint", "n8n", images.n8n, "--version"]);
  run("n8n", [
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=192m,uid=1000,gid=1000",
    "--env",
    "N8N_USER_FOLDER=/tmp/n8n-state",
    "--env",
    "N8N_DIAGNOSTICS_ENABLED=false",
    "--env",
    "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
    "--env",
    "N8N_TEMPLATES_ENABLED=false",
    "--env",
    "N8N_ENFORCE_SETTINGS_FILE_PERMISSIONS=true",
    ...mount(resolve(root, "validation/n8n-audit.sh"), "/suite.sh"),
    ...corpus.cases.flatMap(({ id, path }) =>
      mount(path, `/fixtures/${id}.json`),
    ),
    "--entrypoint",
    "sh",
    images.n8n,
    "/suite.sh",
  ]);
  run("postgres", [
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=48m",
    "--tmpfs",
    "/var/lib/postgresql:rw,nosuid,nodev,size=16m",
    "--user",
    "postgres",
    ...mount(resolve(root, "validation/postgres-control.sh"), "/suite.sh"),
    "--entrypoint",
    "sh",
    images.postgres,
    "/suite.sh",
  ]);
  writeFileSync(
    resolve(directory, "status.json"),
    JSON.stringify(statuses, null, 2) + "\n",
  );
  return summarizeExternal(corpus, directory);
}

export function summarizeExternal(corpus, directory) {
  const status = readJson(resolve(directory, "status.json"));
  const output = (name, stream = "stdout") =>
    readFileSync(resolve(directory, `${name}.${stream}.txt`), "utf8").trim();
  const passed = (name) =>
    status[name]?.exit === 0 && status[name].error === null;
  const flowResults = {};
  for (const { id, workflow } of corpus.cases) {
    const name = `flowguard-${id}`;
    try {
      assert.ok(passed("flowguard-version") && passed("node-version"));
      assert.equal(output("flowguard-version"), "0.2.0");
      assert.equal(output("node-version"), "v20.20.2");
      assert.ok(passed(name));
      const result = JSON.parse(output(name));
      assert.equal(result.files, 1);
      assert.ok(Array.isArray(result.findings));
      for (const { location } of result.findings) {
        assert.equal(location?.workflow, `/fixtures/${id}.json`);
      }
      const signal = result.findings.some(
        ({ ruleId, location }) =>
          ruleId === "missing-input-validation" &&
          location?.nodeType === "n8n-nodes-base.postgres" &&
          workflow.nodes.some(
            (node) =>
              node.id === location.nodeId &&
              node.name === location.nodeName &&
              node.type === location.nodeType,
          ),
      );
      flowResults[id] = signal ? "positive" : "negative";
    } catch {
      flowResults[id] = "failure";
    }
  }

  let sections;
  const control = corpus.cases.find(
    ({ id }) => id === corpus.n8nAuditPositiveControl,
  );
  assert.equal(control?.label, "risk", "n8n audit positive control");
  const controlSink = control.workflow.nodes.find(
    ({ type }) => type === "n8n-nodes-base.postgres",
  );
  let controlObserved = false;
  try {
    assert.ok(passed("n8n-version") && passed("n8n"));
    assert.equal(output("n8n-version"), corpus.n8nVersion);
    assert.ok(
      output("n8n", "stderr").includes(
        `Successfully imported ${corpus.cases.length} workflows.`,
      ),
    );
    const report = output("n8n");
    sections =
      report === "No security issues found"
        ? []
        : JSON.parse(report)["Database Risk Report"].sections;
    assert.ok(Array.isArray(sections));
    for (const section of sections) {
      assert.ok(Array.isArray(section.location));
      for (const {
        workflowName,
        kind,
        nodeId,
        nodeName,
        nodeType,
      } of section.location) {
        const source = corpus.cases.find(
          ({ workflow }) => workflow.name === workflowName,
        );
        assert.ok(source);
        if (section.title === sqlSection || section.title === unusedSection) {
          assert.equal(kind, "node");
          assert.ok(
            source.workflow.nodes.some(
              (node) =>
                node.id === nodeId &&
                node.name === nodeName &&
                node.type === nodeType,
            ),
          );
        }
      }
    }
    controlObserved = sections.some(
      ({ title, location }) =>
        title === sqlSection &&
        location.some(
          ({ kind, workflowName, nodeType, nodeId }) =>
            kind === "node" &&
            workflowName === control.workflow.name &&
            nodeType === controlSink.type &&
            nodeId === controlSink.id,
        ),
    );
    assert.ok(controlObserved, "n8n audit did not report its positive control");
  } catch {
    sections = undefined;
  }
  const n8nResults = (title) =>
    Object.fromEntries(
      corpus.cases.map(({ id, workflow }) => {
        const matching = sections?.some(
          (section) =>
            section.title === title &&
            section.location.some(
              ({ workflowName, nodeType }) =>
                workflowName === workflow.name &&
                nodeType === "n8n-nodes-base.postgres",
            ),
        );
        return [
          id,
          sections ? (matching ? "positive" : "negative") : "failure",
        ];
      }),
    );
  const n8nDirect = n8nResults(sqlSection);
  const n8nUnused = n8nResults(unusedSection);
  const pgLines = output("postgres").split(/\r?\n/);
  const [
    version,
    before,
    constant,
    constantRow,
    first,
    firstRow,
    second,
    secondRow,
    absent,
    after,
  ] = pgLines;
  const expectedRows = [{ label: firstRow }];
  const postgresPass =
    passed("postgres") &&
    version === "18.7" &&
    constant === "constant_id_7" &&
    constantRow === firstRow &&
    first === "normal_id_7" &&
    second === "other_id_9" &&
    secondRow === "pen" &&
    absent === "absent_id_13" &&
    /^before=[0-9a-f]{64}$/.test(before) &&
    after === before.replace("before=", "after=") &&
    pgLines.length === 10 &&
    corpus.behavior.normalInput.id === 7 &&
    corpus.behavior.allowedWrites === 0 &&
    JSON.stringify(expectedRows) ===
      JSON.stringify(corpus.behavior.expectedRows);
  const report = (observations) => ({
    observations,
    metrics: metrics(corpus.cases, observations),
  });
  return {
    corpus: {
      workflows: corpus.cases.length,
      excludedFromBinaryScore: corpus.cases
        .filter(({ label }) => label === "unsupported")
        .map(({ id }) => id),
    },
    n8nPositiveControl: {
      caseId: corpus.n8nAuditPositiveControl,
      passed: controlObserved,
    },
    n8nQueryExpression: report(n8nDirect),
    n8nUnusedParametersProxy: report(n8nUnused),
    flowguardPostgresInputValidationProxy: report(flowResults),
    postgresControl: {
      passed: postgresPass,
      serverVersion: version,
      expectedRows: corpus.behavior.expectedRows,
      constantControlRows: postgresPass ? [{ label: constantRow }] : null,
      observedRows: postgresPass ? expectedRows : null,
      before: before?.split("=")[1] ?? null,
      after: after?.split("=")[1] ?? null,
    },
  };
}
