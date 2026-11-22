import { WorkerApiClient } from "./api-client.js";
import { runLocal, runRemoteOnce } from "./runner.js";
import {
  parseTask,
  readLocalFile,
  taskBytes,
  WorkerFailure,
} from "./worker-io.js";

async function main(args: string[], signal: AbortSignal): Promise<void> {
  if (args[0] === "local" && args.length === 2 && args[1]) {
    const task = parseTask(await readLocalFile(args[1], taskBytes));
    const result = await runLocal(task, signal);
    process.stdout.write(JSON.stringify(result) + "\n");
    if (result.status === "error") process.exitCode = 1;
    return;
  }

  if (args[0] === "mock-once" && args.length === 1) {
    const api = new WorkerApiClient({
      mode: "mock",
      apiOrigin: process.env.WORKER_API_ORIGIN ?? "",
      fileOrigin: process.env.WORKER_FILE_ORIGIN ?? "",
      token: process.env.WORKER_API_TOKEN ?? "",
    });
    const outcome = await runRemoteOnce(api, { signal });
    process.stdout.write(JSON.stringify(outcome) + "\n");
    if (outcome.status !== "idle" && outcome.result.status === "error")
      process.exitCode = 1;
    return;
  }

  throw new WorkerFailure("invalid_configuration");
}

const abort = new AbortController();
const cancel = () => abort.abort();
process.on("SIGINT", cancel);
process.on("SIGTERM", cancel);
try {
  await main(process.argv.slice(2), abort.signal);
} catch (error) {
  const code = error instanceof WorkerFailure ? error.code : "worker_error";
  process.stderr.write(JSON.stringify({ status: "error", code }) + "\n");
  process.exitCode = code === "cancelled" ? 130 : 1;
} finally {
  process.off("SIGINT", cancel);
  process.off("SIGTERM", cancel);
}
