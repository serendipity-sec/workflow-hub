import { limits } from "./contract.js";
import type { Result, Task } from "./contract.js";
import {
  checkActive,
  parseTask,
  sha256,
  taskBytes,
  validateResult,
  WorkerFailure,
} from "./worker-io.js";
import type { WorkerCode } from "./worker-io.js";
import { setTimeout as sleep } from "node:timers/promises";

type ClientConfig = {
  apiOrigin: string;
  fileOrigin: string;
  token: string;
  mode?: "team" | "mock";
};
export type Submission = "accepted" | "duplicate";

const retryableStatuses = new Set([429, 502, 503, 504]);

function configuredOrigin(value: string, mockOnly: boolean): string {
  try {
    const url = new URL(value);
    if (
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    )
      throw Error();
    if (mockOnly) {
      // Require the literal spelling as configured, not hostname or normalized alternate IPv4 spellings.
      if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/.test(value))
        throw Error();
    } else if (url.protocol !== "https:") {
      throw Error();
    }
    return url.origin;
  } catch {
    throw new WorkerFailure("invalid_configuration");
  }
}

async function responseBytes(
  response: Response,
  limit: number,
  tooLarge: WorkerCode,
): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);

  const reader = response.body.getReader();
  try {
    const announced = response.headers.get("content-length");
    if (announced !== null && Number(announced) > limit)
      throw new WorkerFailure(tooLarge);
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.length;
      if (total > limit) throw new WorkerFailure(tooLarge);
      chunks.push(part.value);
    }
    return Buffer.concat(chunks, total);
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function rejectApiStatus(status: number): never {
  if (status === 401 || status === 403)
    throw new WorkerFailure("auth_rejected");
  if (status === 409) throw new WorkerFailure("lease_rejected");
  if (status === 410) throw new WorkerFailure("lease_expired");
  if (retryableStatuses.has(status)) throw new WorkerFailure("api_retryable");
  throw new WorkerFailure("api_protocol");
}

function retryDelay(value: string | null): number {
  if (value === null) return 100;
  if (/^[0-9]+$/.test(value)) return Number(value) * 1_000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 100;
}

export class WorkerApiClient {
  readonly mockOnly: boolean;
  readonly #apiOrigin: string;
  readonly #fileOrigin: string;
  readonly #token: string;

  constructor(config: ClientConfig) {
    this.mockOnly = config.mode === "mock";
    this.#apiOrigin = configuredOrigin(config.apiOrigin, this.mockOnly);
    this.#fileOrigin = configuredOrigin(config.fileOrigin, this.mockOnly);
    if (!/^[\x21-\x7e]{1,4096}$/.test(config.token)) {
      throw new WorkerFailure("invalid_configuration");
    }
    this.#token = config.token;
  }

  async claim(signal?: AbortSignal): Promise<Task | null> {
    return this.#request(
      `${this.#apiOrigin}/internal/worker/v1/claim`,
      { method: "POST", headers: { Authorization: `Bearer ${this.#token}` } },
      async (response) => {
        if (response.status === 204) return null;
        if (response.status !== 200) rejectApiStatus(response.status);
        const task = parseTask(
          await responseBytes(response, taskBytes, "invalid_task"),
        );
        if (task.file.kind !== "download")
          throw new WorkerFailure("invalid_task");
        return task;
      },
      signal,
    );
  }

  async download(task: Task, signal?: AbortSignal): Promise<Buffer> {
    if (task.file.kind !== "download") throw new WorkerFailure("invalid_task");
    const url = new URL(task.file.url);
    if (
      url.origin !== this.#fileOrigin ||
      url.protocol !== (this.mockOnly ? "http:" : "https:") ||
      url.username ||
      url.password ||
      url.hash
    ) {
      throw new WorkerFailure("file_access");
    }

    try {
      return await this.#request(
        url.href,
        { method: "GET", headers: { "Accept-Encoding": "identity" } },
        async (response) => {
          if (response.status === 404)
            throw new WorkerFailure("file_not_found");
          if (response.status !== 200) throw new WorkerFailure("file_access");
          const encoding = response.headers.get("content-encoding");
          if (encoding && encoding.toLowerCase() !== "identity") {
            throw new WorkerFailure("file_access");
          }
          return responseBytes(response, limits.fileBytes, "file_too_large");
        },
        signal,
        Date.parse(task.leaseExpiresAt),
      );
    } catch (error) {
      if (
        error instanceof WorkerFailure &&
        (error.code === "api_unreachable" || error.code === "api_timeout")
      ) {
        throw new WorkerFailure("file_access");
      }
      throw error;
    }
  }

  async submit(
    task: Task,
    result: Result,
    signal?: AbortSignal,
  ): Promise<Submission> {
    const path = `/internal/worker/v1/tasks/${encodeURIComponent(task.taskId)}/attempts/${encodeURIComponent(task.attemptId)}/result`;
    const body = JSON.stringify(validateResult(result, task));
    if (Buffer.byteLength(body) > limits.resultBytes)
      throw new WorkerFailure("analyzer_output_limit");
    const leaseEnd = Date.parse(task.leaseExpiresAt);
    const headers = {
      Authorization: `Bearer ${this.#token}`,
      "Content-Type": "application/json",
      "Idempotency-Key": sha256(Buffer.from(body)),
    };
    const send = async () => {
      try {
        return await this.#request(
          this.#apiOrigin + path,
          { method: "PUT", body, headers },
          async (response) => {
            const { status } = response;
            if (retryableStatuses.has(status)) {
              return {
                retryIn: retryDelay(response.headers.get("retry-after")),
                code: "api_retryable",
              } as const;
            }
            if (status !== 200 && status !== 201) rejectApiStatus(status);
            await responseBytes(response, 0, "api_protocol");
            return status === 201 ? "accepted" : "duplicate";
          },
          signal,
          leaseEnd,
        );
      } catch (error) {
        if (
          error instanceof WorkerFailure &&
          (error.code === "api_timeout" || error.code === "api_unreachable")
        ) {
          return { retryIn: 100, code: error.code } as const;
        }
        throw error;
      }
    };

    const first = await send();
    if (typeof first === "string") return first;
    if (
      first.retryIn > 2_147_483_647 ||
      Date.now() + first.retryIn >= leaseEnd
    ) {
      throw new WorkerFailure(first.code);
    }
    try {
      await sleep(first.retryIn, undefined, { signal });
    } catch {
      throw new WorkerFailure("cancelled");
    }
    const second = await send();
    if (typeof second === "string") return second;
    throw new WorkerFailure(second.code);
  }

  async #request<T>(
    url: string,
    init: RequestInit,
    handle: (response: Response) => Promise<T>,
    signal?: AbortSignal,
    leaseEnd = Infinity,
  ): Promise<T> {
    checkActive(signal, leaseEnd);
    const remainingLeaseMs = leaseEnd - Date.now();
    // A relative timer may fire just before Date.now() reaches the deadline.
    // Preserve which deadline bounded this request instead of retrying an expired lease.
    const timeoutCode =
      remainingLeaseMs <= limits.apiTimeoutMs ? "lease_expired" : "api_timeout";
    const timeout = AbortSignal.timeout(
      Math.max(1, Math.min(limits.apiTimeoutMs, remainingLeaseMs)),
    );
    const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
    try {
      const response = await fetch(url, {
        ...init,
        signal: requestSignal,
        redirect: "manual",
      });
      try {
        const value = await handle(response);
        checkActive(signal, leaseEnd);
        if (timeout.aborted) throw new WorkerFailure(timeoutCode);
        return value;
      } finally {
        await response.body?.cancel().catch(() => undefined);
      }
    } catch (error) {
      if (error instanceof WorkerFailure) throw error;
      checkActive(signal, leaseEnd);
      throw new WorkerFailure(
        timeout.aborted ? timeoutCode : "api_unreachable",
      );
    }
  }
}
