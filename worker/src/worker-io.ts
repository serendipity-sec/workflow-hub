import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { identityOf, resultSchema, taskSchema } from "./contract.js";
import type { ErrorCode, Identity, Result, Task } from "./contract.js";

export type WorkerCode =
  | ErrorCode
  | "invalid_task"
  | "invalid_configuration"
  | "auth_rejected"
  | "lease_rejected"
  | "lease_expired"
  | "api_protocol"
  | "api_unreachable"
  | "api_timeout"
  | "api_retryable";

export class WorkerFailure extends Error {
  constructor(public readonly code: WorkerCode) {
    super(code);
  }
}

export const taskBytes = 16 * 1024;

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parseJson(bytes: Uint8Array): unknown {
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(decoded) as unknown;
}

export function parseTask(bytes: Uint8Array): Task {
  try {
    return taskSchema.parse(parseJson(bytes));
  } catch {
    throw new WorkerFailure("invalid_task");
  }
}

export function validateResult(value: unknown, identity: Identity): Result {
  const result = resultSchema.safeParse(value);
  if (
    !result.success ||
    JSON.stringify(identityOf(result.data)) !==
      JSON.stringify(identityOf(identity))
  ) {
    throw new WorkerFailure("invalid_result");
  }
  return result.data;
}

export function checkActive(signal?: AbortSignal, leaseEnd = Infinity): void {
  if (signal?.aborted) throw new WorkerFailure("cancelled");
  if (Date.now() >= leaseEnd) throw new WorkerFailure("lease_expired");
}

export async function readLocalFile(
  path: string,
  limit: number,
): Promise<Buffer> {
  try {
    const file = await open(
      path,
      constants.O_RDONLY | (constants.O_NONBLOCK ?? 0),
    );
    try {
      const stat = await file.stat();
      if (!stat.isFile()) throw new WorkerFailure("file_access");
      if (stat.size > limit) throw new WorkerFailure("file_too_large");

      const bytes = Buffer.alloc(limit + 1);
      let offset = 0;
      while (offset < bytes.length) {
        const read = await file.read(
          bytes,
          offset,
          bytes.length - offset,
          null,
        );
        if (!read.bytesRead) break;
        offset += read.bytesRead;
      }
      if (offset > limit) throw new WorkerFailure("file_too_large");
      return bytes.subarray(0, offset);
    } finally {
      await file.close();
    }
  } catch (error) {
    if (error instanceof WorkerFailure) throw error;
    const code = (error as NodeJS.ErrnoException).code;
    throw new WorkerFailure(
      code === "ENOENT" ? "file_not_found" : "file_access",
    );
  }
}
