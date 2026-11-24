/**
 * Failed API response. Only the status, the machine-readable `code` and the
 * `requestId` are kept; the response body itself is never exposed to the UI.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code?: string,
    public readonly requestId?: string,
    /** Only set by `409 LATEST_VERSION_CHANGED`: the version that is newest now. */
    public readonly latestVersion?: LatestVersion,
  ) {
    super(`API request failed (${status})`);
    this.name = 'ApiError';
  }
}

export type LatestVersion = { versionId: string; versionLabel: string };

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERSION_LABEL_PATTERN = /^v\d{1,6}(\.\d{1,6})?$/;
const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;
const REQUEST_ID_PATTERN = /^[\w-]{1,100}$/;

function readLatestVersion(details: unknown): LatestVersion | undefined {
  if (typeof details !== 'object' || details === null) return undefined;
  const latest = (details as Record<string, unknown>).latestVersion;
  if (typeof latest !== 'object' || latest === null) return undefined;
  const { versionId, versionLabel } = latest as Record<string, unknown>;
  return typeof versionId === 'string' &&
    UUID_PATTERN.test(versionId) &&
    typeof versionLabel === 'string' &&
    VERSION_LABEL_PATTERN.test(versionLabel)
    ? { versionId, versionLabel }
    : undefined;
}

/** Reads `{ code, requestId }` from an error body; malformed bodies yield nothing. */
async function readErrorDetails(response: Response): Promise<{
  code?: string;
  requestId?: string;
  latestVersion?: LatestVersion;
}> {
  try {
    const body: unknown = JSON.parse(await response.text());
    if (typeof body !== 'object' || body === null) return {};
    const { code, requestId, details } = body as Record<string, unknown>;
    return {
      latestVersion: readLatestVersion(details),
      code:
        typeof code === 'string' && ERROR_CODE_PATTERN.test(code)
          ? code
          : undefined,
      requestId:
        typeof requestId === 'string' && REQUEST_ID_PATTERN.test(requestId)
          ? requestId
          : undefined,
    };
  } catch {
    return {};
  }
}

export function createApiClient(
  getAccessToken: () => Promise<string | null>,
  fetcher: typeof fetch = fetch,
) {
  return async (path: string, init: RequestInit = {}): Promise<Response> => {
    // Keep bearer tokens on our API origin and prohibit redirect forwarding.
    if (!path.startsWith('/api/') || path.includes('\\')) {
      throw new Error('Only same-origin /api/ paths are allowed');
    }
    const token = await getAccessToken();
    if (!token) throw new ApiError(401);
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${token}`);
    const response = await fetcher(path, {
      ...init,
      headers,
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
    });
    // No independent refresh/retry loop: Supabase owns token refresh.
    if (!response.ok) {
      const { code, requestId, latestVersion } =
        await readErrorDetails(response);
      throw new ApiError(response.status, code, requestId, latestVersion);
    }
    return response;
  };
}
