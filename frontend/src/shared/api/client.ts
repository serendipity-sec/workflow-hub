/**
 * Failed API response. Only the status, the machine-readable `code` and the
 * `requestId` are kept; the response body itself is never exposed to the UI.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code?: string,
    public readonly requestId?: string,
  ) {
    super(`API request failed (${status})`);
    this.name = 'ApiError';
  }
}

const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;
const REQUEST_ID_PATTERN = /^[\w-]{1,100}$/;

/** Reads `{ code, requestId }` from an error body; malformed bodies yield nothing. */
async function readErrorDetails(
  response: Response,
): Promise<{ code?: string; requestId?: string }> {
  try {
    const body: unknown = JSON.parse(await response.text());
    if (typeof body !== 'object' || body === null) return {};
    const { code, requestId } = body as Record<string, unknown>;
    return {
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
      const { code, requestId } = await readErrorDetails(response);
      throw new ApiError(response.status, code, requestId);
    }
    return response;
  };
}
