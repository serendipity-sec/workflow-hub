export class ApiError extends Error {
  constructor(public readonly status: number) {
    super(`API request failed (${status})`);
    this.name = 'ApiError';
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
    if (!response.ok) throw new ApiError(response.status);
    return response;
  };
}
