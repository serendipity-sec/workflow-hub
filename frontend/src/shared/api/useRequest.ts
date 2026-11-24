import { useCallback, useEffect, useState } from 'react';

export type RequestState<T> =
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'error'; error: unknown };

/**
 * Runs `fetcher` once on mount. `fetcher` must be referentially stable
 * (wrap it in useCallback); remount with a `key` to load something else.
 */
export function useRequest<T>(fetcher: () => Promise<T>) {
  const [state, setState] = useState<RequestState<T>>({ status: 'loading' });

  useEffect(() => {
    let cancelled = false;
    fetcher().then(
      (data) => !cancelled && setState({ status: 'ready', data }),
      (error: unknown) => !cancelled && setState({ status: 'error', error }),
    );
    return () => {
      cancelled = true;
    };
  }, [fetcher]);

  const retry = useCallback(() => {
    setState({ status: 'loading' });
    fetcher().then(
      (data) => setState({ status: 'ready', data }),
      (error: unknown) => setState({ status: 'error', error }),
    );
  }, [fetcher]);

  /** Reloads without switching to the loading state; keeps old data on failure. */
  const refresh = useCallback(() => {
    fetcher().then(
      (data) => setState({ status: 'ready', data }),
      () => undefined,
    );
  }, [fetcher]);

  return { state, retry, refresh };
}
