import { useCallback, useEffect, useRef, useState } from 'react';

export type RequestState<T> =
  | { status: 'loading' }
  | { status: 'ready'; data: T }
  | { status: 'error'; error: unknown };

/**
 * Runs `fetcher` once on mount. `fetcher` must be referentially stable
 * (wrap it in useCallback); remount with a `key` to load something else.
 *
 * Only the newest call may update the state, so an older response can never
 * overwrite a newer one, and nothing is applied after unmount.
 */
export function useRequest<T>(fetcher: () => Promise<T>) {
  const [state, setState] = useState<RequestState<T>>({ status: 'loading' });
  const latestCall = useRef(0);

  // Resolves once the result was applied or dropped; never rejects.
  const run = useCallback(
    (onFailure: (error: unknown) => void): Promise<void> => {
      const call = ++latestCall.current;
      return fetcher().then(
        (data) => {
          if (call === latestCall.current) setState({ status: 'ready', data });
        },
        (error: unknown) => {
          if (call === latestCall.current) onFailure(error);
        },
      );
    },
    [fetcher],
  );

  useEffect(() => {
    const calls = latestCall;
    void run((error) => setState({ status: 'error', error }));
    return () => {
      // Invalidates calls still in flight when unmounting or when `fetcher` changes.
      calls.current++;
    };
  }, [run]);

  const retry = useCallback(() => {
    setState({ status: 'loading' });
    void run((error) => setState({ status: 'error', error }));
  }, [run]);

  /**
   * Reloads without switching to the loading state and keeps the old data while
   * it runs. If the reload fails, the error is shown so stale data is not
   * mistaken for current data. Resolves when the reload has been applied, so a
   * caller can keep its own lock until the page shows the new data.
   */
  const refresh = useCallback(
    () => run((error) => setState({ status: 'error', error })),
    [run],
  );

  return { state, retry, refresh };
}
