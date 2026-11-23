import { useCallback, useEffect, useState } from 'react';
import type { Page } from './types';

type PagedState<T> = {
  status: 'loading' | 'ready' | 'error';
  items: T[];
  nextCursor: string | null;
  loadingMore: boolean;
  error: unknown;
};

const INITIAL: PagedState<never> = {
  status: 'loading',
  items: [],
  nextCursor: null,
  loadingMore: false,
  error: null,
};

/**
 * Loads the first page on mount and further pages through `loadMore`.
 * `fetchPage` must be referentially stable (wrap it in useCallback);
 * remount with a `key` to load a different list.
 */
export function usePagedList<T>(
  fetchPage: (cursor: string | null) => Promise<Page<T>>,
) {
  const [state, setState] = useState<PagedState<T>>(INITIAL);

  useEffect(() => {
    let cancelled = false;
    fetchPage(null).then(
      (page) =>
        !cancelled &&
        setState({
          status: 'ready',
          items: page.items,
          nextCursor: page.nextCursor,
          loadingMore: false,
          error: null,
        }),
      (error: unknown) =>
        !cancelled && setState({ ...INITIAL, status: 'error', error }),
    );
    return () => {
      cancelled = true;
    };
  }, [fetchPage]);

  const retry = useCallback(() => {
    setState(INITIAL);
    fetchPage(null).then(
      (page) =>
        setState({
          status: 'ready',
          items: page.items,
          nextCursor: page.nextCursor,
          loadingMore: false,
          error: null,
        }),
      (error: unknown) => setState({ ...INITIAL, status: 'error', error }),
    );
  }, [fetchPage]);

  const loadMore = useCallback(() => {
    if (state.status !== 'ready' || !state.nextCursor || state.loadingMore) {
      return;
    }
    const cursor = state.nextCursor;
    setState((current) => ({ ...current, loadingMore: true }));
    fetchPage(cursor).then(
      (page) =>
        setState((current) => ({
          status: 'ready',
          items: [...current.items, ...page.items],
          nextCursor: page.nextCursor,
          loadingMore: false,
          error: null,
        })),
      (error: unknown) =>
        setState((current) => ({
          ...current,
          loadingMore: false,
          error,
        })),
    );
  }, [fetchPage, state]);

  return { state, retry, loadMore };
}
