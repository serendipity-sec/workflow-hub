/** Every successful JSON response is wrapped as `{ data: ... }`. */
export type DataEnvelope<T> = { data: T };

/** Cursor-paged list. `nextCursor` is null on the last page. */
export type Page<T> = { items: T[]; nextCursor: string | null };

export async function readData<T>(response: Response): Promise<T> {
  const body = (await response.json()) as DataEnvelope<T>;
  return body.data;
}
