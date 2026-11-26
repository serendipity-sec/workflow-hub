/** Picks the file name out of a Content-Disposition header, or returns the fallback. */
export function filenameFromDisposition(
  header: string | null,
  fallback: string,
): string {
  if (!header) return fallback;
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (encoded) {
    try {
      return decodeURIComponent(encoded[1].trim());
    } catch {
      return fallback;
    }
  }
  const plain = /filename="?([^";]+)"?/i.exec(header);
  return plain ? plain[1].trim() : fallback;
}

/** Saves a successful response body as a file through the browser. */
export async function saveResponseAsFile(
  response: Response,
  fallbackName: string,
): Promise<void> {
  const filename = filenameFromDisposition(
    response.headers.get('Content-Disposition'),
    fallbackName,
  );
  const url = URL.createObjectURL(await response.blob());
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}
