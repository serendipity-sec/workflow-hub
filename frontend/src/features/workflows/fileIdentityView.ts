/** How the stored original file of a version is identified, as the server recorded it. */
export type FileIdentityView =
  | { known: true; sha256: string; shortHash: string; size: string }
  | { known: false };

const SHORT_HASH_LENGTH = 12;
const UNITS = ['B', 'KiB', 'MiB', 'GiB'] as const;

/** Binary units, like the upload limit ("5 MiB"). One decimal place above bytes. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes.toLocaleString('ko-KR')} B`;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  let rounded = Math.round(value * 10) / 10;
  // Rounding can reach the next unit, e.g. 1023.99 KiB → 1 MiB, not "1024 KiB".
  if (rounded >= 1024 && unit < UNITS.length - 1) {
    rounded = Math.round((rounded / 1024) * 10) / 10;
    unit += 1;
  }
  return `${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)} ${UNITS[unit]}`;
}

/** The first characters are enough to tell files apart at a glance; copy gives the rest. */
export function shortHash(sha256: string): string {
  return sha256.length > SHORT_HASH_LENGTH
    ? `${sha256.slice(0, SHORT_HASH_LENGTH)}…`
    : sha256;
}

/**
 * Shows only what the server recorded. The server stores both values or
 * neither, so a missing one means the file identity is unknown.
 */
export function describeFileIdentity(version: {
  sha256: string | null;
  sizeBytes: number | null;
}): FileIdentityView {
  const { sha256, sizeBytes } = version;
  if (!sha256 || sizeBytes === null || sizeBytes === undefined) {
    return { known: false };
  }
  return {
    known: true,
    sha256,
    shortHash: shortHash(sha256),
    size: formatBytes(sizeBytes),
  };
}

type Clipboard = { writeText?: (text: string) => Promise<void> } | undefined;

/** Whether the browser offers copying at all (it does not on plain http, for example). */
export function canCopy(clipboard: Clipboard): boolean {
  return typeof clipboard?.writeText === 'function';
}

/** Copies `text`; a refused permission is a failure, never a thrown error. */
export async function copyText(
  clipboard: Clipboard,
  text: string,
): Promise<'copied' | 'failed'> {
  const write = clipboard?.writeText;
  if (typeof write !== 'function') return 'failed';
  try {
    // Called on the clipboard object itself, as the browser requires.
    await write.call(clipboard, text);
    return 'copied';
  } catch {
    return 'failed';
  }
}
