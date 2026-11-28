import { describe, expect, it } from 'vitest';
import {
  canCopy,
  copyText,
  describeFileIdentity,
  formatBytes,
  shortHash,
} from './fileIdentityView';

const HASH = '3c700c2454485bca511c63f2fdb89dbbde0dc674c08ef0f8a1c1dcc3201ae3f8';

describe('formatBytes', () => {
  it('keeps small files in bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(52)).toBe('52 B');
    expect(formatBytes(1023)).toBe('1,023 B');
  });

  it('uses binary units with at most one decimal place', () => {
    expect(formatBytes(1024)).toBe('1 KiB');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5 MiB');
    expect(formatBytes(1_258_291)).toBe('1.2 MiB');
  });

  it('moves to the next unit when rounding reaches it', () => {
    expect(formatBytes(1_048_575)).toBe('1 MiB');
    expect(formatBytes(1_048_000)).toBe('1023.4 KiB');
  });
});

describe('shortHash', () => {
  it('keeps the first 12 characters', () => {
    expect(shortHash(HASH)).toBe('3c700c245448…');
  });

  it('leaves short values as they are', () => {
    expect(shortHash('abc')).toBe('abc');
  });
});

describe('describeFileIdentity', () => {
  it('shows the recorded hash and size', () => {
    expect(describeFileIdentity({ sha256: HASH, sizeBytes: 52 })).toEqual({
      known: true,
      sha256: HASH,
      shortHash: '3c700c245448…',
      size: '52 B',
    });
  });

  it('is unknown for versions registered before the values were recorded', () => {
    expect(describeFileIdentity({ sha256: null, sizeBytes: null })).toEqual({
      known: false,
    });
  });

  it('never shows half of the identity', () => {
    expect(describeFileIdentity({ sha256: HASH, sizeBytes: null })).toEqual({
      known: false,
    });
    expect(describeFileIdentity({ sha256: null, sizeBytes: 52 })).toEqual({
      known: false,
    });
  });
});

describe('copyText', () => {
  it('reports a successful copy of the exact value', async () => {
    const written: string[] = [];
    const clipboard = {
      writeText: (text: string) => {
        written.push(text);
        return Promise.resolve();
      },
    };
    await expect(copyText(clipboard, HASH)).resolves.toBe('copied');
    expect(written).toEqual([HASH]);
  });

  it('turns a refused permission into a failure', async () => {
    const clipboard = {
      writeText: () =>
        Promise.reject(new DOMException('denied', 'NotAllowedError')),
    };
    await expect(copyText(clipboard, HASH)).resolves.toBe('failed');
  });

  it('fails without throwing when there is no clipboard', async () => {
    await expect(copyText(undefined, HASH)).resolves.toBe('failed');
    expect(canCopy(undefined)).toBe(false);
    expect(canCopy({})).toBe(false);
    expect(canCopy({ writeText: () => Promise.resolve() })).toBe(true);
  });
});
