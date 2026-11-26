import { describe, expect, it } from 'vitest';
import { filenameFromDisposition } from './download';

describe('filenameFromDisposition', () => {
  it('uses the fallback when the header is missing', () => {
    expect(filenameFromDisposition(null, 'fallback.json')).toBe(
      'fallback.json',
    );
  });

  it('reads a plain quoted file name', () => {
    expect(
      filenameFromDisposition('attachment; filename="flow-v1.json"', 'x.json'),
    ).toBe('flow-v1.json');
  });

  it('decodes an RFC 5987 UTF-8 file name', () => {
    expect(
      filenameFromDisposition(
        "attachment; filename*=UTF-8''%EC%A3%BC%EB%AC%B8-v1.json",
        'x.json',
      ),
    ).toBe('주문-v1.json');
  });

  it('falls back when the encoded name is malformed', () => {
    expect(
      filenameFromDisposition(
        "attachment; filename*=UTF-8''%E0%A4%A",
        'x.json',
      ),
    ).toBe('x.json');
  });
});
