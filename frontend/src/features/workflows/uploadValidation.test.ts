import { describe, expect, it } from 'vitest';
import {
  MAX_TITLE_LENGTH,
  MAX_UPLOAD_BYTES,
  validateTitle,
  validateUploadFile,
} from './uploadValidation';

describe('validateUploadFile', () => {
  it('asks for a file when none is chosen', () => {
    expect(validateUploadFile(null)).toMatch(/선택/);
  });

  it('accepts a normal JSON file, regardless of extension case', () => {
    expect(validateUploadFile({ name: 'flow.json', size: 1200 })).toBeNull();
    expect(validateUploadFile({ name: 'FLOW.JSON', size: 1200 })).toBeNull();
  });

  it('rejects other extensions', () => {
    expect(validateUploadFile({ name: 'flow.txt', size: 10 })).toMatch(/json/);
    expect(validateUploadFile({ name: 'flow.json.zip', size: 10 })).toMatch(
      /json/,
    );
  });

  it('rejects empty files', () => {
    expect(validateUploadFile({ name: 'flow.json', size: 0 })).toMatch(/비어/);
  });

  it('allows exactly the limit and rejects one byte above it', () => {
    expect(
      validateUploadFile({ name: 'a.json', size: MAX_UPLOAD_BYTES }),
    ).toBeNull();
    expect(
      validateUploadFile({ name: 'a.json', size: MAX_UPLOAD_BYTES + 1 }),
    ).toMatch(/5 MiB/);
  });
});

describe('validateTitle', () => {
  it('allows an empty title because the server falls back to the JSON name', () => {
    expect(validateTitle('')).toBeNull();
  });

  it('rejects titles over the maximum length', () => {
    expect(validateTitle('a'.repeat(MAX_TITLE_LENGTH))).toBeNull();
    expect(validateTitle('a'.repeat(MAX_TITLE_LENGTH + 1))).toMatch(/200/);
  });

  it('counts code points like the server, so emoji count once', () => {
    expect(validateTitle('😀'.repeat(MAX_TITLE_LENGTH))).toBeNull();
    expect(validateTitle('😀'.repeat(MAX_TITLE_LENGTH + 1))).toMatch(/200/);
  });
});
