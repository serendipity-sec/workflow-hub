import { describe, expect, it } from 'vitest';
import { readAuthConfig } from './config';

const key = 'sb_publishable_example';
describe('public auth configuration', () => {
  it('keeps unconfigured development usable', () => {
    expect(readAuthConfig({})).toBeNull();
    expect(
      readAuthConfig({
        VITE_SUPABASE_URL: '',
        VITE_SUPABASE_PUBLISHABLE_KEY: '',
      }),
    ).toBeNull();
  });
  it('accepts HTTPS and local Supabase development', () => {
    for (const url of [
      'https://example.supabase.co',
      'http://127.0.0.1:54321',
    ]) {
      expect(
        readAuthConfig({
          VITE_SUPABASE_URL: url,
          VITE_SUPABASE_PUBLISHABLE_KEY: key,
        }),
      ).toEqual({ url, publishableKey: key });
    }
  });
  it('rejects invalid URLs, remote plaintext transport and embedded credentials', () => {
    for (const url of [
      'invalid',
      'http://example.com',
      'https://user:password@example.com',
      'javascript:alert(1)',
    ]) {
      expect(
        readAuthConfig({
          VITE_SUPABASE_URL: url,
          VITE_SUPABASE_PUBLISHABLE_KEY: key,
        }),
      ).toBeNull();
    }
  });
  it('rejects secret keys in client configuration', () => {
    expect(
      readAuthConfig({
        VITE_SUPABASE_URL: 'https://example.supabase.co',
        VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_secret_example',
      }),
    ).toBeNull();
  });
});
