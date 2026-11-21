export type AuthConfig = { url: string; publishableKey: string };

export function readAuthConfig(
  env: Record<string, unknown>,
): AuthConfig | null {
  const url = env.VITE_SUPABASE_URL;
  const publishableKey = env.VITE_SUPABASE_PUBLISHABLE_KEY;
  if (typeof url !== 'string' || typeof publishableKey !== 'string')
    return null;
  if (!url.trim() || !publishableKey.trim()) return null;
  try {
    const parsed = new URL(url);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (
      parsed.protocol !== 'https:' &&
      !(local && parsed.protocol === 'http:')
    ) {
      return null;
    }
    if (parsed.username || parsed.password) return null;
  } catch {
    return null;
  }
  if (!publishableKey.startsWith('sb_publishable_')) return null;
  return { url: url.trim(), publishableKey: publishableKey.trim() };
}
