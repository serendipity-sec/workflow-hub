import { createClient } from '@supabase/supabase-js';
import { readAuthConfig } from './config';

const config = readAuthConfig(import.meta.env);

// Singleton: one SDK owns persistence, refresh scheduling and token rotation.
// SPA tradeoff: SDK tokens persist in browser storage; never log them or inject HTML.
export const supabase = config
  ? createClient(config.url, config.publishableKey, {
      auth: {
        flowType: 'pkce',
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null;
