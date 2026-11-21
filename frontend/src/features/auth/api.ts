import { createApiClient } from '../../shared/api/client';
import { supabase } from './client';

export const authenticatedFetch = createApiClient(async () => {
  if (!supabase) return null;
  const { data, error } = await supabase.auth.getSession();
  if (error) return null;
  return data.session?.access_token ?? null;
});
