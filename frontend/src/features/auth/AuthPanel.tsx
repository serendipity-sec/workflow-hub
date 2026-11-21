import { useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';
import { supabase } from './client';

export function AuthPanel() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(Boolean(supabase));
  const [error, setError] = useState('');

  useEffect(() => {
    if (!supabase) return;
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setLoading(false);
    });
    return () => data.subscription.unsubscribe();
  }, []);

  async function signIn() {
    if (!supabase) return;
    setLoading(true);
    setError('');
    try {
      const result = await supabase.auth.signInWithOAuth({
        provider: 'google',
        options: { redirectTo: window.location.origin },
      });
      if (result.error) throw result.error;
    } catch {
      setError('로그인을 시작하지 못했습니다. 잠시 후 다시 시도해 주세요.');
      setLoading(false);
    }
  }

  async function signOut() {
    if (!supabase) return;
    setLoading(true);
    setError('');
    try {
      const result = await supabase.auth.signOut({ scope: 'local' });
      if (result.error) throw result.error;
    } catch {
      setError('로그아웃에 실패했습니다. 다시 시도해 주세요.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="account-heading">
      <h2 id="account-heading">내 계정</h2>
      {!supabase ? (
        <p>로그인 연결이 아직 준비되지 않았습니다.</p>
      ) : session ? (
        <>
          <p>{session.user.email ?? 'Google 계정'}으로 로그인했습니다.</p>
          <button disabled={loading} onClick={() => void signOut()}>
            로그아웃
          </button>
        </>
      ) : (
        <button disabled={loading} onClick={() => void signIn()}>
          {loading ? '로그인 확인 중…' : 'Google로 로그인'}
        </button>
      )}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
