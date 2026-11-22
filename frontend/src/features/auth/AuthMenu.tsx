import { useAuth } from './authContext';

/** Login / logout control shown at the right of the top bar. */
export function AuthMenu() {
  const { configured, loading, session, error, signIn, signOut } = useAuth();

  if (!configured) {
    return <span className="muted">로그인 연결 준비 중</span>;
  }
  if (session) {
    return (
      <div className="auth-menu">
        <span className="auth-user">{session.user.email ?? 'Google 계정'}</span>
        <button
          type="button"
          className="button-secondary"
          disabled={loading}
          onClick={() => void signOut()}
        >
          로그아웃
        </button>
        {error && <span role="alert">{error}</span>}
      </div>
    );
  }
  return (
    <div className="auth-menu">
      <button type="button" disabled={loading} onClick={() => void signIn()}>
        {loading ? '확인 중…' : 'Google로 로그인'}
      </button>
      {error && <span role="alert">{error}</span>}
    </div>
  );
}
