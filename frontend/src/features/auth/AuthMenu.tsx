import { Button } from '../../shared/ui/Button';
import { Icon } from '../../shared/ui/Icon';
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
        <Button
          variant="secondary"
          size="sm"
          disabled={loading}
          onClick={() => void signOut()}
        >
          <Icon name="logout" size={16} />
          로그아웃
        </Button>
        {error && <span role="alert">{error}</span>}
      </div>
    );
  }
  return (
    <div className="auth-menu">
      <Button size="sm" disabled={loading} onClick={() => void signIn()}>
        <Icon name="login" size={16} />
        {loading ? '확인 중…' : 'Google로 로그인'}
      </Button>
      {error && <span role="alert">{error}</span>}
    </div>
  );
}
