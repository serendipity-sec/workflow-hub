import { Button } from '../../shared/ui/Button';
import { Icon } from '../../shared/ui/Icon';
import { useAuth } from './authContext';

/** Right end of the top bar: login, or e-mail and logout. */
export function AuthMenu() {
  const { configured, loading, session, error, signIn, signOut } = useAuth();

  if (!configured) {
    return <p className="muted auth-note">로그인 연결 준비 중</p>;
  }
  if (session) {
    const email = session.user.email ?? 'Google 계정';
    return (
      <div className="profile">
        <div className="profile-who">
          <span className="avatar" aria-hidden="true">
            {email.charAt(0).toUpperCase()}
          </span>
          <span className="profile-email">{email}</span>
        </div>
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
    <div className="profile">
      <Button size="sm" disabled={loading} onClick={() => void signIn()}>
        <Icon name="login" size={16} />
        {loading ? '확인 중…' : 'Google로 로그인'}
      </Button>
      {error && <span role="alert">{error}</span>}
    </div>
  );
}
