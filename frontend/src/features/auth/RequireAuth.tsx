import { Outlet } from 'react-router';
import { Button } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import { LoadingState } from '../../shared/ui/PageStates';
import { useAuth } from './authContext';

/**
 * Route wrapper for screens that need a signed-in user. This only improves the
 * UI; the server still authorizes every request.
 */
export function RequireAuth() {
  const { configured, loading, session, signIn } = useAuth();

  if (!configured) {
    return (
      <Card className="notice">
        <span className="notice-icon">
          <Icon name="lock" size={22} />
        </span>
        <h1>로그인 연결이 준비되지 않았습니다</h1>
        <p className="muted">
          Supabase 설정(`frontend/.env.local`)이 있어야 로그인할 수 있습니다.
        </p>
      </Card>
    );
  }
  if (loading) return <LoadingState label="로그인 상태를 확인하는 중…" />;
  if (!session) {
    return (
      <Card className="notice">
        <span className="notice-icon">
          <Icon name="lock" size={22} />
        </span>
        <h1>로그인이 필요합니다</h1>
        <p className="muted">
          내 워크플로를 보려면 Google 계정으로 로그인하세요.
        </p>
        <Button onClick={() => void signIn()}>
          <Icon name="login" size={16} />
          Google로 로그인
        </Button>
      </Card>
    );
  }
  return <Outlet />;
}
