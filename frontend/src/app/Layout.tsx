import { Link, NavLink, Outlet } from 'react-router';
import { AuthMenu } from '../features/auth/AuthMenu';
import { Icon } from '../shared/ui/Icon';
import type { IconName } from '../shared/ui/Icon';

// `label` is Korean (footer), `short` is the English name used in the top bar.
const NAV: {
  to: string;
  label: string;
  short: string;
  icon: IconName;
  end?: boolean;
}[] = [
  { to: '/', label: '홈', short: 'Home', icon: 'home', end: true },
  {
    to: '/workflows',
    label: '내 워크플로',
    short: 'Workflows',
    icon: 'folder',
    end: true,
  },
  { to: '/workflows/new', label: '등록', short: 'Upload', icon: 'plus' },
];

export function Layout() {
  return (
    <div className="site">
      <header className="topbar">
        <div className="topbar-inner">
          <Link to="/" className="brand">
            <span className="brand-mark">
              <Icon name="layers" size={18} />
            </span>
            <span className="brand-name">Workflow Hub</span>
          </Link>
          <nav aria-label="주 메뉴" className="nav">
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end}>
                <Icon name={item.icon} size={18} />
                <span lang="en">{item.short}</span>
              </NavLink>
            ))}
          </nav>
          <AuthMenu />
        </div>
      </header>
      <main className="site-main">
        <Outlet />
      </main>
      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-about">
            <Link to="/" className="brand">
              <span className="brand-mark">
                <Icon name="layers" size={18} />
              </span>
              <span>Workflow Hub</span>
            </Link>
            <p className="muted">
              n8n 워크플로를 버전별로 보관하고 원본 그대로 내려받는
              서비스입니다.
            </p>
          </div>
          <nav aria-label="바닥글 메뉴" className="footer-nav">
            {NAV.map((item) => (
              <Link key={item.to} to={item.to}>
                {item.label}
              </Link>
            ))}
          </nav>
          <p className="muted footer-note">© Workflow Hub</p>
        </div>
      </footer>
    </div>
  );
}
