import { Link, NavLink, Outlet } from 'react-router';
import { AuthMenu } from '../features/auth/AuthMenu';
import { Icon } from '../shared/ui/Icon';
import type { IconName } from '../shared/ui/Icon';
import { Backdrop } from './Backdrop';

const NAV: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: '/', label: '홈', icon: 'home', end: true },
  { to: '/workflows', label: '내 워크플로', icon: 'folder', end: true },
  { to: '/workflows/new', label: '등록', icon: 'plus' },
];

export function Layout() {
  return (
    <>
      <Backdrop />
      <div className="shell">
        <header className="topbar">
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
                <span>{item.label}</span>
              </NavLink>
            ))}
          </nav>
          <AuthMenu />
        </header>
        <main className="shell-main">
          <Outlet />
        </main>
      </div>
    </>
  );
}
