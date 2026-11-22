import { Link, NavLink, Outlet } from 'react-router';
import { AuthMenu } from '../features/auth/AuthMenu';

export function Layout() {
  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <Link to="/" className="brand">
            Workflow Hub
          </Link>
          <nav aria-label="주 메뉴" className="nav">
            <NavLink to="/workflows" end>
              내 워크플로
            </NavLink>
            <NavLink to="/workflows/new">등록</NavLink>
          </nav>
          <AuthMenu />
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </>
  );
}
