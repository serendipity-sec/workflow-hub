import { Link } from 'react-router';

export function NotFoundPage() {
  return (
    <section className="panel">
      <h1>페이지를 찾을 수 없습니다</h1>
      <p className="muted">주소가 올바른지 확인해 주세요.</p>
      <Link to="/">처음으로</Link>
    </section>
  );
}
