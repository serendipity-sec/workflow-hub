import { ButtonLink } from '../shared/ui/Button';
import { Card } from '../shared/ui/Card';

export function NotFoundPage() {
  return (
    <Card className="notice">
      <h1>페이지를 찾을 수 없습니다</h1>
      <p className="muted">주소가 올바른지 확인해 주세요.</p>
      <ButtonLink to="/">처음으로</ButtonLink>
    </Card>
  );
}
