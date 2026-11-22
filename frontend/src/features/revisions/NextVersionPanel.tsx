import { Card } from '../../shared/ui/Card';
import { Tag } from '../../shared/ui/Tag';

/**
 * Placeholder for "compare a modified file and register the next version".
 * The backend API is still in development; replace the body when it is merged.
 */
export function NextVersionPanel() {
  return (
    <Card tone="pending" aria-labelledby="next-version-heading">
      <h2 id="next-version-heading">
        새 버전 등록 <Tag tone="outline">준비 중</Tag>
      </h2>
      <p>
        수정한 JSON을 최신 버전과 비교한 뒤 새 버전으로 등록하는 기능입니다.
      </p>
      <p className="muted">
        작은 수정은 v1.1, 큰 수정은 v2처럼 번호가 올라가며, 이전 버전은 그대로
        내려받을 수 있습니다. 아직 제공하지 않습니다.
      </p>
    </Card>
  );
}
