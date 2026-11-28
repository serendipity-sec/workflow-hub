import { Icon } from '../../shared/ui/Icon';
import { Tag } from '../../shared/ui/Tag';

const ROWS = [
  { version: 'v2', note: '큰 수정', latest: true },
  { version: 'v1.1', note: '작은 수정', latest: false },
  { version: 'v1', note: '최초 등록', latest: false },
];

/**
 * A window showing what the workflow detail screen looks like: one workflow
 * with its versions, each with a download. It is a static picture, not a live
 * control: the names are made up and nothing here calls the API.
 */
export function VersionTimeline({ className }: { className?: string }) {
  return (
    <div
      className={['preview', className].filter(Boolean).join(' ')}
      role="img"
      aria-label="워크플로 상세 화면 예시: 버전 v2, v1.1, v1이 쌓이고 버전마다 원본을 받을 수 있습니다"
    >
      <div className="preview-bar" aria-hidden="true">
        <span className="preview-dots">
          <i />
          <i />
          <i />
        </span>
        <span className="preview-title">워크플로 상세 · 예시 화면</span>
      </div>
      <div className="preview-body" aria-hidden="true">
        <div className="preview-head">
          <span className="preview-file">
            <Icon name="file" size={20} />
          </span>
          <div>
            <strong>daily-report.json</strong>
            <span className="muted">버전 3개 · 최신 v2</span>
          </div>
          <span className="preview-new">
            <Icon name="plus" size={14} />새 버전 등록
          </span>
        </div>
        <ol className="preview-rows">
          {ROWS.map((row) => (
            <li
              key={row.version}
              className={row.latest ? 'is-latest' : undefined}
            >
              <strong className="preview-version">{row.version}</strong>
              <span className="muted">{row.note}</span>
              {row.latest && <Tag tone="dark">최신</Tag>}
              <span className="preview-get">
                <Icon name="download" size={15} />
                원본 받기
              </span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}
