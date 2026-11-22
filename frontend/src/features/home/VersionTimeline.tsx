const ROWS = [
  { label: 'v2', note: '주요 수정', latest: true },
  { label: 'v1.1', note: '작은 수정', latest: false },
  { label: 'v1', note: '최초 등록', latest: false },
];

/**
 * Small illustration of how versions stack up. It is a static picture, not a
 * live control: the rows are examples and nothing here calls the API.
 */
export function VersionTimeline() {
  return (
    <div
      className="timeline"
      role="img"
      aria-label="버전이 v1, v1.1, v2로 쌓이는 예시"
    >
      <span className="timeline-tag">예시</span>
      <ol className="timeline-rows">
        {ROWS.map((row) => (
          <li key={row.label} className={row.latest ? 'is-latest' : undefined}>
            <span className="timeline-dot" />
            <strong>{row.label}</strong>
            <span className="muted">{row.note}</span>
            <span className="timeline-file">.json</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
