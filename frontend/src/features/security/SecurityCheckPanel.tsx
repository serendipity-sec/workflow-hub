/**
 * Placeholder for the security check result of a version. The security worker is
 * not connected to the service yet, so this must not look like a result: no score,
 * no "safe" badge. Replace the body with the real result once the API exists.
 */
export function SecurityCheckPanel({
  versionLabel,
}: {
  versionLabel?: string;
}) {
  return (
    <section className="panel panel-pending" aria-labelledby="security-heading">
      <h2 id="security-heading">
        보안 검사 <span className="tag">준비 중</span>
      </h2>
      <p>
        {versionLabel ? `${versionLabel}의 ` : ''}보안 검사는 아직 제공하지
        않습니다.
      </p>
      <p className="muted">
        검사 결과가 연결되면 위험 근거(노드·필드 위치)와 수정 안내가 이 영역에
        표시됩니다. 검사 결과가 없다는 것은 안전하다는 뜻이 아닙니다.
      </p>
    </section>
  );
}
