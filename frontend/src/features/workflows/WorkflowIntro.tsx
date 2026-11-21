export function WorkflowIntro() {
  return (
    <section className="panel" aria-labelledby="workflow-heading">
      <span className="tag">개발 준비 버전</span>
      <h2 id="workflow-heading">워크플로의 다음 버전을 함께 만들어요.</h2>
      <p>
        n8n 워크플로를 업로드하고, 수정본의 계보를 확인하며, 필요한 버전을
        내려받는 공간을 만들고 있습니다.
      </p>
      <p className="muted">
        현재는 프로젝트 기본 구조와 로그인 연결을 준비한 단계입니다. 업로드,
        리비전 관리, 다운로드는 아직 제공하지 않습니다.
      </p>
    </section>
  );
}
