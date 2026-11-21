import { AuthPanel } from '../features/auth/AuthPanel';
import { WorkflowIntro } from '../features/workflows/WorkflowIntro';

export function App() {
  return (
    <main>
      <header>
        <p className="eyebrow">WORKFLOW HUB</p>
        <h1>자동화를 기록하고, 이어가세요.</h1>
        <p>n8n 워크플로와 수정 계보를 위한 팀 프로젝트</p>
      </header>
      <div className="grid">
        <WorkflowIntro />
        <AuthPanel />
      </div>
    </main>
  );
}
