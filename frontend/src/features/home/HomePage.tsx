import { Link } from 'react-router';
import { VersionTimeline } from './VersionTimeline';
import './home.css';

type Step = { title: string; description: string; available: boolean };

// Keep `available` honest: only what the running service really provides.
const STEPS: Step[] = [
  {
    title: '등록',
    description: 'n8n에서 내보낸 JSON 파일을 올리면 v1로 저장됩니다.',
    available: true,
  },
  {
    title: '버전 이력과 다운로드',
    description: '버전마다 등록 당시의 원본을 그대로 내려받습니다.',
    available: true,
  },
  {
    title: '변경점 비교와 새 버전',
    description: '수정본을 최신 버전과 비교하고 v1.1이나 v2로 등록합니다.',
    available: false,
  },
  {
    title: '보안 검사와 수정 안내',
    description: '위험 근거를 확인하고 고친 파일을 다시 검사합니다.',
    available: false,
  },
];

const FACTS = [
  {
    title: '버전 번호는 서버가 매깁니다',
    body: '새 워크플로는 v1, 작은 수정은 v1.1, 큰 수정은 v2로 올라갑니다.',
  },
  {
    title: '원본을 고치지 않습니다',
    body: '한 번 등록한 버전의 파일은 바뀌지 않고, 그대로 내려받을 수 있습니다.',
  },
  {
    title: '올린 파일은 실행하지 않습니다',
    body: '워크플로와 Code 노드는 서버에서 실행하지 않고 파일로만 보관합니다.',
  },
];

export function HomePage() {
  return (
    <div className="home">
      <header className="home-hero">
        <div className="home-hero-text enter">
          <p className="eyebrow">WORKFLOW HUB</p>
          <h1>n8n 워크플로를 버전별로 보관하고, 원본 그대로 내려받으세요.</h1>
          <p className="home-lead">
            수정할 때마다 새 버전으로 남기면, 이전 버전도 언제든 같은 파일로
            받을 수 있습니다.
          </p>
          <div className="home-actions">
            <Link className="button" to="/workflows">
              내 워크플로 보기
            </Link>
            <Link className="button button-secondary" to="/workflows/new">
              워크플로 등록하기
            </Link>
          </div>
        </div>
        <div className="enter enter-late">
          <VersionTimeline />
        </div>
      </header>

      <section aria-labelledby="flow-heading" className="home-section">
        <h2 id="flow-heading">서비스 흐름</h2>
        <ol className="steps">
          {STEPS.map((step, index) => (
            <li
              key={step.title}
              className={step.available ? 'step lift' : 'step step-pending'}
            >
              <span className="step-number">{index + 1}</span>
              <strong>{step.title}</strong>
              <p className="muted">{step.description}</p>
              <span className="tag">
                {step.available ? '제공 중' : '준비 중'}
              </span>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="facts-heading" className="home-section">
        <h2 id="facts-heading">보관 방식</h2>
        <ul className="facts">
          {FACTS.map((fact) => (
            <li key={fact.title} className="fact lift">
              <strong>{fact.title}</strong>
              <p className="muted">{fact.body}</p>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
