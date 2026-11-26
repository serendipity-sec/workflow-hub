import { ButtonLink } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import type { IconName } from '../../shared/ui/Icon';
import { VersionTimeline } from './VersionTimeline';
import './home.css';

type Step = { title: string; description: string; available: boolean };

// Keep `available` honest: only what the running service really provides.
const STEPS: Step[] = [
  {
    title: '등록',
    description: 'n8n에서 내보낸 JSON을 올리면 v1로 저장됩니다.',
    available: true,
  },
  {
    title: '버전 이력과 다운로드',
    description: '버전마다 등록 당시의 원본을 그대로 받습니다.',
    available: true,
  },
  {
    title: '변경점 비교와 새 버전',
    description: '수정본을 비교하고 v1.1이나 v2로 등록합니다.',
    available: true,
  },
  {
    title: '보안 검사와 수정 안내',
    description: '위험 근거를 확인하고 고친 파일을 다시 검사합니다.',
    available: false,
  },
];

const NOTES: { icon: IconName; title: string; body: string }[] = [
  {
    icon: 'layers',
    title: '버전 번호는 서버가 매깁니다',
    body: 'v1, 작은 수정은 v1.1, 큰 수정은 v2로 올라갑니다.',
  },
  {
    icon: 'file',
    title: '원본을 고치지 않습니다',
    body: '등록한 버전의 파일은 바뀌지 않습니다.',
  },
  {
    icon: 'lock',
    title: '올린 파일은 실행하지 않습니다',
    body: '워크플로와 Code 노드는 파일로만 보관합니다.',
  },
];

export function HomePage() {
  const available = STEPS.filter((step) => step.available).length;

  return (
    <div className="home">
      <header className="home-head enter">
        <p className="eyebrow">WORKFLOW HUB</p>
        <h1>
          <span>Workflow</span> <span>Hub</span>
        </h1>
        <p className="home-lead">
          n8n 워크플로를 버전별로 보관하고, 원본 그대로 내려받으세요. 수정할
          때마다 새 버전으로 남기면 이전 버전도 언제든 같은 파일로 받을 수
          있습니다.
        </p>
      </header>

      <div className="bento enter enter-late">
        <Card className="bento-flow" aria-labelledby="flow-heading">
          <h2 id="flow-heading">서비스 흐름</h2>
          <ol className="flow">
            {STEPS.map((step, index) => (
              <li
                key={step.title}
                className="flow-item"
                style={{ '--i': index } as React.CSSProperties}
              >
                <span
                  className={step.available ? 'flow-pill is-on' : 'flow-pill'}
                >
                  <span className="flow-num">{index + 1}</span>
                  {step.title}
                  <span className="flow-state">
                    {step.available ? '제공 중' : '준비 중'}
                  </span>
                </span>
                <p className="muted">{step.description}</p>
              </li>
            ))}
          </ol>
        </Card>

        <Card className="bento-stat">
          <p className="stat-label">제공 중인 단계</p>
          <p className="stat-value">
            {available}
            <span>/{STEPS.length}</span>
          </p>
          <div
            className="stat-bar"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={STEPS.length}
            aria-valuenow={available}
            aria-label="제공 중인 단계"
          >
            <span style={{ width: `${(available / STEPS.length) * 100}%` }} />
          </div>
          <p className="muted">나머지는 준비 중입니다.</p>
        </Card>

        <VersionTimeline className="bento-version" />

        <Card className="bento-notes" aria-labelledby="notes-heading">
          <h2 id="notes-heading">보관 방식</h2>
          <ul className="notes">
            {NOTES.map((note) => (
              <li key={note.title}>
                <span className="notes-icon">
                  <Icon name={note.icon} size={18} />
                </span>
                <div>
                  <strong>{note.title}</strong>
                  <p className="muted">{note.body}</p>
                </div>
              </li>
            ))}
          </ul>
        </Card>

        <Card tone="dark" className="bento-start">
          <h2>첫 워크플로를 등록해 보세요</h2>
          <p className="muted">
            n8n 편집기에서 내보낸 JSON 파일 하나면 충분합니다.
          </p>
          <div className="start-actions">
            <ButtonLink to="/workflows/new">워크플로 등록하기</ButtonLink>
            <ButtonLink to="/workflows" variant="ghost" className="start-link">
              내 워크플로 보기
            </ButtonLink>
          </div>
        </Card>
      </div>
    </div>
  );
}
