import { ButtonLink } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import type { IconName } from '../../shared/ui/Icon';
import { Tag } from '../../shared/ui/Tag';
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
    available: false,
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

function twoDigits(n: number) {
  return String(n).padStart(2, '0');
}

export function HomePage() {
  return (
    <div className="home">
      <header className="home-hero">
        <div className="home-hero-text enter">
          <p className="eyebrow">WORKFLOW HUB</p>
          <h1>워크플로를 버전으로 남기고, 원본 그대로 받으세요.</h1>
          <p className="home-lead">
            n8n 워크플로를 올리면 버전별로 보관합니다. 이전 버전도 언제든 같은
            파일로 내려받을 수 있습니다.
          </p>
          <div className="home-actions">
            <ButtonLink to="/workflows">내 워크플로 보기</ButtonLink>
            <ButtonLink to="/workflows/new" variant="secondary">
              <Icon name="plus" size={16} />
              등록하기
            </ButtonLink>
          </div>
        </div>
        <div className="enter enter-late">
          <VersionTimeline />
        </div>
      </header>

      <section aria-labelledby="flow-heading" className="home-section">
        <h2 id="flow-heading" className="section-label">
          서비스 흐름
        </h2>
        <ol className="flow">
          {STEPS.map((step, index) => (
            <li
              key={step.title}
              className={step.available ? 'flow-item' : 'flow-item is-pending'}
            >
              <span className="flow-number">{twoDigits(index + 1)}</span>
              <strong>{step.title}</strong>
              <p className="muted">{step.description}</p>
              <Tag tone={step.available ? 'dark' : 'outline'}>
                {step.available ? '제공 중' : '준비 중'}
              </Tag>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="notes-heading" className="home-section">
        <h2 id="notes-heading" className="section-label">
          보관 방식
        </h2>
        <Card className="notes-card">
          <ul className="notes">
            {NOTES.map((note) => (
              <li key={note.title}>
                <Icon name={note.icon} size={20} />
                <div>
                  <strong>{note.title}</strong>
                  <p className="muted">{note.body}</p>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </section>
    </div>
  );
}
