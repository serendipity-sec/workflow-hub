import { ButtonLink } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import type { IconName } from '../../shared/ui/Icon';
import { Tag } from '../../shared/ui/Tag';
import { VersionTimeline } from './VersionTimeline';
import './home.css';

type Feature = {
  id: string;
  icon: IconName;
  title: string;
  body: string;
};

// Keep this honest: only what the running service really provides, plus the
// security check clearly marked as not available yet.
const FEATURES: Feature[] = [
  {
    id: 'versions',
    icon: 'layers',
    title: '버전 관리',
    body: '수정본을 올리면 노드와 연결의 변경점을 보여 주고, 작은 수정(v1.1)이나 큰 수정(v2)으로 등록합니다.',
  },
  {
    id: 'download',
    icon: 'download',
    title: '원본 다운로드',
    body: '버전마다 등록 당시의 파일을 그대로 받습니다. 버전별로 다운로드를 중지할 수도 있습니다.',
  },
  {
    id: 'restore',
    icon: 'refresh',
    title: '삭제와 복구',
    body: '삭제한 버전과 워크플로는 목록에서 빠지고, 복구 기한 안에는 되살릴 수 있습니다.',
  },
  {
    id: 'original',
    icon: 'lock',
    title: '원본 보관',
    body: '등록한 파일은 바뀌지 않고, SHA-256과 크기로 같은 파일인지 확인할 수 있습니다. 올린 워크플로는 실행하지 않습니다.',
  },
];

const STEPS: { title: string; body: string }[] = [
  {
    title: 'JSON 내보내기',
    body: 'n8n 편집기에서 워크플로를 JSON 파일로 내보냅니다.',
  },
  {
    title: '올려서 v1로 등록',
    body: 'Google 계정으로 로그인한 뒤 파일을 올리면 v1로 저장됩니다.',
  },
  {
    title: '수정하고 새 버전으로',
    body: '고친 파일을 비교한 뒤 v1.1이나 v2로 등록하면 이전 버전은 그대로 남습니다.',
  },
  {
    title: '원하는 버전 받기',
    body: '버전 목록에서 필요한 버전의 원본을 내려받습니다.',
  },
];

export function HomePage() {
  return (
    <div className="home">
      <section className="hero" aria-labelledby="hero-heading">
        <div className="hero-copy enter">
          <h1 id="hero-heading">
            n8n 워크플로를 <em>버전별로 보관</em>하고, 원본 그대로 받으세요
          </h1>
          <p className="hero-lead">
            수정할 때마다 새 버전으로 남기면 이전 버전도 언제든 같은 파일로 받을
            수 있습니다.
          </p>
          <div className="hero-actions">
            <ButtonLink to="/workflows/new">
              워크플로 등록하기
              <Icon name="arrow-right" size={16} />
            </ButtonLink>
            <ButtonLink to="/workflows" variant="secondary">
              내 워크플로 보기
            </ButtonLink>
          </div>
        </div>
        <VersionTimeline className="hero-visual enter enter-late" />
      </section>

      <section className="section" aria-labelledby="features-heading">
        <h2 id="features-heading" className="section-title">
          워크플로 관리에 필요한 기능
        </h2>
        <div className="bento">
          {FEATURES.map((feature) => (
            <Card
              key={feature.id}
              className={`feature feature-${feature.id}`}
              aria-labelledby={`feature-${feature.id}`}
            >
              <Icon name={feature.icon} size={22} />
              <h3 id={`feature-${feature.id}`}>{feature.title}</h3>
              <p className="muted">{feature.body}</p>
              {feature.id === 'versions' && (
                <div className="chain" aria-hidden="true">
                  <span>v1</span>
                  <i />
                  <span>v1.1</span>
                  <i />
                  <span className="is-last">v2</span>
                </div>
              )}
              {feature.id === 'original' && (
                <code className="hash" aria-hidden="true">
                  SHA-256 · 파일 크기
                </code>
              )}
            </Card>
          ))}
          <Card
            tone="pending"
            className="feature feature-pending"
            aria-labelledby="feature-security"
          >
            <Icon name="shield" size={22} />
            <div>
              <h3 id="feature-security">
                보안 검사 <Tag tone="outline">준비 중</Tag>
              </h3>
              <p className="muted">
                아직 제공하지 않는 기능입니다. 검사 결과가 없다는 것은
                안전하다는 뜻이 아닙니다.
              </p>
            </div>
          </Card>
        </div>
      </section>

      <section className="section split" aria-labelledby="steps-heading">
        <h2 id="steps-heading" className="section-title">
          사용 방법
        </h2>
        <ol className="steps">
          {STEPS.map((step, index) => (
            <li key={step.title}>
              <span className="step-num">{index + 1}</span>
              <h3>{step.title}</h3>
              <p className="muted">{step.body}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="section">
        <Card tone="dark" className="cta" aria-labelledby="cta-heading">
          <h2 id="cta-heading">첫 워크플로를 등록해 보세요</h2>
          <p>n8n 편집기에서 내보낸 JSON 파일 하나면 충분합니다.</p>
          <div className="cta-actions">
            <ButtonLink to="/workflows/new">
              워크플로 등록하기
              <Icon name="arrow-right" size={16} />
            </ButtonLink>
            <ButtonLink to="/workflows" variant="ghost">
              내 워크플로 보기
            </ButtonLink>
          </div>
        </Card>
      </section>
    </div>
  );
}
