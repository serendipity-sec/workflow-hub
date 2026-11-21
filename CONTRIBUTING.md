# 개발 참여 가이드

먼저 루트 `AGENTS.md`, 담당 영역의 `AGENTS.md`, 관련 API 계약을 읽습니다.

## 작업 흐름

1. **이슈 생성 (사람)**: `개발 작업` 템플릿으로 이슈를 직접 만듭니다. 목적, 범위, 완료 조건, 결정 사항을 적습니다.
2. **작업 시작 (AI)**: 이슈 번호를 넘기고 `/start-task <번호>`를 실행합니다. AI가 이슈를 읽고 브랜치와 계획을 보고합니다. 계획을 확인하고 진행을 승인합니다.
3. **구현 (AI)**: 이슈에 없는 결정이 필요하면 AI가 멈추고 묻습니다. 정한 내용은 이슈에 댓글로 남깁니다.
4. **작업 마무리 (AI)**: `/finish-task`를 실행합니다. 검사, 리뷰 스킬 1차 리뷰, 로컬 커밋을 마치고 push 명령과 PR 제목·본문 초안을 넘깁니다.
5. **push와 PR (사람)**: 결과를 확인하고 직접 push한 뒤 PR을 만듭니다.
6. **봇 리뷰 (사람이 실행)**: PR에 `@coderabbitai review` 댓글을 남겨 CodeRabbit 리뷰를 실행합니다. 지적 사항은 AI에게 넘겨 고치거나, 반영하지 않는 이유를 답글로 남깁니다.
7. **머지 (사람)**: CI와 리뷰를 확인하고 squash merge합니다.

AI는 커밋까지만 합니다. 이슈·댓글 생성, push, PR 생성·머지는 사람이 합니다.
Claude Code 외의 에이전트는 `.claude/skills/*/SKILL.md`를 읽고 같은 절차를 따릅니다.

## 브랜치와 커밋

브랜치는 `<type>/<이슈 번호>-<짧은-설명>`입니다. 예: `feat/42-workflow-upload`.
한 PR은 하나의 목적을 가지며, 관련 이슈는 PR 본문에 `Closes #42`로 연결합니다.
작업 중 커밋은 자유롭게 쌓아도 됩니다. Conventional Commits를 권장하지만 squash merge로 main에는 남지 않습니다.

## PR 제목

squash merge만 허용하며 **PR 제목이 그대로 main의 커밋 제목이 됩니다.** CI가 PR 제목을 검사합니다.

```text
feat(workflow): 워크플로 업로드 추가
fix(auth): 만료 토큰 처리 수정
feat(revision)!: 리비전 응답 형식 변경
ci: 빌드 검사 추가
```

- 형식: `type(scope): 설명`. scope는 선택입니다.
- 타입: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`
- scope: `auth`, `workflow`, `revision`, `analysis`, `build`처럼 기능이나 도메인을 나타냅니다. `front`, `back`, `frontend`, `backend`는 scope로 쓸 수 없습니다.
- 설명: 한국어로 무엇이 바뀌는지 한 문장. 마침표 없이 50자 안팎으로 씁니다.
- 이슈 번호는 제목에 넣지 않습니다. 머지할 때 GitHub가 `(#PR 번호)`를 붙입니다.
- 호환성을 깨는 API·DB 변경은 type 뒤에 `!`를 붙입니다.
- 작업 범위가 바뀌면 머지 전에 제목도 고칩니다. 제목을 수정하면 CI가 다시 검사합니다.
- 로컬 확인: `npm run check:pr-title -- "feat(workflow): 워크플로 업로드 추가"`

담당 영역은 `frontend`, `backend`, `infra`, `docs` 라벨로 표현합니다. 변경 경로를 기준으로 자동으로 붙으며 여러 개일 수 있습니다.

## 검사

루트는 `npm ci` 후 `npm run check`와 `npm run test:tooling`을 실행합니다.
포맷 수정은 `npm run format`입니다. 프론트와 백엔드는 각각의 포매터를 사용합니다.
프론트 검사 명령은 `frontend/AGENTS.md`, 백엔드는 `backend/AGENTS.md`를 따릅니다.
CI의 필수 검사는 `repository`, `frontend`, `backend`, `secrets`이며, 모두 통과해야 머지할 수 있습니다.

- `repository`(포맷·API 계약·PR 제목)와 `secrets`(Gitleaks)는 모든 PR에서 실행합니다.
- `frontend`는 `frontend/**`, `.node-version`, `ci.yml`이 바뀐 PR에서만, `backend`는 `backend/**`, `ci.yml`이 바뀐 PR에서만 실행합니다.
  해당 없는 job은 skipped로 표시되며 필수 검사를 통과한 것으로 처리됩니다. 문서만 바꾼 PR은 빌드를 돌지 않습니다.
- main에 머지된 뒤에는 경로와 관계없이 모든 job을 실행합니다.
- 경로 필터는 job 단위(`changes` job + `if`)로 겁니다. 워크플로 `paths:` 필터로 바꾸면 필수 검사가 대기 상태로 남아 머지가 막힙니다.

## 리뷰 봇

공개 저장소 무료 플랜으로 CodeRabbit을 사용합니다. 설정은 `.coderabbit.yaml`이며 한국어로 리뷰하고 `AGENTS.md` 규칙을 기준으로 봅니다.
별 10개 미만 공개 저장소는 자동 리뷰가 돌지 않으므로 PR마다 `@coderabbitai review`(최신 변경) 또는 `@coderabbitai full review`(전체) 댓글로 실행합니다.
봇 리뷰는 필수 검사가 아니며, AI의 1차 리뷰(`/finish-task`)를 대체하지 않습니다.

UTF-8, LF, 마지막 개행을 사용합니다. `.bat`와 `.cmd`만 CRLF를 사용합니다.
포매터 설정이 들여쓰기와 코드 스타일의 기준입니다. 포매터 결과를 취향으로 되돌리지 않습니다.

## GitHub 저장소 설정

저장소: `serendipity-sec/workflow-hub` (공개). 아래 설정이 적용되어 있습니다.

- 머지는 squash만 허용하고, squash 커밋 제목은 PR 제목, 본문은 PR 본문을 사용합니다.
- merge 후 작업 브랜치를 자동으로 삭제합니다.
- `main`은 PR로만 변경할 수 있고, 필수 상태 검사를 통과해야 합니다. force push와 삭제를 막습니다.
- `frontend`, `backend`, `infra`, `docs` 라벨을 사용합니다.
- secret scanning과 push protection을 켭니다.

## 설정과 데이터

환경변수 예시에는 이름과 무해한 예시만 넣습니다. `.env`는 Git에 올리지 않습니다.
`VITE_*`는 브라우저에 공개되므로 서버 비밀키, DB 비밀번호, AWS 자격 증명을 넣지 않습니다.
실제 업로드 파일과 실제 토큰을 테스트 fixture나 로그로 남기지 않습니다.
제품 코드의 권한 검사는 백엔드에서 실행하며 프론트 화면 숨김으로 대체하지 않습니다.
