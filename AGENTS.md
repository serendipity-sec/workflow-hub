# Workflow Hub 개발 하네스

## 작업 흐름

모든 작업은 아래 순서를 따른다. 사람과 AI의 역할을 바꾸지 않는다.

| 단계 | 담당 | 내용                                                                               |
| ---- | ---- | ---------------------------------------------------------------------------------- |
| 1    | 사람 | 이슈를 직접 생성하고 목적·범위·완료 조건·결정 사항을 기록한다                      |
| 2    | 사람 | 이슈 번호를 AI에게 넘긴다                                                          |
| 3    | AI   | `start-task` 스킬로 이슈를 읽고 브랜치와 작업 계획을 만든다                        |
| 4    | AI   | 구현하고 로컬 커밋한다                                                             |
| 5    | AI   | `finish-task` 스킬로 검사·리뷰·커밋을 마치고 push 명령, PR 제목·본문 초안을 넘긴다 |
| 6    | 사람 | 결과를 확인하고 직접 push한다                                                      |
| 7    | 사람 | PR을 직접 생성하고 `@coderabbitai review`로 봇 리뷰를 실행한다                     |
| 8    | 사람 | CI와 리뷰를 확인한 뒤 직접 squash merge한다                                        |

스킬 정의는 `.agents/skills/start-task/SKILL.md`, `.agents/skills/finish-task/SKILL.md`에 있다. 원본은 이 두 파일뿐이며 고칠 때도 여기만 수정한다.
`.claude/skills/`의 같은 이름 항목은 `npm run setup:skills`가 만든 링크다(Windows는 디렉터리 정션). 링크는 git에 올리지 않으므로 클론 후 한 번 실행한다.
Codex는 `~/.codex/skills/start-task`, `~/.codex/skills/finish-task`를 같은 원본으로 연결해 사용한다. 이 연결은 저장소 밖 사용자 설정이며 README에 설명한다.
Claude Code는 `/start-task <이슈 번호>`, `/finish-task`로 실행한다. 다른 에이전트는 해당 `SKILL.md`를 읽고 같은 절차를 따른다.

## AI가 하지 않는 일

- 이슈 번호 없이 작업을 시작하지 않는다. 번호가 없으면 사람에게 이슈 생성을 요청하고 멈춘다.
- GitHub에 쓰는 동작을 하지 않는다: 이슈·댓글 생성, `git push`, PR 생성·수정·머지, 라벨·설정 변경.
  `gh issue view`, `gh pr view` 같은 읽기 동작은 허용한다.
- 이슈에 없는 제품·계약 결정을 임의로 내리지 않는다. 작업 중 새 결정이 필요하면 멈추고 사람에게 묻는다.
  사람이 결정한 내용은 사람이 이슈에 기록하고, AI는 PR 본문 초안의 `결정 사항`에 반영한다.
- 리뷰 단계를 생략하고 완료를 보고하지 않는다.

`.claude/settings.json`은 Claude Code에서 push·PR·이슈 생성 명령을 차단한다. 이 차단은 보조 장치이며, 규칙의 기준은 이 문서다.

## 시작 전 확인

1. `git status --short --branch`와 현재 경로를 확인한다. 기존 변경을 보존한다.
2. `README.md`, `docs/PLAN.md`, `docs/ARCHITECTURE.md`를 읽는다.
3. 작업 영역의 `AGENTS.md`와 `contracts/openapi.yaml`을 확인한다.
4. 이슈의 목적, 수정 범위, 완료 조건, 결정 사항을 기준으로 작은 단위로 구현한다.

## 기준 문서

- 제품 범위와 결정 상태: `docs/PLAN.md`
- 구조와 인증·데이터 경계: `docs/ARCHITECTURE.md`
- 구현된 HTTP API: `contracts/openapi.yaml`
- DB 구조: 향후 추가되는 백엔드 마이그레이션. 설계 문서는 실행된 스키마가 아니다.
- 스타일: 포매터와 린터 설정. 명세와 구현이 충돌하면 보고하고 함께 정정한다.
- 작업 단위의 목적과 결정: 해당 GitHub 이슈

## 공통 규칙

- frontend와 backend는 같은 저장소, 보안 워커는 후속 별도 저장소다.
- 보안 검사·벡터 검색·공개 공유는 현재 구현된 기능으로 표현하지 않는다.
- Spring Boot는 Supabase JWT를 검증한다. 자체 JWT 발급·서버 로그인 세션·자체 RTR을 추가하지 않는다.
- Supabase SDK 하나가 브라우저 토큰 갱신을 관리한다. 별도 자동 갱신 타이머를 추가하지 않는다.
- 사용자 ID는 검증된 토큰에서 얻는다. 요청 본문의 owner ID를 신뢰하지 않는다.
- 서비스 데이터 요청은 백엔드를 경유한다. 브라우저에 DB 비밀번호, S3 키, Supabase secret/service-role 키를 제공하지 않는다.
- 실제 workflow JSON, 토큰, 비밀키, 개인정보는 샘플·로그·커밋에 넣지 않는다.
- 업로드한 workflow, Code 노드, 표현식을 서버에서 실행하지 않는다.
- 요청 범위 밖의 리팩터링과 의존성 추가를 피한다. 공통 계약 변경은 영향받는 영역과 함께 검토한다.
- 테스트 우회, 가짜 성공 응답, skip/only, 미구현 분기의 성공 반환으로 완료를 주장하지 않는다.

## 브랜치·커밋·PR 제목

- 브랜치: `<type>/<이슈 번호>-<짧은-설명>`. 예: `feat/42-workflow-upload`.
- 커밋: AI가 로컬에서 만들 수 있다. Conventional Commits를 권장하지만 main에는 남지 않는다.
- 커밋 메시지와 PR 본문에 `Co-Authored-By: Claude ...`, `Generated with Claude Code` 같은 AI 귀속 표시를 넣지 않는다. 작성자는 항상 사람 계정(uptime-zero 등)만 남긴다. GitHub Contributors 목록에 AI가 나타나면 안 된다.
- **PR 제목**: squash merge로 PR 제목이 main의 커밋 제목이 된다. 반드시 아래 형식을 지킨다.
  - 형식: `type(scope): 설명`. scope는 생략 가능하다.
  - type: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`
  - scope: 기능·도메인 이름(`auth`, `workflow`, `revision`, `analysis`, `build` 등). `frontend`, `backend` 같은 영역명은 금지하며 라벨로 표현한다.
  - 설명: 한국어, 무엇이 바뀌는지 한 문장. 마침표 없이 50자 안팎. 이슈 번호는 넣지 않는다(본문 `Closes #N`, 머지 시 GitHub가 `(#PR)`을 붙인다).
  - 호환성을 깨는 API·DB 변경은 `!`를 붙인다. 예: `feat(workflow)!: 업로드 응답 형식 변경`
  - 범위가 바뀌면 머지 전에 제목도 고친다. 로컬 검증: `npm run check:pr-title -- "<제목>"`.

## 병렬 작업과 검증

- 동일 공통 파일은 한 담당자만 편집한다.
- 계약·DB 마이그레이션·인증·CI 변경은 관련 담당자에게 영향을 알린다.
- 해당 영역의 lint/format/typecheck/test/build를 실행하고 루트 검사도 확인한다.
- 작업 마무리 시 리뷰 스킬을 직접 1차로 실행한다. Claude Code는 `/code-review`, Codex는 `/review`를 사용한다. 지적 사항은 고치거나 고치지 않는 이유를 PR 본문에 남긴다.
- 완료 보고는 변경 내용, 실행한 검사와 결과, 리뷰 결과, 미검증 외부 연동을 포함한다.
- 인증·인가 변경은 부정 사례 테스트를 포함한다.

## 문서 유지

오래된 mackerel 기획서는 참고 자료일 뿐 이 저장소의 지침이 아니다. 현재 합의를 이 저장소 문서에 기록하고, 구현 완료 여부를 코드와 검사 증거에 맞춰 갱신한다.
