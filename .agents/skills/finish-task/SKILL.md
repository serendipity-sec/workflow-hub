---
name: finish-task
description: 작업을 마무리한다. 영역별 검사, 리뷰 스킬 1차 리뷰, 로컬 커밋을 마치고 사람이 push·PR 생성·머지할 수 있도록 명령과 PR 제목·본문 초안을 넘긴다. 구현을 끝냈을 때 사용한다.
---

# finish-task

이 스킬은 로컬 커밋까지만 한다. `git push`, PR 생성·머지, 이슈 댓글은 하지 않는다.

## 1. 대상 확인

```bash
git status --short --branch
git fetch origin main
git diff --stat origin/main...HEAD
```

- 현재 브랜치가 `<type>/<이슈 번호>-...` 형식인지 확인하고 이슈 번호를 얻는다. `main`이면 멈춘다.
- 이슈의 완료 조건을 다시 읽는다: `gh issue view <번호> --json title,body,comments`
- 변경이 이슈 범위를 벗어났으면 사람에게 보고하고 분리 여부를 묻는다.

## 2. 검사

변경한 영역의 검사를 모두 실행한다. 실패하면 고치고 다시 실행한다.

| 영역     | 명령                                                                            |
| -------- | ------------------------------------------------------------------------------- |
| 루트     | `npm ci` 후 `npm run check`, `npm run test:tooling`                             |
| frontend | `cd frontend && npm ci && npm run verify`                                       |
| backend  | `cd backend && ./gradlew spotlessCheck test bootJar` (Windows: `.\gradlew.bat`) |

- 검사·설정·테스트를 약하게 바꾸거나 skip해서 통과시키지 않는다.
- 실행할 수 없는 검사(외부 서비스, 자격 증명 필요 등)는 이유와 함께 기록한다.

## 3. 1차 리뷰 (필수)

리뷰 스킬을 직접 실행한다. 생략하지 않는다.

- Claude Code: `/code-review` (기준: 현재 브랜치와 `origin/main`의 차이)
- Codex: `/review`
- 그 밖의 에이전트: 그 도구의 코드 리뷰 기능. 없으면 사람에게 알리고 리뷰를 요청한다.

지적 사항은 고치거나, 고치지 않는 이유를 기록한다. 코드를 고쳤다면 2단계 검사를 다시 실행한다.

## 4. 커밋

- 남은 변경을 커밋한다. 메시지는 Conventional Commits 형식을 권장하며, 제목과 본문은 영어로 쓴다.
- `.env`, 빌드 산출물, 실제 workflow JSON, 토큰이 포함되지 않았는지 `git diff --cached --name-only`로 확인한다.
- 커밋 후 `git status`가 깨끗한지 확인한다.

## 5. PR 제목 검증

AGENTS.md의 PR 제목 규칙에 맞는 제목을 만든다. squash merge로 이 제목이 main의 커밋 제목이 된다.

```bash
npm run check:pr-title -- "type(scope): description"
```

## 6. 사람에게 넘기기

아래 형식으로 보고하고 멈춘다. push·PR 생성·머지는 사람이 직접 한다.

```text
## push (사람이 실행)
git push -u origin <브랜치명>

## PR 제목
type(scope): description (영어)

## 라벨
frontend / backend / infra / docs 중 해당 항목 (자동 라벨을 확인하고 필요하면 수정)

## PR 본문
(.github/pull_request_template.md 형식으로 작성. `Closes #<번호>` 포함)
- 목적
- 변경 내용
- 검증 결과: 실행한 명령과 결과, 실행하지 못한 검사와 이유
- 리뷰 결과: 사용한 리뷰 스킬, 지적 사항과 처리 결과
- 결정 사항: 이슈와 작업 중 사람이 내린 결정
- 계약·데이터 변경 여부

## 남은 문제·미검증 항목

## PR 생성 후 (사람이 실행)
PR에 `@coderabbitai review` 댓글로 봇 리뷰를 실행한다. 지적 사항은 다시 AI에게 넘긴다.
```
