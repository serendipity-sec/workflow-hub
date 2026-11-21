---
name: finish-task
description: 작업을 마무리한다. 영역별 검사, 리뷰 스킬 1차 리뷰, 로컬 커밋을 마치고 사람이 push·PR 생성·머지할 수 있도록 명령과 PR 제목·본문 초안을 넘긴다. 구현을 끝냈을 때 사용한다.
---

# finish-task

이 스킬은 로컬 커밋까지만 한다. `git push`, PR 생성·머지, 이슈 댓글은 하지 않는다.
로컬 커밋은 이 스킬에서만 생성한다. 필수 검사 통과와 리뷰의 미해결 문제 없음이 커밋의 선행 조건이다. 그 전까지 변경은 작업 트리에 유지한다.

## 1. 대상 확인

```bash
git status --short --branch
git fetch origin main
git diff --stat origin/main...HEAD
git diff --stat
git diff --cached --stat
```

- 현재 브랜치에서 `<type>/<이슈 번호>-...`에 대응하는 이슈 번호와 작업 연관성을 확인한다. `start-task`에서 재사용한 기존 브랜치는 접두사가 있어도 허용한다. `main`이면 멈춘다.
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
- 필수 로컬 검사를 실행할 수 없거나 실패하면 이유를 기록하고 커밋·완료 보고를 하지 않는다. 문제를 해결하고 재검증한다.
- 실제 GitHub 이벤트나 외부 서비스 연동 검증은 로컬 검사와 구분해 실행 여부와 결과를 기록한다. 미검증 결과를 통과로 보고하지 않는다.

## 3. 1차 리뷰 (필수)

리뷰 스킬을 직접 실행한다. 생략하지 않는다.

리뷰 대상은 `origin/main`과 현재 작업 트리의 전체 차이다. 기존 브랜치 커밋, staged·unstaged 변경과 이슈 범위의 untracked 파일 내용을 모두 포함한다. 커밋 간 차이만으로 리뷰를 끝내지 않는다. `git diff origin/main`과 `git ls-files --others --exclude-standard`를 확인하고 신규 파일도 읽는다.

- Claude Code: `/code-review` (기준: 위의 전체 변경 내용)
- Codex: `/review`
- 그 밖의 에이전트: 그 도구의 코드 리뷰 기능. 없으면 사람에게 알리고 리뷰를 요청한다.

지적 사항을 수정하고 필요한 2단계 검사를 다시 실행한 뒤 리뷰 지적의 해결 여부를 확인한다. 미해결 문제가 있으면 커밋하거나 완료를 보고하지 않는다. 반영하지 않는 항목은 근거와 함께 문제가 아님을 확인한 경우에만 해결로 기록한다.

## 4. PR 제목 검증

AGENTS.md의 PR 제목 규칙에 맞는 제목을 만든다. squash merge로 이 제목이 main의 커밋 제목이 된다.

```bash
npm run check:pr-title -- "type(scope): description"
```

제목 검사가 실패하면 제목을 수정하고 다시 검증한다.

## 5. 커밋

- 2~4단계의 필수 검사와 리뷰가 완료되고 미해결 문제가 없는지 확인한 뒤에만 커밋한다.
- 검사·리뷰한 이슈 범위 파일만 스테이징한다. `git diff --cached`로 커밋 내용을 다시 읽고, 해당 파일의 `git diff`가 비어 있는지 확인해 index와 검사·리뷰한 작업 트리가 일치하는지 확인한다. 다른 staged 변경이나 누락된 신규 파일이 있으면 커밋하지 않고 처리한다. 검사·리뷰 후 내용이 바뀌었다면 필요한 검사와 리뷰를 다시 실행한다.
- `.env`, 빌드 산출물, 실제 workflow JSON, 토큰이 포함되지 않았는지 `git diff --cached --name-only`로 확인한다.
- 확인한 변경을 커밋한다. 메시지는 Conventional Commits 형식을 권장하며, 제목과 본문은 영어로 쓴다.
- 커밋 후 `git status`가 깨끗한지 확인한다.

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
