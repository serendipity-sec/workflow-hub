# 개발 참여 가이드

먼저 루트 `AGENTS.md`, 담당 영역의 `AGENTS.md`, 관련 API 계약을 읽습니다.

## 작업과 커밋

작업별 브랜치를 사용합니다. 예: `feat/42-workflow-upload`.
한 PR은 하나의 목적을 가지며, 관련 이슈는 PR 본문에 `Closes #42`로 연결합니다.

커밋에는 Conventional Commits를 권장합니다. PR 제목은 필수입니다.

```text
feat(workflow): 워크플로 업로드 추가
fix(auth): 만료 토큰 처리 수정
ci: 빌드 검사 추가
```

타입은 `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`를 사용합니다.
scope는 선택 사항이며 `auth`, `workflow`, `revision`, `analysis`, `build`처럼 도메인이나 기능을 나타냅니다.
`front`, `back`, `frontend`, `backend`는 scope로 사용하지 않습니다.
담당 영역은 `frontend`, `backend`, `infra`, `docs` 라벨로 표현하고 여러 라벨을 붙일 수 있습니다.

## 검사

루트는 `npm ci` 후 `npm run check`와 `npm run test:tooling`을 실행합니다.
포맷 수정은 `npm run format`입니다. 프론트와 백엔드는 각각의 포매터를 사용합니다.
프론트 검사 명령은 `frontend/AGENTS.md`, 백엔드는 `backend/AGENTS.md`를 따릅니다.
CI는 모든 PR에서 각 영역의 검사와 빌드를 실행합니다. 영역별 경로 필터로 필수 검사가 누락되지 않게 합니다.

UTF-8, LF, 마지막 개행을 사용합니다. `.bat`와 `.cmd`만 CRLF를 사용합니다.
포매터 설정이 들여쓰기와 코드 스타일의 기준입니다. 포매터 결과를 취향으로 되돌리지 않습니다.

## GitHub 초기 설정

다음은 저장소 파일만으로 활성화되지 않으므로 원격 repo 생성 후 관리자가 적용합니다.

1. 최초 README 초안을 사용자에게 검토받고 명시적 승인을 받은 뒤 첫 push를 합니다.
2. 기본 브랜치는 `main`, 머지는 squash만 허용합니다.
3. squash commit의 기본 제목을 PR 제목으로 설정합니다.
4. merge 후 작업 브랜치 자동 삭제를 켭니다.
5. `frontend`, `backend`, `infra`, `docs` 라벨을 생성합니다. 자동 라벨 워크플로가 변경 경로를 기준으로 부착합니다.
6. main 직접 push를 제한하고 PR을 요구합니다. 팀 규모에 맞게 작성자 외 1인 검토를 권장합니다.
7. CI 최초 실행 후 `repository`, `frontend`, `backend`, `secrets`를 필수 상태 검사로 지정합니다.
8. 사용 가능한 secret scanning과 push protection을 활성화합니다.

PR 제목을 squash 커밋 제목으로 사용하므로 작업 중 모든 커밋을 재작성할 필요는 없습니다.
README 최초 사용자 승인은 첫 업로드의 별도 조건입니다. 이후 모든 README 변경에 사용자 개인 승인을 요구하지 않습니다.

## 설정과 데이터

환경변수 예시에는 이름과 무해한 예시만 넣습니다. `.env`는 Git에 올리지 않습니다.
`VITE_*`는 브라우저에 공개되므로 서버 비밀키, DB 비밀번호, AWS 자격 증명을 넣지 않습니다.
실제 업로드 파일과 실제 토큰을 테스트 fixture나 로그로 남기지 않습니다.
제품 코드의 권한 검사는 백엔드에서 실행하며 프론트 화면 숨김으로 대체하지 않습니다.
