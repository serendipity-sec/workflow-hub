# Workflow Hub

n8n 워크플로 JSON을 업로드하고, 버전별 이력을 관리하며, 원하는 버전을 다운로드하는 웹 서비스를 개발합니다. 프론트엔드와 백엔드를 한 저장소에서 관리합니다.

## 개발 목표

- Google 계정 로그인 (Supabase Auth)
- n8n 워크플로 JSON 업로드 및 다운로드
- 워크플로별 버전 이력 관리 (`v1`, `v1.1`, `v2`)
- 개인 비공개 워크플로 저장

현재 인증 기반 API와 워크플로·버전 메타데이터 DB 마이그레이션이 구현되어 있습니다. 업로드·조회·다운로드 API와 실제 S3 연동은 후속 작업입니다.

## 기술 스택

| 영역     | 기술                               |
| -------- | ---------------------------------- |
| Frontend | React, TypeScript, Vite            |
| Backend  | Java, Spring Boot, Spring Security |
| Auth     | Supabase Auth (Google), JWT        |
| Database | Supabase PostgreSQL                |
| Storage  | AWS S3 (비공개 버킷)               |

## 시작하기

### 요구 사항

- Node.js 24
- JDK 25
- 백엔드 실행용 PostgreSQL
- 백엔드 테스트용 Docker 호환 컨테이너 런타임 (실행 상태 필요)

Gradle은 `backend`의 Wrapper(`gradlew`)를 사용하므로 별도 설치가 필요하지 않습니다.

### 저장소 도구와 에이전트 스킬

```sh
# 저장소 루트: 문서/계약 검사 도구
npm ci

# Claude Code가 .agents/skills의 스킬을 읽도록 링크 생성 (클론 후 한 번)
npm run setup:skills
```

스킬 원본은 `.agents/skills/`에 있습니다. `setup:skills`는 `.claude/skills/`에 링크를 만들며, 이 링크는 git에 올리지 않습니다. Windows는 디렉터리 정션을 쓰므로 관리자 권한이 필요 없습니다.

Codex를 쓴다면 `~/.codex/skills/` 아래에도 같은 원본을 연결합니다. 이 연결은 저장소 밖 사용자 설정이라 커밋되지 않습니다. PowerShell 예시(저장소 경로는 본인 환경에 맞게 바꿉니다):

```powershell
$repo = "C:\path\to\workflow-hub"
$codexSkills = "$env:USERPROFILE\.codex\skills"
New-Item -ItemType Directory -Force -Path $codexSkills | Out-Null
foreach ($s in "start-task","finish-task") {
  $link = Join-Path $codexSkills $s
  if (-not (Test-Path $link)) {
    New-Item -ItemType Junction -Path $link -Target "$repo\.agents\skills\$s" | Out-Null
  }
}
```

### 프론트엔드

```sh
cd frontend
npm ci
cp .env.example .env.local
npm run dev
```

`.env.local`에 Supabase URL과 공개용(anon/publishable) 키를 설정합니다. service-role 등 비밀 키는 `VITE_` 변수에 넣지 마세요.

### 백엔드

```sh
cd backend

# macOS/Linux
./gradlew bootRun

# Windows PowerShell
.\gradlew.bat bootRun
```

실행 전에 `backend/.env.example`을 참고해 `DATABASE_URL`(JDBC URL), `DATABASE_USERNAME`, `DATABASE_PASSWORD`를 터미널이나 IDE의 프로세스 환경변수로 지정합니다. Supabase JWT issuer, JWKS 등 인증 설정도 환경변수로 전달합니다. Spring Boot는 `.env` 파일을 자동으로 읽지 않습니다.

백엔드는 시작 시 Flyway로 `backend/src/main/resources/db/migration/`의 마이그레이션을 적용합니다. 연결 계정은 `workflow_hub` 스키마와 테이블을 생성할 수 있어야 합니다. Supabase에서는 이 스키마를 Data API의 exposed schemas에 추가하지 않습니다. 실제 Google·Supabase·S3 연동은 별도 환경에서 확인해야 합니다.

## 테스트와 빌드

```sh
# 루트
npm run check

# frontend
npm run lint
npm run format:check
npm run typecheck
npm test
npm run build

# backend (Windows는 gradlew.bat)
./gradlew spotlessCheck test bootJar
```

CI에서도 동일한 명령을 실행합니다. 백엔드 테스트는 Testcontainers로 일회용 PostgreSQL을 실행하며, 운영 DB나 실제 Supabase 자격 증명이 필요하지 않습니다. 컨테이너 이미지를 처음 내려받을 때 네트워크 연결이 필요합니다.

## 문서

- [범위와 일정](docs/PLAN.md)
- [구조와 인증·데이터 정책](docs/ARCHITECTURE.md)
- [API 명세](contracts/openapi.yaml)
- [워크플로 샘플](contracts/examples/minimal-workflow.json)

## 기여하기

1. 이슈를 먼저 등록해 변경 내용을 공유합니다.
2. 브랜치를 만들어 작업하고, 위의 테스트와 빌드 명령이 모두 통과하는지 확인합니다.
3. PR 제목은 `feat(workflow): add workflow upload`처럼 `type(scope): description` 형식(설명은 영어)으로 작성하고, frontend/backend 영역 라벨을 붙입니다.

자세한 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 데이터 처리

- 워크플로·버전 메타데이터는 PostgreSQL에 저장합니다. 원본 파일의 S3 저장은 후속 업로드 구현에서 연결합니다.
- 업로드한 워크플로는 서버에서 실행하지 않습니다.
- 로그인 토큰 갱신은 Supabase SDK가 처리하며, 브라우저에 저장된 토큰은 JavaScript에서 접근할 수 있습니다.
- 로그아웃 후에도 이미 발급된 Access Token은 만료 시점까지 유효할 수 있습니다.

## 라이선스

이 프로젝트는 [Apache License 2.0](LICENSE)에 따라 배포됩니다.
