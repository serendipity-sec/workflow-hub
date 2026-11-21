# Workflow Hub

n8n 워크플로 JSON의 수정 계보를 관리하고, 각 버전의 보안 검사 근거와 수정 전후 변화를 확인할 수 있는 서비스를 목표로 합니다. 프론트엔드와 백엔드는 한 저장소에서 관리하고, 보안 워커는 별도 저장소로 구성할 계획입니다.

> 보안 검사·수정·공개는 팀 검토용 설계입니다. 현재 제공하는 기능은 아래 구현 현황에서 확인할 수 있습니다.

## 제품 목표와 검토 중인 기능

- Google 계정 로그인과 개인 비공개 워크플로 관리
- 원본과 수정본을 덮어쓰지 않는 리비전 관리 및 다운로드
- 리비전별 보안 검사와 노드·필드·데이터 흐름에 연결된 근거 제공
- 이전 버전과 비교한 새 위험, 해소된 위험, 분석하지 못한 부분 표시
- 수정안 적용, 새 리비전 생성, 재검사의 연결
- 사용 조건과 검사 범위를 포함한 특정 리비전 공개·재사용

공개·자동 수정·고급 분석의 세부 정책은 설계 제안입니다. 검사 결과는 확인한 범위의 근거를 제공하며, 모든 실행 환경에서의 안전성을 보증하는 표시로 사용하지 않습니다.

## 현재 구현 상태

저장소의 코드와 [OpenAPI 계약](contracts/openapi.yaml) 기준입니다. 외부 서비스는 배포 환경에서 연결을 검증해야 합니다.

| 영역                           | 상태                                                              |
| ------------------------------ | ----------------------------------------------------------------- |
| 프론트·백엔드 기반             | 실행 구조, 로그인 연결 코드, JWT 검증, 개발 도구·검사 설정이 있음 |
| 구현된 HTTP API                | 상태 확인과 인증된 사용자 확인. 정확한 계약은 OpenAPI 참조        |
| 워크플로 CRUD·리비전·S3 저장   | 후속 구현 대상                                                    |
| 서비스 DB 연결·마이그레이션    | Supabase PostgreSQL 사용 방향이 정해져 있으며 후속 구현 대상      |
| 저장소 비밀정보 검사           | GitHub Actions에서 Gitleaks로 Git 커밋 이력 검사                  |
| 사용자 업로드 파일의 보안 검사 | 설계 제안, 미구현                                                 |
| 보안 변화 비교·수정·공개       | 설계 제안, 미구현                                                 |

제품 범위·우선순위·결정 상태는 [개발 계획](docs/PLAN.md), 검사 방식과 지원 범위는 [보안 설계안](docs/SECURITY_DESIGN.md)에서 관리합니다.

## 기술 스택

| 영역            | 기술                                                                 |
| --------------- | -------------------------------------------------------------------- |
| Frontend        | React, TypeScript, Vite                                              |
| Backend         | Java, Spring Boot, Spring Security                                   |
| Auth            | Supabase Auth (Google), JWT                                          |
| Database        | Supabase PostgreSQL                                                  |
| Storage         | AWS S3 (비공개 버킷)                                                 |
| Security worker | 별도 저장소·실행 구성. 언어·도구 버전·작업 계약은 후속 이슈에서 확정 |

## 시작하기

### 요구 사항

- Node.js 24
- JDK 25

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

Supabase JWT issuer, JWKS 등 인증 관련 설정은 환경변수로 전달합니다. 설정 항목은 `backend/src/main/resources`의 설정 파일을 참고하세요. 루트의 `.env` 파일은 Spring Boot가 자동으로 읽지 않으므로, 터미널이나 IDE 실행 설정에서 환경변수를 지정해야 합니다.

이 명령은 현재 애플리케이션 기반을 실행하는 절차입니다. 아직 구현되지 않은 DB·S3·검사 워커의 실행 절차를 포함하지 않습니다. 실제 외부 연동 준비는 [설정 문서](docs/SETUP.md)를 참고하고, 기능 구현과 함께 갱신합니다.

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

작업에 필요한 검증 범위와 마무리 절차는 현행 [AGENTS.md](AGENTS.md)를 따릅니다. 실제 CI 실행 범위와 결과는 해당 PR의 워크플로에서 확인합니다.

## 문서

- [개발 목표·범위·완료 조건](docs/PLAN.md)
- [구조와 인증·데이터 정책](docs/ARCHITECTURE.md)
- [보안 검사 설계안](docs/SECURITY_DESIGN.md)
- [기존 기능 비교와 차별화 검증 계획](docs/DIFFERENTIATION.md)
- [외부 연동과 배포 준비](docs/SETUP.md)
- [구현된 API 명세](contracts/openapi.yaml)
- [합성 워크플로 샘플](contracts/examples/minimal-workflow.json)

## 기여하기

1. 사람이 이슈에 목적·범위·완료 조건·결정 사항을 기록합니다.
2. 작업자는 현행 [AGENTS.md](AGENTS.md)의 시작·마무리 절차를 따릅니다.
3. 문서의 제안·보류 상태와 구현 완료 상태를 구분하고, 변경 근거와 검증 결과를 남깁니다.
4. 사람이 결과를 확인하고 push·PR·리뷰·merge를 진행합니다.

스킬 경로와 PR 제목 규칙은 현행 [AGENTS.md](AGENTS.md), 자세한 기여 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 기준으로 합니다.

## 데이터 처리 원칙

- 원본 워크플로 파일은 비공개 S3, 메타데이터는 PostgreSQL에 저장하는 설계입니다. 실제 저장 기능은 후속 구현 대상입니다.
- 업로드한 워크플로·Code 노드·표현식을 서버에서 실행하지 않습니다.
- 검사 결과에도 비밀정보가 포함될 수 있으므로, 결과 마스킹과 접근 권한을 함께 설계합니다.
- 공개 기능은 특정 리비전과 공개용 결과를 대상으로 하며, 비공개 원본·부모 계보를 자동 공개하지 않는 방향으로 검토합니다.
- 로그인 토큰 갱신은 Supabase SDK가 처리하며, 브라우저에 저장된 토큰은 JavaScript에서 접근할 수 있습니다.
- 로그아웃 후에도 이미 발급된 Access Token은 만료 시점까지 유효할 수 있습니다.

## 라이선스

이 프로젝트는 [Apache License 2.0](LICENSE)에 따라 배포됩니다. 추가하는 검사 엔진과 외부 규칙의 사용 조건은 각 의존성의 라이선스에 따라 별도로 확인합니다.
