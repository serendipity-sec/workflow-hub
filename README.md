# Workflow Hub

외부에서 구한 n8n 워크플로를 내 계정·데이터에 연결하기 전에 위험 근거와 사용 조건을 확인하고, 수정·재검사한 정확한 버전을 선택하도록 돕는 서비스를 목표로 합니다. 워크플로별 버전 이력을 관리하며 프론트엔드와 백엔드는 한 저장소, 보안 워커는 별도 저장소로 구성할 계획입니다.

> 보안 검사·수정·공개는 팀 검토용 설계입니다. 현재 제공하는 기능은 아래 구현 현황에서 확인할 수 있습니다.

## 제품 목표와 검토 중인 기능

- Google 계정 로그인과 개인 비공개 워크플로 관리
- 원본과 수정본을 덮어쓰지 않는 버전 관리 및 다운로드
- 버전별 보안 검사와 노드·필드·데이터 흐름에 연결된 근거 제공
- 이전 버전과 비교한 새 위험, 해소된 위험, 분석하지 못한 부분 표시
- 수정 안내, 수정본 업로드, 새 버전 생성, 재검사의 연결
- 사용 조건과 검사 범위를 포함한 특정 버전 공개·재사용

1차에는 대표 위험 경로 1~2개의 제한된 분석과 근거 표시, 수동 수정본의 재검사·비교, 특정 버전 공개·다운로드를 연결합니다. 공개 정책과 최초 지원 노드·버전은 해당 구현 전에 결정합니다. 자동 수정, Python·Merge 등 복잡한 흐름 분석, 실제 환경·패키지 연동, AI 동적 평가는 기회와 필요성이 확인될 때 별도로 검토하는 선택적 고도화입니다. 상세 범위와 완료 조건은 [1차 구현과 선택적 고도화](docs/PLAN.md#5-단계별-구현-순서-제안)를 따릅니다.

검사 결과는 확인한 범위의 근거를 제공하며, 모든 실행 환경에서의 안전성을 보증하는 표시로 사용하지 않습니다. 파일·검사 버전과 미지원·실패 상태는 처음부터 기록하고, 고급 기능의 미구현을 안전 판정으로 바꾸지 않습니다.

n8n의 템플릿 심사·보안 감사·버전 리뷰, 제3자 공유 경로, 공개 검사기의 흐름 분석·보안 변경 비교를 비교 기준으로 삼습니다. 검증이 실제 작업 값과 경로에 적용되는지 분석하고, 사용자의 허용 목적지·데이터 정책과 수정 효과를 연결하는 것이 차별화 후보입니다. 기존 도구보다 정확하거나 악성 워크플로를 모두 막는다고 확인된 상태는 아닙니다. 조사 출처, 공개 취약 사례와 악성 패키지의 구분, 해결 범위 및 비교 계획은 [차별화 근거와 검증 계획](docs/DIFFERENTIATION.md)을 참고하세요.

## 현재 구현 상태

저장소의 코드와 백엔드의 OpenAPI 문서(Swagger UI) 기준입니다. 외부 서비스는 배포 환경에서 연결을 검증해야 합니다.

| 영역                           | 상태                                                                                                                                                     |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 프론트·백엔드 기반             | 실행 구조, 로그인 연결 코드, JWT 검증, 개발 도구·검사 설정이 있음                                                                                        |
| 구현된 HTTP API                | 상태·사용자 확인, 최초 업로드, 소유자별 조회, 변경점 비교·버전 등록, 원본 다운로드·허용 상태 변경, 버전·워크플로 삭제와 복구. 정확한 계약은 OpenAPI 참조 |
| 워크플로·버전 DB 기반          | PostgreSQL 연결·Flyway 및 소유자/버전 메타데이터 스키마·제약 구현                                                                                        |
| 워크플로 서비스·S3 저장        | 비공개 원본·비교 파일 저장 및 소유자별 다운로드 구현. 실제 개발용 S3 연동 미검증                                                                         |
| 저장소 비밀정보 검사           | GitHub Actions에서 Gitleaks로 Git 커밋 이력 검사                                                                                                         |
| 사용자 업로드 파일의 보안 검사 | 설계 제안, 미구현                                                                                                                                        |
| 보안 변화 비교·수정·공개       | 설계 제안, 미구현                                                                                                                                        |

제품 범위·우선순위·결정 상태는 [개발 계획](docs/PLAN.md), 검사 방식과 지원 범위는 [보안 설계안](docs/SECURITY_DESIGN.md)에서 관리합니다.

[#8](https://github.com/serendipity-sec/workflow-hub/issues/8)·[#10](https://github.com/serendipity-sec/workflow-hub/pull/10)에 따라 새 워크플로는 `v1`에서 시작하고, 작은 업데이트는 `v1.1`, `v1.2`, 주요 업데이트는 `v2`처럼 다음 정수 버전으로 올립니다. 파생 기능을 도입하면 파생본은 독립 워크플로의 `v1`이며, 부모·자식 버전 트리는 현재 DB 모델에 포함하지 않습니다. 수정 기준과 결과 버전, 출처·검사 이력의 연결은 후속 보안 확장 제안입니다.

[#27](https://github.com/serendipity-sec/workflow-hub/issues/27)의 `MINOR`는 선택한 계열의 최신 버전에서 올립니다. `v2` 등록 후에도 `v1.1`에서 `v1.2`를 만들 수 있습니다. `MAJOR`는 번호가 가장 높은 계열의 최신 버전에서 올립니다. 다운로드를 중지한 버전은 소유자가 다시 허용할 수 있습니다.

[#37](https://github.com/serendipity-sec/workflow-hub/issues/37)의 삭제는 버전을 지우지 않고 삭제 표시만 해서 즉시 조회·다운로드·비교에서 제외하며, 삭제한 번호는 다시 쓰지 않습니다. 소유자는 삭제 후 7일(`WORKFLOW_DELETE_GRACE`) 안에 복구할 수 있고, 이후 S3 원본을 지웁니다. 살아 있는 버전이 하나뿐일 때 그 버전을 삭제하면 워크플로 전체가 삭제됩니다. 삭제된 항목은 목록의 `includeDeleted=true`로 조회합니다.

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

실행 전에 `backend/.env.example`을 참고해 `DATABASE_URL`(JDBC URL), `DATABASE_USERNAME`, `DATABASE_PASSWORD`, `WORKFLOW_BUCKET`(S3 없이 실행할 때는 아무 이름)을 터미널이나 IDE의 프로세스 환경변수로 지정합니다. Supabase JWT issuer, JWKS 등 인증 설정도 환경변수로 전달합니다. Spring Boot는 `.env` 파일을 자동으로 읽지 않습니다.

백엔드는 시작 시 Flyway로 `backend/src/main/resources/db/migration/`의 마이그레이션을 적용합니다. 초기 연결 계정은 `workflow_hub` 스키마와 테이블·마이그레이션 이력을 관리할 권한이 필요합니다. Supabase에서는 이 스키마를 Data API의 exposed schemas에 추가하지 않습니다. 현재 하나의 datasource로 마이그레이션도 실행하므로 운영 역할 분리는 별도 보강 대상입니다.

이 명령은 현재 인증·DB 기반을 실행하는 절차이며 S3·검사 워커 실행은 포함하지 않습니다. 실제 Google·Supabase·S3 연동, TLS·역할별 권한은 별도 환경에서 확인해야 합니다. [설정 문서](docs/SETUP.md)

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

작업에 필요한 검증 범위와 마무리 절차는 현행 [AGENTS.md](AGENTS.md)를 따릅니다. 백엔드 테스트는 Testcontainers로 일회용 PostgreSQL을 실행하며 운영 DB나 실제 Supabase 자격 증명은 필요하지 않습니다. 컨테이너 이미지를 처음 내려받을 때는 네트워크가 필요합니다. 실제 CI 실행 범위와 결과는 해당 PR의 워크플로에서 확인합니다.

## 문서

- [개발 목표·범위·완료 조건](docs/PLAN.md)
- [구조와 인증·데이터 정책](docs/ARCHITECTURE.md)
- [보안 검사 설계안](docs/SECURITY_DESIGN.md)
- [차별화 근거와 검증 계획](docs/DIFFERENTIATION.md)
- [외부 연동과 배포 준비](docs/SETUP.md)
- [n8n JSON 입력 한도와 측정 기록](docs/INPUT_LIMITS.md)
- API 명세: 백엔드를 `API_DOCS_ENABLED=true`로 실행하고 `/swagger-ui.html` 확인 ([설정](docs/SETUP.md))
- [합성 워크플로 샘플](backend/src/test/resources/samples/minimal-workflow.json)

## 기여하기

1. 사람이 이슈에 목적·범위·완료 조건·결정 사항을 기록합니다.
2. 작업자는 현행 [AGENTS.md](AGENTS.md)의 시작·마무리 절차를 따릅니다.
3. 문서의 제안·보류 상태와 구현 완료 상태를 구분하고, 변경 근거와 검증 결과를 남깁니다.
4. 사람이 결과를 확인하고 push·PR·리뷰·merge를 진행합니다.

스킬 경로와 PR 제목 규칙은 현행 [AGENTS.md](AGENTS.md), 자세한 기여 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 기준으로 합니다.

## 데이터 처리 원칙

- 소유자별 업로드·조회·버전 등록·다운로드 API는 PostgreSQL 메타데이터와 비공개 S3의 원본 바이트를 사용합니다. 버전별 원본 파일 해시·크기를 서버가 기록하고 버전 조회 응답에 포함합니다(V6 이전 버전은 미확인). 검사 기록은 후속 범위입니다.
- 업로드한 워크플로·Code 노드·표현식을 서버에서 실행하지 않습니다.
- 최초 업로드와 버전 비교는 중첩 깊이 64·노드 300·연결 1,500 한도(환경 변수로 조정)를 넘는 JSON을 `422 WORKFLOW_LIMIT_EXCEEDED`로 거절하며, 거절된 요청은 S3와 DB에 아무것도 남기지 않습니다. 값의 근거와 측정·미검증 항목은 [입력 한도 문서](docs/INPUT_LIMITS.md)에 있습니다.
- 검사 결과에도 비밀정보가 포함될 수 있으므로, 결과 마스킹과 접근 권한을 함께 설계합니다.
- 공개 기능은 특정 버전과 공개용 결과를 대상으로 하며, 다른 비공개 버전·원본·상세 결과를 자동 공개하지 않는 방향으로 검토합니다.
- 검사한 파일과 다운로드 파일의 일치를 확인하더라도, 사용자가 수정한 파일이나 실제 n8n 실행 환경 전체의 안전성을 보증하지 않습니다.
- 로그인 토큰 갱신은 Supabase SDK가 처리하며, 브라우저에 저장된 토큰은 JavaScript에서 접근할 수 있습니다.
- 로그아웃 후에도 이미 발급된 Access Token은 만료 시점까지 유효할 수 있습니다.

## 라이선스

이 프로젝트는 [Apache License 2.0](LICENSE)에 따라 배포됩니다. 추가하는 검사 엔진과 외부 규칙의 사용 조건은 각 의존성의 라이선스에 따라 별도로 확인합니다.
