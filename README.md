# Workflow Hub

n8n 워크플로 JSON을 업로드하고, 수정 이력을 리비전 트리로 관리하며, 원하는 시점의 버전을 다운로드할 수 있는 웹 서비스입니다. 프론트엔드와 백엔드를 한 저장소에서 관리합니다.

## 주요 기능

- Google 계정 로그인 (Supabase Auth)
- n8n 워크플로 JSON 업로드 및 다운로드
- 워크플로 수정 계보(리비전 트리) 관리
- 개인 비공개 워크플로 저장

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

Gradle은 `backend`의 Wrapper(`gradlew`)를 사용하므로 별도 설치가 필요하지 않습니다.

### 프론트엔드

```sh
# 저장소 루트: 문서/계약 검사 도구
npm ci

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

CI에서도 동일한 명령을 실행합니다.

## 문서

- [범위와 일정](docs/PLAN.md)
- [구조와 인증·데이터 정책](docs/ARCHITECTURE.md)
- [API 명세](contracts/openapi.yaml)
- [워크플로 샘플](contracts/examples/minimal-workflow.json)

## 기여하기

1. 이슈를 먼저 등록해 변경 내용을 공유합니다.
2. 브랜치를 만들어 작업하고, 위의 테스트와 빌드 명령이 모두 통과하는지 확인합니다.
3. PR 제목은 `feat(workflow): 업로드 기능 추가`처럼 `type(scope): 설명` 형식으로 작성하고, frontend/backend 영역 라벨을 붙입니다.

자세한 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

## 데이터 처리

- 원본 워크플로 파일은 S3에, 메타데이터는 PostgreSQL에 저장합니다.
- 업로드한 워크플로는 서버에서 실행하지 않습니다.
- 로그인 토큰 갱신은 Supabase SDK가 처리하며, 브라우저에 저장된 토큰은 JavaScript에서 접근할 수 있습니다.
- 로그아웃 후에도 이미 발급된 Access Token은 만료 시점까지 유효할 수 있습니다.

## 라이선스

이 프로젝트는 [Apache License 2.0](LICENSE)에 따라 배포됩니다.
