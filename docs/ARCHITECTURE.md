# 구조와 경계

## 저장소

```text
frontend/      React UI, 기능별 auth/workflow 영역
backend/       Spring Boot API, 도메인별 패키지
contracts/     구현된 OpenAPI와 합성 샘플
docs/          범위, 구조, 운영 준비
.github/       CI와 작업 템플릿
```

과도한 공통 추상화와 다수의 Gradle 모듈은 만들지 않는다. 초기에는 프론트 앱 하나, 백엔드 앱 하나다. 별도 보안 워커나 벡터 검색은 API/작업 계약이 필요해질 때 추가한다.

## 인증

Google → Supabase Auth → React → Bearer Access Token → Spring Boot → 사용자 소유권 검사.

기반 구현 선택: React의 Supabase SDK가 PKCE 로그인과 토큰 갱신을 관리한다. SDK의 브라우저 지속 저장을 사용하므로 토큰이 JavaScript에서 접근 가능하다. 이는 HttpOnly 쿠키 방식과 동일한 보호를 제공하지 않는다. 임의 HTML 삽입을 피하고 토큰을 로그·URL·분석 도구에 보내지 않는다. 배포 시 CSP를 설정한다. 향후 refresh token을 HttpOnly 쿠키로 옮기려면 갱신 주체를 백엔드로 변경하는 별도 설계가 필요하다.

Supabase의 RTR과 재사용 탐지 기능을 사용한다. 병렬 갱신을 위한 공급자 예외를 인정하고 자체 회전 DB나 타이머를 중복 구현하지 않는다. Supabase 내부의 인증 세션은 존재하나 우리 API는 HttpSession 로그인에 의존하지 않는다.

백엔드는 비대칭 JWKS 서명, issuer, audience, 만료를 검증한다. Supabase 사용자 `sub`를 사용자 식별자로 사용한다. 프론트가 넘긴 이메일/owner_id는 인증 근거가 아니다. 로그인용 사용자 토큰만 허용하며 secret/service-role 키를 사용자 인증으로 취급하지 않는다.

로그아웃은 브라우저 토큰을 지우고 공급자 갱신 세션을 종료한다. 이미 발급된 JWT는 만료 전까지 로컬 서명 검증에 통과할 수 있다. 즉시 폐기가 필요해지면 별도 서버 확인/차단 설계를 추가한다. JWT를 단순 디코딩한 값으로 권한을 판정하지 않는다.

## 데이터: 워크플로와 버전

#8의 결정에 따라 리비전 트리 대신 워크플로별 버전 이력을 저장한다. 실행되는 DB 구조의 기준은 `backend/src/main/resources/db/migration/`의 버전 관리되는 SQL이다.

- Workflow: 식별자, 소유자, 제목. 소유자는 검증된 Supabase JWT의 `sub`에 대응하는 문자열이며, 별도 서비스 사용자 테이블이나 `auth.users` 외래 키는 추가하지 않는다.
- Version: 식별자, 소속 workflow ID, 버전 번호, S3 객체 키, 생성 시각.
- 첫 버전은 `v1`, 작은 업데이트는 `v1.1`, `v1.2`, 주요 업데이트는 `v2`처럼 다음 정수 버전이다. 번호의 선택과 발급은 후속 업로드 서비스에서 구현한다.
- 같은 workflow의 버전 번호는 DB unique constraint로 중복을 거부한다. 서로 다른 workflow는 같은 버전 번호를 가질 수 있다. workflow 외래 키는 존재하지 않는 workflow에 버전을 저장하지 못하게 한다.
- 예: A에는 `v1`, `v1.1`, `v2`, B에는 독립적으로 `v1`을 저장할 수 있다. A에 `v1`을 다시 추가하면 DB가 거부한다.
- 저장된 버전의 파일은 불변이다. 업데이트 시 새 버전 레코드와 별도 파일을 추가한다. 실제 S3 저장과 덮어쓰기 방지는 후속 업로드 구현의 책임이며, 이번 마이그레이션만으로 파일 불변성을 보장하지 않는다.
- 파생본은 독립된 workflow의 `v1`로 시작한다. 부모 버전·계보 관계와 파생 기능은 이번 DB 모델에 포함하지 않는다.

Supabase PostgreSQL은 백엔드에서 접속한다. 테이블은 `workflow_hub` 스키마에 두며, Supabase Data API의 exposed schemas에 추가하지 않는다. 브라우저의 Data API 직접 접근은 초기 구성에 포함하지 않는다. 향후 노출 스키마에 추가한다면 RLS/권한을 함께 구성한다. 서버 DB 연결이 RLS를 우회할 수 있으므로 후속 서비스 API의 사용자별 인가는 항상 API에서 검증한다.

백엔드는 `DATABASE_URL`, `DATABASE_USERNAME`, `DATABASE_PASSWORD`로 PostgreSQL에 연결하고 시작 시 Flyway 마이그레이션을 적용한다. DB 연결과 마이그레이션 실패는 시작 실패로 처리한다. 테스트에서는 Testcontainers의 일회용 PostgreSQL을 사용한다. HTTP API 계약은 변경하지 않으며, 실제 업로드·조회·다운로드는 아직 구현하지 않는다.

S3 버킷은 비공개로 구성할 예정이다. 후속 다운로드 구현은 서버 생성 객체 키를 쓰며 승인한 사용자에게만 짧은 수명의 다운로드 URL 또는 스트리밍 응답을 제공한다. presigned URL은 유효 기간 동안 접근 가능한 비밀값처럼 다룬다. S3 versioning과 앱의 버전 번호는 별개다.

DB와 S3 작업은 원자적이지 않다. 업로드 기능에서는 업로드 실패/DB 저장 실패 후 정리와 재시도 정책을 구현한다. 삭제와 보관 정책은 실제 업로드 출시 전에 확정한다. 백업 정책도 삭제 정책과 함께 정의한다.

## 업로드 경계

JSON 파싱과 허용 크기/구조 검사를 수행한다. 내용의 안전성을 보증하지 않는다. workflow 코드·표현식은 실행하지 않는다. 샘플은 합성 데이터만 사용한다. 업로드 본문·인증 헤더·다운로드 URL은 로그에 남기지 않는다.

## 출처

- [Supabase sessions/RTR](https://supabase.com/docs/guides/auth/sessions)
- [Supabase signing keys](https://supabase.com/docs/guides/auth/signing-keys)
- [Supabase pgvector](https://supabase.com/docs/guides/database/extensions/pgvector)

이 문서는 새로운 workflow-hub의 기준이다. 이전 mackerel 문서의 보안 필수/일시 저장/FastAPI 설계를 자동 상속하지 않는다.
