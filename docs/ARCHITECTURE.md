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

## 데이터: 후속 구현 모델

- User: Supabase 사용자 ID와 서비스 프로필.
- Workflow: 소유자, 제목, 비공개 기본값.
- Revision: workflow ID, parent revision ID, 서버 발급 순번, S3 객체 키, fingerprint, 생성자/시간.
- 같은 workflow 내 순번은 DB unique constraint/transaction으로 발급한다. 번호는 계보를 인코딩하지 않는다.
- 저장된 리비전의 파일은 덮어쓰지 않는다. 부모 연결은 접근 권한을 확인한다.
- 파일 내용 기반 중복 판별과 의미 유사도 검색은 분리한다. fingerprint만으로 공개되지 않은 타인 파일의 존재를 노출하지 않는다.

Supabase PostgreSQL은 백엔드에서 접속한다. 브라우저의 Data API 직접 접근은 초기 구성에 포함하지 않는다. 테이블을 exposed schema에 추가한다면 RLS/권한을 함께 구성한다. 서버 DB 연결이 RLS를 우회할 수 있으므로 사용자별 인가는 항상 API에서 검증한다.

S3 버킷은 비공개다. 서버 생성 객체 키를 쓰며 승인한 사용자에게만 짧은 수명의 다운로드 URL 또는 스트리밍 응답을 제공한다. presigned URL은 유효 기간 동안 접근 가능한 비밀값처럼 다룬다. S3 versioning과 앱의 revision 관계는 별개다.

DB와 S3 작업은 원자적이지 않다. 업로드 기능에서는 업로드 실패/DB 저장 실패 후 정리와 재시도 정책을 구현한다. 삭제와 보관 정책은 실제 업로드 출시 전에 확정한다. 백업 정책도 삭제 정책과 함께 정의한다.

## 업로드 경계

JSON 파싱과 허용 크기/구조 검사를 수행한다. 내용의 안전성을 보증하지 않는다. workflow 코드·표현식은 실행하지 않는다. 샘플은 합성 데이터만 사용한다. 업로드 본문·인증 헤더·다운로드 URL은 로그에 남기지 않는다.

## 출처

- [Supabase sessions/RTR](https://supabase.com/docs/guides/auth/sessions)
- [Supabase signing keys](https://supabase.com/docs/guides/auth/signing-keys)
- [Supabase pgvector](https://supabase.com/docs/guides/database/extensions/pgvector)

이 문서는 새로운 workflow-hub의 기준이다. 이전 mackerel 문서의 보안 필수/일시 저장/FastAPI 설계를 자동 상속하지 않는다.
