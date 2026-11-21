# 외부 연동과 최초 업로드

## Supabase와 Google

1. 개발용 Supabase 프로젝트를 준비한다. 프로젝트 URL과 공개용 publishable key를 프론트 환경변수에 설정한다.
2. Supabase Google provider에 필요한 Google OAuth 앱을 등록한다. Google 쪽 callback은 Supabase 대시보드가 안내하는 주소를 사용한다.
3. Supabase redirect allowlist에는 실제 프론트 개발/배포 주소를 등록한다. 운영에서는 광범위 wildcard를 피한다.
4. 프로젝트의 비대칭 JWT signing key와 JWKS를 확인한다. 백엔드 issuer/audience/JWKS를 같은 프로젝트로 설정한다.
5. refresh token rotation과 재사용 허용 설정을 확인한다. React SDK와 별도 갱신 타이머를 함께 실행하지 않는다.
6. 실제 Google 로그인, `/api/me`, 갱신 후 요청, 로그아웃, 다른 프로젝트 토큰 거부를 검증한다.

외부 프로젝트 설정은 코드 테스트로 증명되지 않는다. 실제 검증 결과를 PR이나 배포 기록에 남긴다. 운영 키는 GitHub/배포 플랫폼의 비밀 저장소로 관리한다.

## PostgreSQL

백엔드는 `DATABASE_URL`(JDBC URL), `DATABASE_USERNAME`, `DATABASE_PASSWORD` 환경변수로 PostgreSQL에 연결한다. Supabase 연결 시 제공되는 TLS 연결 설정을 사용하고, 비밀번호를 URL이나 저장소에 넣지 않는다. `.env` 파일은 자동으로 읽지 않는다.

시작 시 Flyway가 `backend/src/main/resources/db/migration/`의 SQL을 적용한다. 초기 연결 계정은 `workflow_hub` 스키마를 생성하고 테이블과 마이그레이션 이력을 관리할 권한이 필요하다. DB 연결이나 마이그레이션이 실패하면 시작도 실패한다. 배포 시 마이그레이션과 런타임 계정을 분리한다면 각 계정의 권한을 별도로 확인한다.

`workflow_hub`는 백엔드 전용 스키마로 두고, Supabase Data API의 exposed schemas에 추가하지 않는다. 실제 Supabase 프로젝트의 연결·권한·노출 설정은 별도 검증한다. 백엔드 테스트는 Docker에서 일회용 PostgreSQL을 실행하며 운영 자격 증명을 사용하지 않는다.

## S3: 업로드 기능 구현 시 연결

S3는 Block Public Access를 활성화하고 개발/운영 리소스를 구분한다. 런타임 IAM 역할을 우선 사용하며 장기 AWS 키를 저장소에 넣지 않는다. 업로드 기능에서 객체 크기 제한, 비밀정보 로그 제외, DB 실패 시 객체 정리, 삭제 정책을 함께 구현한다.

## GitHub 최초 설정

- README 초안을 사용자에게 검토받은 뒤 최초 push한다.
- 원격 소유자·공개 여부는 확정 후 생성한다. 준비 단계의 기본안은 비공개다.
- Squash merge를 활성화하고 다른 머지 방식을 비활성화한다.
- squash commit 기본 제목을 PR 제목으로 설정한다.
- CI가 실제 실행된 뒤 정확한 job 이름으로 필수 검사를 지정한다.
- main 직접 push/force push 제한과 일반 PR 리뷰 정책은 팀 운영에 맞춰 설정한다. README 최초 검토가 모든 README 수정에 대한 사용자 승인 의무를 뜻하지는 않는다.
- 영역 라벨과 템플릿을 적용한다. 파일에 설정이 있어도 서버 측 branch protection이나 labels가 자동 적용되었다고 간주하지 않는다.
- fork PR CI에 secrets를 노출하지 않는다. PR 검사에 `pull_request_target`으로 사용자 코드를 실행하지 않는다.

이 체크리스트는 실제 실행 기록이 아니다. 원격 생성·push·리소스 배포는 이번 로컬 기반 작업에서 수행하지 않는다.
