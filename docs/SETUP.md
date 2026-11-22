# 외부 연동과 최초 업로드

## Supabase와 Google

1. 개발용 Supabase 프로젝트의 URL과 공개용 publishable key를 `frontend/.env.local`의 `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`에 설정한다.
2. Google Auth Platform에서 `Web application` OAuth 클라이언트를 만든다. Authorized JavaScript origins에는 프론트 주소를, Authorized redirect URIs에는 Supabase의 Google 공급자 화면에 표시된 콜백 주소를 등록한다. Supabase에서 Google 공급자를 켜고 발급받은 Client ID와 Client Secret을 해당 공급자 설정에 저장한다. [Supabase Google 로그인 설정](https://supabase.com/docs/guides/auth/social-sign-in/auth-google#project-setup)
3. Supabase redirect allowlist에는 브라우저가 실제로 접속할 프론트 주소를 등록한다. 로컬 개발 기본값은 `http://127.0.0.1:5173`이다. 운영에서는 광범위 wildcard를 피한다.
4. 같은 프로젝트의 비대칭 JWT signing key를 확인한다. 백엔드 환경변수 `SUPABASE_JWT_ISSUER`에는 프로젝트 URL 뒤에 `/auth/v1`을 붙인 값을, `SUPABASE_JWKS_URI`에는 issuer 뒤에 `/.well-known/jwks.json`을 붙인 값을 사용한다. 백엔드의 audience는 `authenticated`다.
5. refresh token rotation과 재사용 허용 설정을 확인한다. React SDK와 별도 갱신 타이머를 함께 실행하지 않는다.

### 로컬 브라우저에서 `/api/me` 검증

PostgreSQL 연결을 준비한 뒤 백엔드를 `./gradlew bootRun`으로, 프론트를 `npm run dev`로 실행한다. Vite는 `/api/` 요청을 로컬 백엔드로 전달한다. `http://127.0.0.1:5173`에서 **Google로 로그인**을 누른다. 앱으로 돌아와 **로그아웃** 버튼이 보이면 같은 탭의 개발자 도구 콘솔에서 실행한다.

```js
await (async () => {
  const { supabase } = await import('/src/features/auth/client.ts');
  const { authenticatedFetch } = await import('/src/features/auth/api.ts');

  const { data: initial, error: loginError } = await supabase.auth.getSession();
  if (loginError || !initial.session) throw new Error('Google 로그인 세션을 확인하세요.');

  const before = await authenticatedFetch('/api/me');
  const beforeMatches = (await before.json()).id === initial.session.user.id;

  const { data: refreshed, error: refreshError } = await supabase.auth.refreshSession();
  if (refreshError || !refreshed.session) throw new Error('Supabase 세션 갱신에 실패했습니다.');

  const after = await authenticatedFetch('/api/me');
  console.table({
    loginStatus: before.status,
    loginIdMatches: beforeMatches,
    refreshStatus: after.status,
    refreshIdMatches: (await after.json()).id === refreshed.session.user.id,
    sameUser: initial.session.user.id === refreshed.session.user.id,
    accessTokenChanged: initial.session.access_token !== refreshed.session.access_token,
  });
})();
```

두 상태 코드는 `200`이고 비교 결과는 모두 `true`여야 한다. 이 절차는 갱신을 한 번 요청해 갱신 이후의 인증을 확인한다. [Supabase `refreshSession` 문서](https://supabase.com/docs/reference/javascript/auth-refreshsession)

화면의 **로그아웃**을 누르고 로그인 버튼이 다시 나타나면 같은 콘솔에서 실행한다. `sessionCleared`가 `true`이고 `status`가 `401`이어야 한다. 인증 클라이언트는 세션이 없으면 요청 전에 중단하므로, 서버 응답은 인증 헤더 없는 브라우저 요청으로 확인한다.

```js
await (async () => {
  const { supabase } = await import('/src/features/auth/client.ts');
  const { data, error } = await supabase.auth.getSession();
  const response = await fetch('/api/me', { credentials: 'omit', cache: 'no-store' });
  console.table({ sessionCleared: !error && data.session === null, status: response.status });
})();
```

서명과 발급자 불일치 등 토큰 거부는 백엔드 자동 테스트에서 확인한다. 실제 연동 결과는 자동 테스트 결과와 구분해 PR이나 배포 기록에 남긴다. 상태 코드와 비교 결과만 기록하고 토큰, 이메일, 사용자 ID는 기록하지 않는다. 운영 키는 GitHub/배포 플랫폼의 비밀 저장소로 관리한다.

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
