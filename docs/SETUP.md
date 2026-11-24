# 외부 연동과 최초 업로드

## Supabase와 Google

1. 개발용 Supabase 프로젝트의 URL과 공개용 publishable key를 `frontend/.env.local`의 `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`에 설정한다.
2. Google Auth Platform에서 `Web application` OAuth 클라이언트를 만든다. Authorized JavaScript origins에는 프론트 주소를, Authorized redirect URIs에는 Supabase의 Google 공급자 화면에 표시된 콜백 주소를 등록한다. Supabase에서 Google 공급자를 켜고 발급받은 Client ID와 Client Secret을 해당 공급자 설정에 저장한다. [Supabase Google 로그인 설정](https://supabase.com/docs/guides/auth/social-sign-in/auth-google#project-setup)
3. Supabase redirect allowlist에는 브라우저가 실제로 접속할 프론트 주소를 등록한다. 로컬 개발 기본값은 `http://127.0.0.1:5173`이다. 운영에서는 광범위 wildcard를 피한다.
4. 같은 프로젝트의 비대칭 JWT signing key를 확인한다. 백엔드 환경변수 `SUPABASE_JWT_ISSUER`에는 프로젝트 URL 뒤에 `/auth/v1`을 붙인 값을, `SUPABASE_JWKS_URI`에는 issuer 뒤에 `/.well-known/jwks.json`을 붙인 값을 사용한다. 백엔드의 audience는 `authenticated`다.
5. refresh token rotation과 재사용 허용 설정을 확인한다. React SDK와 별도 갱신 타이머를 함께 실행하지 않는다.

### 로컬 브라우저에서 `/api/me` 검증

PostgreSQL 연결과 `WORKFLOW_BUCKET`(필수, S3 없이 실행하면 아무 이름이나 지정. [S3 절](#s3-업로드-저장소) 참조)을 준비한 뒤 백엔드를 `./gradlew bootRun`으로, 프론트를 `npm run dev`로 실행한다. Vite는 `/api/` 요청을 로컬 백엔드로 전달한다. `http://127.0.0.1:5173`에서 **Google로 로그인**을 누른다. 앱으로 돌아와 **로그아웃** 버튼이 보이면 같은 탭의 개발자 도구 콘솔에서 실행한다.

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

## S3: 업로드 저장소

S3는 Block Public Access를 활성화하고 개발/운영 리소스를 구분한다. 런타임 IAM 역할을 우선 사용하며 장기 AWS 키를 저장소에 넣지 않는다. 업로드 기능에서 객체 크기 제한, 비밀정보 로그 제외, DB 실패 시 객체 정리, 삭제 정책을 함께 구현한다.

백엔드는 `AWS_REGION`(기본 `ap-northeast-2`)과 `WORKFLOW_BUCKET`을 읽고, 자격 증명은 AWS 기본 공급자 체인(환경 변수, 프로필, 역할)에서 가져온다. `WORKFLOW_BUCKET`은 필수이며 비어 있으면 앱이 시작되지 않는다. 파일을 사용하는 API와 만료된 비교본 정리는 S3를 호출한다. S3 요청 시간 제한은 `S3_ATTEMPT_TIMEOUT`(기본 20s)과 `S3_CALL_TIMEOUT`(기본 60s)로 바꾼다.

런타임 역할에는 해당 버킷의 `workflows/*` 객체에 대한 `s3:PutObject`, `s3:DeleteObject`, `s3:GetObject`가 필요하다. 삭제 권한은 참조 없는 업로드 파일, 만료된 비교본, 복구 기간이 끝난 삭제 버전의 원본을 정리할 때 사용한다. 삭제한 버전의 복구는 `HeadObject`로 원본이 남아 있는지 확인하므로 같은 버킷의 `s3:ListBucket`(`workflows/*` 접두사로 제한)도 필요하다. 이 권한이 없으면 없는 객체도 `403`으로 응답되어, 백엔드는 이를 "없음"으로 단정하지 않고 복구를 `503 STORAGE_UNAVAILABLE`로 중단한다. 이 권한은 실제 S3에서 검증하지 않았다. 비교 ID는 24시간 뒤 만료되며, 백엔드에서 `workflows/comparisons/` 임시 파일을 주기적으로 삭제하고 실패하면 재시도한다. 실제 삭제 시점은 정리 작업의 실행과 S3 응답에 달려 있다.

참조 없는 업로드 객체는 `pending_objects` 기록을 바탕으로 백엔드가 자동 정리한다. 기록 생성 후 `PENDING_OBJECT_GRACE`(기본 30m)가 지나야 정리하며, 이 값은 요청 하나의 최대 소요(S3 호출 제한 `S3_CALL_TIMEOUT` 포함)보다 충분히 길어야 하며, `S3_CALL_TIMEOUT`의 2배보다 짧으면 앱이 시작되지 않는다. 대기 시간이 지나면 요청이 아직 진행 중이어도 정리 작업이 객체를 지우고, 그 요청은 커밋하지 않고 `503 STORAGE_UNAVAILABLE`로 실패하므로 같은 `Idempotency-Key`로 다시 시도한다. 삭제 실패 시 `CLEANUP_RETRY_DELAY`(기본 5m) 뒤 다시 시도하고, 정리 작업은 `PENDING_OBJECT_CLEANUP_INTERVAL`(기본 10s) 간격으로 실행된다. 삭제가 계속 실패해도 시도 횟수 제한이나 알림은 없으며, 남은 행은 `workflow_hub.pending_objects`와 `workflow.object_cleanup.delete_failed` 로그로 확인한다. 이 정리는 S3 versioning을 끈 버킷을 전제로 한다(개발 버킷은 versioning을 쓰지 않기로 했으며, 실제 상태는 개발 S3 검증 때 확인해 기록한다). 이 기능을 넣기 전에 남은 고아 객체나 대기 시간 뒤에 늦게 완료된 쓰기는 자동 정리되지 않는다.

삭제한 버전과 워크플로(#37)는 먼저 DB에서 접근을 막고, `WORKFLOW_DELETE_GRACE`(기본 7d)가 지난 뒤 백엔드가 S3 원본을 `DeleteObject`로 지운다. 이 기간 안에는 소유자가 복구 API로 되살릴 수 있다. 정리 작업은 기존 `PENDING_OBJECT_CLEANUP_INTERVAL` 간격으로 실행되고, 삭제가 실패하면 `CLEANUP_RETRY_DELAY` 뒤 다시 시도한다. 원본을 지운 뒤에도 DB에는 버전 번호와 삭제 시각만 남고(객체 키·해시·크기·워크플로 제목은 비운다) 번호는 다시 쓰지 않는다. 정리는 S3 versioning을 끈 버킷을 전제로 하며, 이 경우 삭제된 원본은 복구할 수 없다. 이 프로젝트는 S3 복제나 AWS Backup을 쓰지 않는다고 가정한다(사용한다면 해당 사본의 만료 규칙을 따로 정해야 한다). Supabase의 DB 백업에는 파일 내용이 없고 제목·객체 키·해시·크기 같은 메타데이터만 있으며, 백업이 만료되기 전까지 남을 수 있다. 보관 기간은 플랫폼 요금제에 따르므로 배포 환경에서 확인해 기록한다. DB를 백업에서 복원하면 이미 원본을 지운 버전의 행이 되살아날 수 있으므로, 복원 뒤에는 S3에서 객체 존재를 확인해 없는 행을 삭제·정리 완료로 다시 표시한다. 이 점검은 자동화하지 않았다.

버킷 versioning을 켜면 삭제 마커 뒤에 이전 객체 버전이 남는다. 임시 파일 접두사에는 이전 객체 버전을 제거할 수명 주기 규칙을 적용하고, 보관 기간을 배포 정책에 반영한다. 규칙의 범위를 `workflows/comparisons/`로 제한해 정식 버전 경로에 임시 파일 보관 기한이 적용되지 않게 한다.

자동 테스트는 합성 JSON과 mock 저장소를 사용해 다운로드 바이트 보존과 권한 거부를 확인한다. AWS 클라이언트 호출은 mock으로 확인한다. 실제 개발용 비공개 S3 연동은 미검증이며, 해당 환경의 런타임 역할로 합성 JSON을 업로드한 뒤 같은 버전을 다운로드해 원본 바이트 일치 여부와 결과를 별도로 기록한다.

## n8n JSON 입력 한도

최초 업로드와 버전 비교는 파일 크기 5 MiB 외에 중첩 깊이, 노드 수, 연결 수 한도를 검사한다. 값은 환경 변수로 바꾸며 바꾼 뒤에는 서버를 재시작해야 한다.

| 환경 변수                  | 기본값 | 의미                                   |
| -------------------------- | ------ | -------------------------------------- |
| `WORKFLOW_MAX_DEPTH`       | 64     | 루트 객체를 1로 센 배열·객체 중첩 수   |
| `WORKFLOW_MAX_NODES`       | 300    | `nodes` 배열 길이                      |
| `WORKFLOW_MAX_CONNECTIONS` | 1500   | `connections` 아래 대상 항목의 총 개수 |

한도에 도달한 파일은 통과하고 초과한 파일은 `422 WORKFLOW_LIMIT_EXCEEDED`로 거절한다. 메시지에 초과한 한도의 종류와 값이 있으며, 정상 파일이 거절되면 해당 값을 올린다. 노드·연결은 1 이상, 깊이는 6 이상이어야 하며 어기거나 숫자가 아닌 값이면 앱이 시작되지 않는다. 저장된 기준 버전이 한도를 넘으면 비교도 같은 코드로 거절되고 메시지가 `Base version:`으로 시작한다. 기본값은 CPU 0.5코어·힙 1 GB 가정에서 동시 비교 10개의 첫 실행 지연을 5초 안으로 맞춘 값이고, 값을 올릴수록 지연이 거의 비례해 늘어난다. 근거, 측정 기록, 미검증 항목은 [INPUT_LIMITS.md](INPUT_LIMITS.md)에 있다.

## 로컬에서 API 문서와 로그 확인

`.env.example`의 기본값은 `false`다. 로컬에서 `API_DOCS_ENABLED=true`로 백엔드를 실행하면 `http://localhost:8080/swagger-ui.html`에서 Swagger UI를, `/v3/api-docs`에서 OpenAPI JSON을 볼 수 있다. 운영 환경에서는 설정하지 않아 노출되지 않는다. API 명세의 기준은 컨트롤러의 OpenAPI 어노테이션이며, 업로드 호출 예시는 UI의 `POST /api/workflows`에 있다.

모든 응답에는 `X-Request-Id` 헤더가 있고 오류 본문에는 같은 값이 `requestId`로 들어간다. 로그는 `[requestId] event=workflow.upload.committed ...`처럼 `event=` 키로 검색한다. 문제가 생기면 응답의 `requestId`로 `grep`해서 해당 요청의 전체 경로를 본다. 업로드 후 DB 기록이 실패해 남은 S3 객체는 `workflow_hub.pending_objects`의 기록으로 자동 정리되며, 정리 결과는 `event=workflow.object_cleanup.deleted`·`kept_referenced`·`delete_failed`·`discard_failed`·`run_failed`의 `objectKey`로 확인한다. 삭제가 계속 실패하면 `workflow.object_cleanup.discard_failed`나 `workflow.object_cleanup.delete_failed`의 키와 `pending_objects`의 남은 행을 함께 본다. 파일 내용, 제목, 토큰은 로그에 남지 않는다.

SQL 로그가 필요하면 `LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_JDBC_CORE=DEBUG`를 임시로 설정한다. 바인딩 값이 보일 수 있으니 운영에서는 쓰지 않는다.

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
