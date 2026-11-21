# Frontend 작업 지침

- 루트 AGENTS.md와 API 계약을 먼저 읽는다. 이 폴더는 React + TypeScript + Vite 앱이다.
- `src/app`은 앱 구성, `src/features/<domain>`은 기능, 기능 간 공통 코드가 실제로 생기면 `src/shared`로 분리한다.
- 컴포넌트는 PascalCase, 훅은 use 접두어, 일반 함수는 camelCase를 사용한다. TypeScript strict를 끄거나 any로 회피하지 않는다.
- `npm ci`, `npm run dev`, `npm run verify`를 사용한다. 포맷 수정은 `npm run format`이다.
- 변경된 동작에 대한 테스트를 작성한다. API 구현 전에는 계약 기반 mock임을 명확히 표시하고 완료된 기능으로 소개하지 않는다.
- Supabase client는 하나만 사용한다. Google OAuth PKCE, 토큰 보관 및 자동 갱신은 SDK가 담당한다. 별도 refresh timer나 자체 JWT 발급을 추가하지 않는다.
- 현재 SPA는 SDK 기본 브라우저 저장소에 토큰을 유지한다. HttpOnly 쿠키 구조가 아니다. 토큰·세션·워크플로 원문을 로그에 출력하지 않고 `dangerouslySetInnerHTML`을 사용하지 않는다.
- `VITE_` 값은 공개 번들에 포함된다. publishable key만 사용하며 service role, secret key, DB 비밀번호, S3 자격 증명을 넣지 않는다.
- 실제 API 요청에 Supabase access token을 Bearer로 전달한다. UI에서의 로그인 판단은 서버 인가를 대체하지 않는다.
- Supabase allowlist에 정확한 개발/운영 origin을 등록해야 한다. 기본 개발 주소는 http://127.0.0.1:5173 이다.
- 실 Google 로그인/RTR 검증은 공급자 설정이 있어야 한다. 로컬 단위 테스트 통과를 실제 로그인 검증이라고 보고하지 않는다.
