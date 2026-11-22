# 보안 검사 워커 작업 지침

- 워커는 Workflow Hub의 `worker/`에서 관리한다. Node.js 버전은 이 디렉터리의 `.node-version`을 사용하며 의존성은 워커에서 설치한다.
- 정적 분석과 팀 연동 계약은 [지원 범위](docs/contract.md), [실행기](docs/runner.md), [보안 설계](../docs/SECURITY_DESIGN.md)를 기준으로 한다. 팀 HTTP API의 구현 범위는 [공개 OpenAPI](../contracts/openapi.yaml)와 백엔드 코드를 확인한다.
- 작업은 루트 지침에 따라 Workflow Hub 이슈로 추적한다. 업로드된 워크플로의 노드·표현식·Code를 실행하지 않는다. 테스트는 합성 JSON과 계약 모의 서버를 사용한다.
- 루트에서 `npm --prefix worker ci`와 `npm --prefix worker run verify`를 실행한다. CLI의 상대 입력 경로는 현재 작업 디렉터리를 기준으로 해석한다. 워커 검증 명령과 기존 실행 근거는 [검증 문서](docs/validation.md)에 있다.
- 합성 코퍼스와 저장된 실행 기록은 실측 근거다. 해시를 고정한 입력과 원본 출력을 갱신할 때는 관련 검증을 다시 수행하고 결과를 함께 기록한다.
- 개발용 루프백 계약 테스트와 팀 환경에서 실제로 관측한 연동 결과를 구분해 보고한다. 팀 실행은 승인된 격리와 작업 API가 준비된 뒤 검증한다.
