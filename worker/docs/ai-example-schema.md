# AI 도구의 고정 JSON 예제 분석

AI 흐름 프로파일 `1.1.0`은 Code Tool과 Workflow Tool v1의 활성 `jsonSchemaExample` 중 제한된 고정 예제를 분석한다. 예제 값을 모델 전송 데이터로 오인하지 않고, 예제로부터 생성되는 스키마의 구조·속성 이름을 검사한다. 모델의 실제 출력이나 도구 실행을 검증하는 기능은 아니다.

## 공식 동작과 적용 범위

고정 n8n 커밋 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`의 [Code Tool](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/nodes/tools/ToolCode/ToolCode.node.ts)과 [Workflow Tool v1](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/nodes/tools/ToolWorkflow/v1/ToolWorkflowV1.node.ts)은 활성 예제를 스키마로 변환한다. [공통 변환기](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/utils/schemaParsing.ts)는 객체 입력도 JSON 문자열로 변환하며, Code Tool 1.3에서는 모든 속성을 필수로 표시한다.

공식 [n8n 스키마 생성기](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/generate-schema-from-example.ts)는 OSS `generate-schema` 2.6.0을 사용한다. 그 [고정 버전 구현](https://github.com/Nijikokun/generate-schema/blob/v2.6.0/src/schemas/json.js)의 평면 객체·기본값 부분만 요약했다. 기존 `parseLiteralJsonData`를 재사용하고 새 의존성은 추가하지 않았다. 숫자는 이 버전대로 `number`, 문자열·불리언·null은 각각의 타입이 된다. 원래 예제 값은 생성 스키마에 넣지 않는다.

- 문자열 또는 JSON 객체로 저장된 평면 객체만 지원한다. 활성 스키마 선택의 기본값과 버전별 필수 속성 차이를 유지한다.
- 입력 8,192자, 속성 64개, 속성 이름 128자로 제한한다. 중첩 객체·배열·비유한 숫자·손상 JSON·동적 표현식·예산 초과는 계속 미확인이다.
- `__proto__`, `prototype`, `constructor`와 Object.prototype에 있는 이름은 거부한다. 공식 런타임의 일부 키 제거를 안전하다는 판정으로 대체하지 않는다.
- 생성 스키마는 데이터 리터럴로만 분석한다. 속성 이름 안의 표현식처럼 보이는 텍스트를 해석하지 않는다. 속성 이름 자체가 이메일 등 개인정보이면 후보를 보존하되 결과에는 원문을 복사하지 않는다.
- 예제 `{"email":"synthetic@example.invalid"}`의 값은 모델 전송으로 판정하지 않는다. 도구 결과·모델 생성 인자·알 수 없는 런타임 내용은 별도의 미확인 성분으로 유지한다.

## 검증

`test/ai-example-schema.test.mjs`의 5개 검사에서 Code/Workflow Tool 버전, 문자열·객체 예제, 개인정보 값과 속성 이름의 차이, 표현식처럼 보이는 이름, 프로토타입 키, 크기·중첩·배열·비유한 값, 비활성·수동·미확정 선택을 검증했다. 기존 `ai-flow.test.mjs`의 고정 예제 기대값만 새 동작에 맞췄고 동적 스키마·출력 파서 예제·생성 인자의 불확실성은 유지했다. Code/AI/설정 관련 총 180개 검사를 통과했다.

확정 공개 25개 중 5819 `/nodes/9`의 숫자 속성 3개가 지원 범위에 들어왔다. 기준 `cf2f5beb941e05cb2fbdac5874be4d06ee9f7f40`과 후보 모듈의 직접 정적 비교에서 `ai_tool_example_derived_schema_content_unverified`만 제거되고 새로운 AI 진단은 생기지 않았다. 원본 해시는 `819722b716c1c3d0b8ef15e82a7189f409f600c6801ac07ea7cfdfc254d6bc37`이다. 공개 원본을 실행하거나 외부에 전송하지 않았다. 전체 보고서의 `partial` 해소나 모델의 실제 스키마 준수는 이 결과로 입증하지 않는다.
