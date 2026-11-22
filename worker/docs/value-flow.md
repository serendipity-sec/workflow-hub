# 필드별 정적 값 흐름

`src/value-flow.ts`는 워크플로 JSON에서 가능한 값의 출처·민감도·변환·분기 조건을 추적한다. 업로드한 표현식·Code·워크플로를 실행하지 않는다. Acorn은 JavaScript 구문을 파싱하는 데만 사용한다.

## 내부 API와 결과 의미

`buildValueFlow(context, { sourceAnnotations })`가 반환하는 객체는 `resolve(nodeKey, value, options)`와 `output(nodeKey, fieldPath, outputIndex)`를 제공한다. 일반 노드 값은 `=` 접두사가 있어야 표현식으로 읽는다. Postgres처럼 별도 템플릿 처리기가 있는 호출자는 `expressionMode: 'template'`을 명시한다.

`=` 접두사 뒤에 보간 구분자가 전혀 없으면 고정 텍스트로 모델링한다. 닫히지 않은 보간 구분자는 미확인으로 남긴다.

- `origins`: Webhook, DB 결과, 리터럴, 자격 증명 참조, 미지원 노드 출력의 가능한 출처다. 원본 필드 경로는 JSON Pointer로 보존한다. `/a.b`와 `/a/b`를 구분한다.
- `trust`: 외부 입력 여부다. 외부 입력이라는 이유만으로 개인정보·비밀값이라고 판단하지 않는다.
- `sensitivity`: `secret_candidate`, `pii_candidate`, `public_literal`, `unknown`이다. `sensitivityBasis`가 필드명 추정, 리터럴 형식 추정, 운영자·스키마 선언을 구분한다. 후보를 확인된 개인정보로 승격하지 않는다.
- `sensitivityClasses`: 값에 포함될 수 있는 분류의 전체 집합이다. 객체 합성·배열·직렬화·문자열 결합·경로 병합에서 비밀 후보와 개인정보 후보를 모두 보존한다. `sensitivity`는 호환용 최대 분류이며, 전송 정책은 전체 집합에 적용한다. 미확인 부분의 `unknown`도 유지하고, 정확히 한 필드를 선택할 때는 그 필드의 분류만 반환한다.
- Code·표현식 객체도 JSON·Set과 같이 필드명 힌트를 반영한다. 예를 들어 `password`와 `phone`에는 각각 비밀·개인정보 후보를 추가하며, 값에서 이미 얻은 다른 분류를 덮어쓰지 않는다. 신뢰된 별도 분류 선언은 기존 Set 프로필과 같은 우선순위를 유지한다. 이름 추정은 확인된 개인정보나 실제 비밀값의 증명이 아니다.
- `presence`: 필드가 정의됨, 제거됨, 미확인을 구분한다. Set에서 삭제된 필드를 추적 실패와 같은 상태로 취급하지 않는다.
- `valueId`, `guards`, `transforms`: 방어 조건이 검사한 값과 실제 사용 값의 동일성을 확인하는 내부 근거다. 숫자 변환, URL component 인코딩, 문자열 결합, 직렬화는 별도 문맥이다. 범용 `sanitized=true` 판정은 없다.
- `fields`: 전체 객체에 포함된 알려진 필드 분류다. 전체 객체·중첩 객체를 출력할 때 알려진 민감 필드가 사라지지 않도록 집계한다. 알려진 필드가 없다는 이유로 전체 객체를 공개 데이터로 판단하지 않는다.
- `status`, `diagnosticCodes`: 지원 정의를 해석한 상태와 미확인을 구분한다. `resolved`는 정적 값 모델의 상태이며 실행 성공·실제 안전성을 의미하지 않는다.

이 구조는 **내부용**이다. 원본 필드명, 경로, 조건의 리터럴에는 민감정보가 있을 수 있다. 공개 보고서는 고정 근거 코드와 마스킹된 노드·설정 위치로 변환해야 한다. 운영자·스키마 선언은 호출자가 해당 입력 해시에 연결한 신뢰된 별도 설정으로 전달해야 하며 업로드 JSON의 주석·설명을 선언으로 자동 승격하지 않는다.

## 지원하는 선언 프로필

| 프로필                   | 처리 내용                                                                                                         | 남는 한계                                                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Webhook 2/2.1/2.2        | 메서드와 출력 번호, JSON 필드의 외부 출처                                                                         | raw body의 내부 필드 구조, 활성 상태·앞단 인증은 미확인                          |
| Postgres 2.4/2.5/2.6/2.8 | DB 결과를 별도 출처로 분리                                                                                        | 실제 스키마·행 수·권한·민감도는 선언 없이 확정하지 않음                          |
| Set 1/2                  | `values`, `keepOnlySet`, dot notation                                                                             | 동적 필드명·옵션은 미확인                                                        |
| Set 3–3.2                | `fields.values`, include 설정                                                                                     | 타입 변환 실패 시 실제 실행은 보증하지 않음                                      |
| Set 3.3–3.5              | assignments, 기본 다른 필드 제외, include/except/selected, raw JSON                                               | 전체 객체의 except 결과는 알려지지 않은 필드 때문에 부분 분석                    |
| IF 2/2.1/2.2             | 입력 보존, true/false 출력, 엄격한 숫자·단일 리터럴 동등 조건                                                     | 느슨한 변환·불명확한 OR/AND 경로·다른 필드의 검증은 방어로 인정하지 않음         |
| Switch 3–3.5             | rules의 출력별 조건, 별도 fallback                                                                                | 기존 rule 출력으로 fallback을 합치면 그 조건을 공통 방어로 인정하지 않음         |
| Merge 3–3.2 append       | 가능한 입력 출처의 합집합, 모든 경로에 공통인 조건만 유지                                                         | 개별 아이템 대응은 주장하지 않음                                                 |
| Merge chooseBranch       | 선택한 입력의 값 또는 빈 출력                                                                                     | 입력 도착·실제 실행 여부는 미확인                                                |
| Merge combineByPosition  | 가능한 필드 출처를 보존                                                                                           | 행 수·정렬·충돌 대응이 미확인이므로 항상 부분 분석, 방어 조건 해제               |
| Code 1/2 JavaScript      | 불변 const 선언과 별칭, 단일 반환 아이템의 JSON 객체/배열 래퍼, 제한된 상수·날짜 출력, 단일 `return $input.all()` | 대입·수정·반복문·임의 호출·Python 등은 불투명 처리하고 입력의 민감 가능성을 보존 |

표현식은 현재 아이템과 이름으로 지정한 원본 노드 참조, 점·리터럴 대괄호 접근, 리터럴 객체·배열, 문자열 결합, `Number`/`parseInt`/`parseFloat`, `encodeURIComponent`, `JSON.stringify`의 제한된 구문을 처리한다. `$env`·`$credentials`는 참조 후보만 기록하며 실제 환경 값을 읽지 않는다. 임의 함수는 실행하지 않고 가능한 입력 출처와 미확인 상태를 유지한다.

Code의 출력 해석은 `const` 선언 뒤 단일 `return`만 허용하는 별도 구문 프로필이다. `new Date()`의 제한된 문자열 포맷과 `$now`·`$today`의 제한된 포맷은 현재 시각을 읽지 않고 `runtime_clock` 근거의 비입력 값으로 모델링한다. 날짜 생성자에 입력을 주거나 포맷 옵션이 동적이면 미확인이다. 이 범위에서 상수·날짜만 반환하는 분기는 앞선 전체 이메일·비밀값을 복사한 것으로 취급하지 않는다. 임의 함수 호출, 변수·객체 변경, 내장 이름 가림은 여전히 불투명하다. [고정 Code 래퍼 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Code/JavaScriptSandbox.ts)의 객체/배열 반환 계약을 따르되 해당 샌드박스를 워커에서 실행하지 않는다.

허용된 상수 포맷·옵션 인자의 민감 후보는 날짜 결과에 합쳐 보존한다. Luxon `toFormat`의 작은따옴표 구간은 리터럴로 출력될 수 있으므로, 이메일 같은 상수를 포맷 문자열에 넣어도 공개 값으로 낮아지지 않는다. 일반 날짜 포맷은 외부 입력 민감도를 상속하지 않는다.

## 방어 조건과 한도

ExecuteWorkflowTrigger 1/1.1은 외부에서 전달된 인자 출처로 표시하되 `subworkflow_argument_context_unresolved`를 항상 남긴다. 부모·자식 인자 대응이나 부모의 방어 조건을 자동 승계하지 않는다. [고정 트리거 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ExecuteWorkflow/ExecuteWorkflowTrigger/ExecuteWorkflowTrigger.node.ts)의 선언을 기준으로 하며, 입력 선언과 실제 부모 인자 대응은 별도 검증 사항이다.

동일한 정규화 필드 경로에 분류 선언이 충돌하면 더 민감한 후보를 유지하고 `source_annotation_conflict` 부분 분석을 반환한다. 먼저 나온 `public_literal` 선언이 뒤의 비밀 후보를 가리지 않는다.

조건은 동일 `valueId`에만 연결한다. Set에서 이름만 바꾼 값은 출처가 유지되지만 다시 결합·변환한 값은 이전 조건을 자동 승계하지 않는다. 원본 노드를 직접 참조하면 중간 IF의 조건을 자동 적용하지 않는다. 여러 경로가 합쳐지면 모든 경로에 공통인 조건만 남긴다. 숫자 비교의 거짓 분기에서 엄격한 숫자 타입이 유지될 수 있어도 참 분기의 동등 조건까지 유지하지 않는다.

현재 한도는 재귀 64, 요청 4096, 표현식 AST 2048 노드, 객체 필드 128, 경로·출처 대안 64, 별도 분류 선언 256이다. 순환, 한도 초과, 미지원 변환은 종료와 진단을 보장한다. 선언된 경로의 존재를 실제 실행 가능성 증명으로 표현하지 않는다.

객체·배열의 필드를 128개에서 잘랐다면 `fieldsComplete=false`와 `flow_field_limit`를 유지한다. 잘린 객체에서 필드를 선택해도 필드가 없거나 공개 데이터라고 확정하지 않는다. 선택 결과는 존재 미확인, 부분 분석, 기존 민감 후보와 `unknown`을 보존한다. 표현식 객체는 한도 뒤의 같은 이름 속성이 앞의 값을 덮어쓸 수 있어 앞부분 필드의 선택도 보수적으로 처리한다. 완전히 분석한 객체의 실제 미정의 필드만 `absent`로 판단한다.

## 고정 소스 근거와 검증

n8n 기준 커밋은 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`다.

- [Set 버전 연결](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/Set.node.ts), [Set V2 실행](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/SetV2.node.ts), [필드 합성·변환](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/helpers/utils.ts).
- [IF V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/IfV2.node.ts), [Switch V3](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Switch/V3/SwitchV3.node.ts).
- [Merge 모드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/index.ts), [chooseBranch](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/chooseBranch.ts), [위치 결합](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/combineByPosition.ts).

`test/value-flow.test.mjs`의 합성 사례는 민감도·외부 조작성 분리, 필드 매핑·제거, 정확한 조건 연결, 우회 분기, fallback, 병합, Code 미실행, 순환 종료를 검증한다. 128/129 필드 경계, 중첩 배열, 한도 뒤 속성 덮어쓰기, 비밀·개인정보 혼합 분류와 단일 필드 선택도 회귀 검증한다. 실제 팀 API·운영 환경·임의 프로그램의 완전 분석 검증은 포함하지 않는다.
