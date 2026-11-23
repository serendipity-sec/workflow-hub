# 필드별 정적 값 흐름

`src/value-flow.ts`는 워크플로 JSON에서 가능한 값의 출처·민감도·변환·분기 조건을 추적한다. 업로드한 표현식·Code·워크플로를 실행하지 않는다. Acorn은 JavaScript 구문을 파싱하는 데만 사용한다.

0.6의 `src/bounded-code.ts`는 단순 const 프로필이 처리하지 못한 Code를 위한 별도 유한 추상 해석기다. `eval`, VM, `Function`, 제출된 함수·메서드·정규식의 실행을 사용하지 않는다. 지역 상태와 AST의 가능한 출처를 옮기는 작업이며 n8n 실행 재현이 아니다.

## 내부 API와 결과 의미

`buildValueFlow(context, { sourceAnnotations })`가 반환하는 객체는 `resolve(nodeKey, value, options)`와 `output(nodeKey, fieldPath, outputIndex)`를 제공한다. 일반 노드 값은 `=` 접두사가 있어야 표현식으로 읽는다. Postgres처럼 별도 템플릿 처리기가 있는 호출자는 `expressionMode: 'template'`을 명시한다.

이미 Code AST에서 추출한 단일 표현식에는 내부 API `resolveExpression(nodeKey, expression)`을 사용한다. Acorn으로 직접 파싱하므로 중첩 객체의 닫힘이나 문자열 안의 `}}`를 n8n 템플릿 종료로 오인하지 않는다. 괄호는 같은 표현식으로 해석하며 최대 65,536자, AST 2,048개, 기존 깊이·요청 한도를 적용한다. 이 API 역시 코드를 실행하지 않으며 일반 n8n 설정 문자열을 임의로 Code 표현식으로 승격하는 데 사용하지 않는다.

`=` 접두사 뒤에 보간 구분자가 전혀 없으면 고정 텍스트로 모델링한다. 닫히지 않은 보간 구분자는 미확인으로 남긴다.

- `origins`: Webhook, DB 결과, 리터럴, 자격 증명 참조, 미지원 노드 출력의 가능한 출처다. 원본 필드 경로는 JSON Pointer로 보존한다. `/a.b`와 `/a/b`를 구분한다.
- `trust`: 외부 입력 여부다. 외부 입력이라는 이유만으로 개인정보·비밀값이라고 판단하지 않는다.
- `sensitivity`: `secret_candidate`, `pii_candidate`, `public_literal`, `unknown`이다. `sensitivityBasis`가 필드명 추정, 리터럴 형식 추정, 운영자·스키마 선언을 구분한다. 후보를 확인된 개인정보로 승격하지 않는다.
- `sensitivityClasses`: 값에 포함될 수 있는 분류의 전체 집합이다. 객체 합성·배열·직렬화·문자열 결합·경로 병합에서 비밀 후보와 개인정보 후보를 모두 보존한다. `sensitivity`는 호환용 최대 분류이며, 전송 정책은 전체 집합에 적용한다. 미확인 부분의 `unknown`도 유지하고, 정확히 한 필드를 선택할 때는 그 필드의 분류만 반환한다.
- `constant`: 내부용 원시 리터럴 근거다. 문자열·숫자·불리언·null과 제한된 고정 문자열 결합에만 설정한다. 공개라는 별도 분류 선언, 외부 응답, 모델 결과, 시계, 객체·배열 래퍼와 미확인 변환에는 설정하지 않는다. SQL·수신처 소비자는 `status: resolved`인 문자열 상수만 사용할 수 있다. 원문이므로 공개 결과·로그로 복사하면 안 된다.
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
| IF 2/2.1/2.2/2.3         | 입력 보존, true/false 출력, 엄격한 숫자·단일 리터럴 동등 조건                                                     | 느슨한 변환·불명확한 OR/AND 경로·다른 필드의 검증은 방어로 인정하지 않음         |
| Switch 3–3.5             | rules의 출력별 조건, 별도 fallback                                                                                | 기존 rule 출력으로 fallback을 합치면 그 조건을 공통 방어로 인정하지 않음         |
| Merge 3–3.2 append       | 가능한 입력 출처의 합집합, 모든 경로에 공통인 조건만 유지                                                         | 개별 아이템 대응은 주장하지 않음                                                 |
| Merge chooseBranch       | 선택한 입력의 값 또는 빈 출력                                                                                     | 입력 도착·실제 실행 여부는 미확인                                                |
| Merge combineByPosition  | 가능한 필드 출처를 보존                                                                                           | 행 수·정렬·충돌 대응이 미확인이므로 항상 부분 분석, 방어 조건 해제               |
| Code 1/2 JavaScript      | 불변 const 선언과 별칭, 단일 반환 아이템의 JSON 객체/배열 래퍼, 제한된 상수·날짜 출력, 단일 `return $input.all()` | 대입·수정·반복문·임의 호출·Python 등은 불투명 처리하고 입력의 민감 가능성을 보존 |

표현식은 현재 아이템과 이름으로 지정한 원본 노드 참조, 점·리터럴 대괄호 접근, 리터럴 객체·배열, 문자열 결합, `Number`/`parseInt`/`parseFloat`, `encodeURIComponent`, `JSON.stringify`의 제한된 구문을 처리한다. `$env`·`$credentials`는 참조 후보만 기록하며 실제 환경 값을 읽지 않는다. 임의 함수는 실행하지 않고 가능한 입력 출처와 미확인 상태를 유지한다.

선택적 필드 접근(`?.`, `?.[0]`)은 같은 정적 필드의 출처와 민감도를 추적하되 값 존재와 기존 방어 조건을 확정하지 않는다. 리터럴 객체·배열과 순수 const 별칭의 고정 필드·인덱스 선택도 지원한다. `||`와 `??`는 두 가능한 값의 출처·민감도 합집합이며, 기본값을 붙였다는 이유로 원래 값의 민감도가 사라지거나 방어 조건이 유지되지 않는다. 임의 선택적 함수 호출, 동적 인덱스 계산, 대입·수정은 이 범위에 포함하지 않는다.

Code의 출력 해석은 `const` 선언 뒤 단일 `return`만 허용하는 별도 구문 프로필이다. `new Date()`의 제한된 문자열 포맷과 `$now`·`$today`의 제한된 포맷은 현재 시각을 읽지 않고 `runtime_clock` 근거의 비입력 값으로 모델링한다. 날짜 생성자에 입력을 주거나 포맷 옵션이 동적이면 미확인이다. 이 범위에서 상수·날짜만 반환하는 분기는 앞선 전체 이메일·비밀값을 복사한 것으로 취급하지 않는다. 임의 함수 호출, 변수·객체 변경, 내장 이름 가림은 여전히 불투명하다. [고정 Code 래퍼 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Code/JavaScriptSandbox.ts)의 객체/배열 반환 계약을 따르되 해당 샌드박스를 워커에서 실행하지 않는다.

허용된 상수 포맷·옵션 인자의 민감 후보는 날짜 결과에 합쳐 보존한다. Luxon `toFormat`의 작은따옴표 구간은 리터럴로 출력될 수 있으므로, 이메일 같은 상수를 포맷 문자열에 넣어도 공개 값으로 낮아지지 않는다. 일반 날짜 포맷은 외부 입력 민감도를 상속하지 않는다.

## 추가 유한 Code 프로필

확장 프로필은 `code_bounded_flow_partial`을 남긴다. 지원한 필드의 정확한 출처와 상수는 추적하지만 전체 프로그램의 실행 성공·행 수·반복 횟수·경로 실행 가능성을 보증하지 않는다.

- const/let 지역 변수와 스칼라의 `=`·`+=` 대입은 추적한다. 객체의 속성 대입이나 배열 push가 있으면 전체 Code 반환의 필드 정밀도를 포기하고 `code_object_mutation_unresolved`를 남긴다. 모든 관찰한 대입 값·이전 지역 값·진단·직접 참조의 민감 분류와 unknown을 합치며 개별 필드나 상수를 공개로 확정하지 않는다. 내부적으로 관찰한 고정 키 변경은 후보 수집에만 사용하고 완전한 heap alias 해석이라고 주장하지 않는다. 다른 객체·배열·helper를 거친 참조 변경에는 추가로 `code_nested_alias_mutation_unresolved`가 남을 수 있다. `__proto__`·`prototype`·`constructor` 쓰기도 프로토타입 의미를 실행하지 않고 미확인으로 처리하며 분석용 사전은 null prototype을 사용한다.
- if/else는 조건을 실행하지 않고 가능한 결과를 합치며 독립 출력 필드의 출처를 각각 유지한다. try/catch는 예외가 발생하는 시점의 중간 대입 상태를 완전히 재구성하지 않는다. 따라서 `code_try_state_unresolved`와 함께 전체 Code 반환을 부분 분석으로 처리하고, try/catch 양쪽에서 관찰한 RHS·지역 값·직접 참조 후보를 보존한다. catch를 try 시작 전의 값으로만 판단하여 중간 비밀 값을 공개로 낮추지 않는다. 조건을 통한 정보 누설 같은 암시적 흐름은 증명하지 않으며, finally·임의 제어문은 미지원이다.
- 객체 spread의 알려진 필드와 덮어쓰기 순서를 보존한다. 불명확한 spread가 나중에 나타나면 기존 필드를 공개로 확정하지 않는다. 배열 spread의 길이·인덱스는 미확인으로 유지한다.
- `$input.all()` 및 `map`은 가능한 모든 아이템을 합친 단일 요소 요약을 사용한다. 반환 배열의 첫 아이템만 선택하지 않는다. for-of/push는 0회와 추상 1회 결과를 합쳐 `code_loop_summary_partial`을 남긴다. 반복 안에서 쓰인 바인딩에는 전체 반복 입력과 알려진 반복 상태를 합친 `code_loop_carried_state_unverified`를 추가하여 두 번째 이후 반복의 비밀·개인정보가 첫 번째 반복의 공개값에 가려지지 않게 한다. 구체적인 반복 실행·횟수와 일반 for/while, 재귀·복잡한 반복 상태는 완전 해석하지 않는다.
- 순수한 지역 helper는 매개변수, 자체 지역 변수, 명시적으로 지원한 n8n 참조·내장 변환·순수 함수 참조를 제한적으로 추적한다. 함수 정의 전에 확인된 **불변 const 원시 상수**는 최대 128개까지 어휘적 정의 환경에서 캡처한다. caller의 동명 매개변수로 바꾸지 않으며, helper 이름이 매개변수에 가려지면 원래 helper를 호출한 것으로 취급하지 않는다. mutable 변수·객체·불확실한 값·정의 이후 초기화의 closure는 `code_closure_capture_unresolved`로 유지한다. 객체를 helper에 전달·반환하거나 복합 식에 저장하면 밖으로 전달된 참조로 표시하고 이후 변경을 미확인으로 처리한다. 함수 깊이 6, 문장 깊이 12, 추상 전이 2,048회와 공통 요청 예산을 적용한다. 임의 호출·외부 효과·지원하지 않는 구문은 입력, 알려진 지역 값, 대입·진단에서 관찰한 값과 정적 n8n 직접 참조의 민감 가능성을 모두 보존한 `code_effects_partially_analyzed`로 끝낸다.
- trim/대소문자/replace/split/join/slice 등의 문자열 메서드는 값의 출처·민감도 전이만 모델링한다. 제출된 정규식을 컴파일하거나 매칭·치환하지 않는다. 이 변환을 개인정보 제거·인젝션 방어로 인정하지 않는다. `JSON.parse`는 고정 문자열에 한해서 데이터 파서로 읽고, 동적 문자열은 원래 민감도와 구조 미확인을 유지한다.

이 프로필은 [고정 Code 샌드박스의 반환 정규화 계약](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Code/JavaScriptSandbox.ts)을 참고한다. 해당 샌드박스를 워커에서 호출하지 않는다.

이름 있는 함수 표현식의 자기 이름은 같은 이름의 바깥 const를 가린다. 자기 이름을 실제로 읽으면 `code_function_self_binding_unresolved`를 남기고 상수 캡처를 사용하지 않는다. 한정된 본문에서 매개변수·callback 필드의 민감 후보를 먼저 수집한 뒤 전체 출력의 미확인을 유지한다. 자기 이름과 같은 매개변수가 있으면 JavaScript의 매개변수 가림을 따른다.

## 외부 결과와 AI 출력의 값 흐름

HTTP Request 3/4–4.3, Gmail 2.1/2.2 get/getAll, Airtable 2–2.2의 고정 record 작업, Google Sheets 3/4–4.7 read, Notion 2–2.2 databasePage get/getAll·database get, Google Docs 1/2 document get은 직전 입력을 그대로 복사하는 것으로 가정하지 않는다. 새 외부 결과 출처와 `service_response_shape_unverified`를 남긴다. 응답·권한·정확한 스키마가 없으므로 실제 내용은 unknown이며, 이메일 결과의 주소·본문은 서비스 스키마에 따른 개인정보 가능성으로만 표시한다. Sheets append는 실행 중 빈 시트에 따라 원본 입력 반환으로 바뀔 수 있어 입력 가능성을 보존한다.

Manual Trigger 1은 고정 소스의 빈 JSON 아이템을 모델링한다. Error Trigger 1의 실제 오류 데이터는 별도 출처와 미확인으로 표시한다. 검토한 AI main 출력은 `aiPromptInputs`가 선택한 실제 prompt 설정의 민감 후보와 출력 unknown을 합치며 guard와 상수를 만들지 않는다. 모델·파서 연결을 데이터 정제나 안전 증명으로 보지 않는다.

근거: [HTTP Request](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/V3/HttpRequestV3.node.ts), [Gmail](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Gmail/v2/GmailV2.node.ts), [Airtable 결과 변환](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Airtable/v2/helpers/utils.ts), [Sheets append](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Sheet/v2/actions/sheet/append.operation.ts), [Manual Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ManualTrigger/ManualTrigger.node.ts), [Error Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ErrorTrigger/ErrorTrigger.node.ts).

Code의 선택적 접근·기본값 구문도 위 한정 문법을 적용한다. 한 객체 안의 `summary`가 동적 입력을 포함해도 독립적인 상수·날짜 `docTitle`에는 그 민감도를 복사하지 않는다. 객체 전체를 보내거나 요약 필드를 보내면 해당 민감 후보는 유지한다. 이 분리는 모든 선언과 반환이 지원되는 순수 문법인 경우에만 적용하며, 미지원 함수나 대입문이 있는 Code 전체를 공개 출력으로 추론하지 않는다.

## 방어 조건과 한도

### Wait·Aggregate·외부 트리거의 추가 프로파일

- **Wait 1/1.1:** 기본 `timeInterval` 모드에서 생략된 기본값 또는 0 이상 유한 amount와 고정 seconds/minutes/hours/days를 확인하면 성공 출력의 입력 필드를 보존한다. base HTTP/SQL/응답 경로 추적도 이 노드를 실제로 통과한다. webhook/form 재개·동적 시간·잘못된 단위·다른 실행 옵션은 이 프로파일로 처리하지 않는다. 기다린 시간이나 실제 실행 성공을 검증한 것은 아니다.
- **Aggregate 1:** 전체 입력 모음의 destinationFieldName, 런타임이 실제로 읽는 include/exclude 필드 모두, 개별 필드 모음의 이름/출력명/dot notation을 해석한다. UI에서 비활성인 저장 옵션도 원본 실행 코드가 읽으면 반영한다. 단일 목록의 임의 숫자 인덱스는 가능한 입력 출처의 합집합이며 `collection_cardinality_unverified`와 함께 개수·순서·존재 미확인을 유지한다. 원래 guard·scalar constant를 목록의 특정 아이템에 승계하지 않는다. lodash.get의 중첩 경로와 같은 이름의 literal dotted key가 모두 가능하면 두 출처를 보존한다. 동적 필드명, 충돌한 출력 경로, prototype 경로, bracket 표기, 불명확한 flatten은 지원 완료로 바꾸지 않는다. 전체 객체의 일부 필드 제외도 알려지지 않은 나머지 필드를 공개 데이터로 확정하지 않는다.
- **Gmail Trigger 1–1.4, IMAP 1/2–2.2, Telegram Trigger 1–1.5, Form Trigger 2–2.6:** 실제 메일·메시지·폼 입력을 별도 외부 출처로 연결한다. 이메일의 주소/본문은 개인정보 후보를 유지한다. `trigger_payload_schema_unverified`는 실제 payload나 권한을 확인하지 않았다는 의미이며, 이 변경으로 전체 `partial`을 없애지 않는다. 가짜 incoming 연결과 비정상 출력 포트는 별도 미확인으로 남는다.

고정 근거: [Wait 입력 보존](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Wait/Wait.node.ts), [Aggregate 필드 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/Aggregate/Aggregate.node.ts), [필드 목록 파서](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/utils/utils.ts), [Gmail Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Gmail/GmailTrigger.node.ts), [IMAP 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/EmailReadImap/EmailReadImap.node.ts), [Telegram Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Telegram/TelegramTrigger.node.ts), [Form Trigger V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Form/v2/FormTriggerV2.node.ts).

Wait의 unit은 문자열만 허용하며 배열·객체를 문자열로 강제 변환하지 않는다. Aggregate 개별 모음은 `keepMissing` 생략/false에서 입력 배열의 null을 제거하므로, flatten을 끈 경우에도 중첩 배열 인덱스가 이동할 수 있다. 해당 인덱스를 조회하면 `aggregate_null_filter_alignment_unverified`와 원래 경로·전체 후보를 함께 보존한다. `keepMissing: true`의 기존 인덱스 투영은 유지한다. `mergeLists: true`에서도 전체 값과 객체·배열 요소의 가능한 하위 필드 후보를 합치며, `aggregate_flatten_shape_unverified`와 실제 요소 위치의 미확인을 유지한다.

Aggregate의 모음·선택값 원래 출처에는 내부용 `includesDescendants` 후보 표시를 붙인다. 정책은 같은 원본 노드와 정확한 필드 경계 아래에 선언된 분류도 보존하므로, 이동 전 배열의 내부정보 분류를 단순 unknown으로 잃지 않는다. 위치·존재가 입증된 것은 아니며 범위 안의 후손 후보를 넓게 포함할 수 있다. public 선언만 있어도 unknown을 유지한다. 전체 목록·객체·JSON 직렬화·Code의 단순 별칭에도 후보가 유지된다. 출처 64개·분류 선언 256개 한도를 사용하며 이 내부 경로나 표시는 공개 결과로 직렬화하지 않는다. `keepMissing: true`의 정확한 인덱스는 다른 인덱스의 원출처까지 넓히지 않는다.

전체 입력 모음의 명시적 include/exclude는 선택된 최상위 필드 경계를 따른다. include 없이 exclude만 있고 나머지 전체 객체의 구조를 모르면, 제외된 필드까지 후보로 되살리지 않으며 기존 `aggregate_excluded_unknown_fields`를 유지한다. 이 경우 남은 임의 하위 분류를 모두 보존했다고 주장하지 않는다. 해당 출력의 특정 잔존 필드를 직접 조회하는 경우는 그 경로만 추적한다.

개별 모음의 중복 여부는 n8n이 검사하는 키(`renameField`가 true이면 저장된 출력명, 아니면 원래 입력 필드명)로 먼저 확인한다. 실제 출력 경로끼리의 충돌도 별도로 검사한다. 중복 설정은 `aggregate_duplicate_field_unresolved`이며 두 출력이 생긴 것으로 추적하지 않는다.

`test/value-flow-profiles.test.mjs`는 민감 입력 보존, 제외 필드, 배열 불확실성, 위험 포트/모드, 동명 closure와 mutable/객체 반례를 확인한다. 공개 원본의 source-to-sink 분석과 별도로 합성 정답을 유지하며 실제 트리거나 노드를 실행하지 않는다.

ExecuteWorkflowTrigger 1/1.1은 외부에서 전달된 인자 출처로 표시하되 `subworkflow_argument_context_unresolved`를 항상 남긴다. 부모·자식 인자 대응이나 부모의 방어 조건을 자동 승계하지 않는다. [고정 트리거 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ExecuteWorkflow/ExecuteWorkflowTrigger/ExecuteWorkflowTrigger.node.ts)의 선언을 기준으로 하며, 입력 선언과 실제 부모 인자 대응은 별도 검증 사항이다.

동일한 정규화 필드 경로에 분류 선언이 충돌하면 더 민감한 후보를 유지하고 `source_annotation_conflict` 부분 분석을 반환한다. 먼저 나온 `public_literal` 선언이 뒤의 비밀 후보를 가리지 않는다.

조건은 동일 `valueId`에만 연결한다. Set에서 이름만 바꾼 값은 출처가 유지되지만 다시 결합·변환한 값은 이전 조건을 자동 승계하지 않는다. 원본 노드를 직접 참조하면 중간 IF의 조건을 자동 적용하지 않는다. 여러 경로가 합쳐지면 모든 경로에 공통인 조건만 남긴다. 숫자 `equals`의 거짓 분기는 비교 대상과 다르다는 사실만 유지하며 숫자 타입을 증명하지 않는다.

조건 옵션의 버전은 1–3을 지원하며, 생략 시 고정 런타임의 기본값 1을 따른다. `typeValidation: strict`는 명시되어야 한다. IF 2.1 이상과 Switch 3.1 이상의 `looseTypeValidation`은 최상위 매개변수에서 읽고, 이전 버전은 `options`에서 읽는다. 모든 조건 버전은 엄격한 타입 검사 전에 `null`·`undefined`를 허용하며 숫자 비교에도 그대로 넘긴다. IF 2.3과 Switch 3.4의 조건 v3은 추가로 빈 문자열·빈 배열을 `null`로 바꾼다. 따라서 모든 버전의 숫자 타입 근거는 유한 숫자 `equals`의 참 분기와 `notEquals`의 거짓 분기에만 부여한다. 부등 비교와 나머지 분기에는 숫자 타입 근거를 자동 부여하지 않는다. [고정 필터 구현](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/node-parameters/filter-parameter.ts), [버전별 느슨한 변환 옵션](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/utils.ts)을 기준으로 한다.

0.5 분석기에서는 이전 v1/v2 거짓 동등 분기의 숫자 타입 기대를 정정했다. 이 분기에 `null`이 도달할 수 있으므로 기존 기대는 방어 사실을 과장했고 SQL 후보를 가릴 수 있었다. 합성 회귀는 거짓 분기의 숫자 근거가 없어지고 SQL 문자열 입력 후보가 남는 것을 확인한다. 이는 검사를 생략하거나 경고를 줄이는 변경이 아니다. 논리 선택(`||`, `??`)에서 객체·스칼라의 구조가 불명확하면 하위 필드 투영도 부분 분석으로 남기고 원래 민감 분류와 출처를 보존한다.

Switch fallback은 생략, `none`, `extra`, 범위 안의 고정 정수 출력 번호만 해석한다. 정규 숫자 문자열도 같은 고정 출력으로 취급한다. 규칙과 fallback이 같은 출력에 합류하면 그 출력의 방어 조건을 보장하지 않는다. 동적 표현식·`null`·불리언·비정수·범위 밖 선택자와 객체가 아닌 전체 `options` 값은 출처를 보존한 부분 분석으로 표시하고 방어 근거를 제거한다. 고정 [Switch 실행 코드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Switch/V3/SwitchV3.node.ts)는 `getNodeParameter('options')` 결과로 fallback을 결정하므로, 해석하지 못한 선택자를 기본 `none`으로 간주하지 않는다.

현재 한도는 재귀 64, 요청 4096, 표현식 AST 2048 노드, 객체 필드 128, 경로·출처 대안 64, 별도 분류 선언 256이다. 순환, 한도 초과, 미지원 변환은 종료와 진단을 보장한다. 선언된 경로의 존재를 실제 실행 가능성 증명으로 표현하지 않는다.

미지원 Code 문법을 발견해도 그 지점에서 이미 알려진 출처를 버리지 않는다. 소스 순서로 AST 최대 2,048노드에서 직접 n8n 참조·자격 증명 참조·개인정보 형식의 literal/template 조각·민감 필드명 후보를 최대 256개 관찰한다. 이 후보들은 추상 전달 작업 전에 평가해 전달 예산 소진 뒤 사라지지 않게 한다. 함수 매개변수·블록 선언·함수 범위 var·이름 있는 클래스가 같은 이름의 root를 가리면 외부 자격 증명으로 승격하지 않는다. 별도 함수의 동명 매개변수가 파일의 실제 global 참조까지 지우지는 않는다. 이는 관찰용 제한 scope이며 일반 JavaScript 실행·heap·동적 binding 해석이 아니다.

문법 오류나 길이 제한은 정상 실행 가능성을 주장하지 않는다. 활성 JavaScript 프로필에 대해서만 최대 65,536자·4,096토큰의 Acorn tokenizer로 확실한 RHS/return·직접 member 및 literal 필드 후보를 제한적으로 회수한다. 주석·일반 문자열·정규식 안의 root처럼 보이는 문구, 일반 property/method 이름과 모호한 binding은 실제 root 읽기로 인정하지 않는다. 복구 범위 밖의 문맥은 `code_source_binding_unresolved`·`code_token_observation_incomplete`·`code_source_observation_limit`로 남긴다. 길이 검사는 const 전용 빠른 경로보다 먼저 적용하며 비활성 Python 노드의 jsCode를 분석 대상으로 바꾸지 않는다. 모든 opaque 관찰 결과는 `code_source_observations_only` 또는 해당 미지원 진단과 함께 unknown을 보존하고 constant·fields·guards를 제거한다. AST/형태/반환 한도에서도 관찰한 비밀·개인정보 후보는 유지하며, 읽지 못한 나머지를 공개로 확정하지 않는다.

확장 Code의 객체 구성·선택·복제 전에는 반복 참조 경로를 각각 세어 한 값 묶음의 구조 노드 512개, 구조 깊이 32, 분석 중 누적 구조 순회 16,384개 한도를 확인한다. 한도 초과는 `code_value_shape_limit`으로 구조와 상수 확정을 버리되 이미 관찰한 민감 분류를 유지한다. 작은 소스의 중첩 객체 복제가 지수적으로 커지는 것을 허용하지 않는다. 문자열 상수 추론도 결합하기 전에 결과 길이와 분석 전체 누적 65,536문자 예산을 확인하며 초과 시 `constant_inference_size_limit`과 원래 민감도·unknown을 남긴다. 이는 정적 상수 추론의 한계이며 데이터 정제를 의미하지 않는다. 배열 push나 리터럴이 필드 한도를 넘으면 128개 이후에 관찰한 후보도 전체 결과에 합치고 공개값으로 자르지 않는다.

JS 템플릿은 literal quasi와 substitution을 원래 순서대로 합치고, n8n 문자열도 literal 부분과 `{{ ... }}` 결과를 원래 위치에 둔다. 단일 표현식 앞뒤의 literal 공백도 버리지 않는다. 민감도 집합을 합칠 때 쓰던 순서를 상수 문자열 생성에 재사용하지 않는다. 합성 URL 회귀는 차단된 호스트의 접두사가 허용된 호스트로 바뀌지 않고 목적지 정책에서 계속 거부되는 것을 확인한다. 고정 [n8n 표현식 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/expression.ts)는 맨 앞의 `=`를 제거한 본문을 렌더러에 넘기며, 워커는 이 본문을 실행하지 않고 한정 AST 값과 literal 조각만 해석한다.

같은 분석 인스턴스 안에서는 노드별 Code 전체 출력과 동일한 값·옵션의 `resolve` 결과를 재사용한다. 다른 노드나 별도 분석의 분류 선언을 공유하지 않으며 반환값은 복제해 호출자의 변경이 캐시를 오염시키지 않는다. 캐시 재사용으로 이미 해석한 Code를 필드마다 다시 분석하는 비용을 줄이고, 새로운 분석 요청의 한도나 미지원 상태는 그대로 유지한다.

객체·배열의 필드를 128개에서 잘랐다면 `fieldsComplete=false`와 `flow_field_limit`를 유지한다. 잘린 객체에서 필드를 선택해도 필드가 없거나 공개 데이터라고 확정하지 않는다. 선택 결과는 존재 미확인, 부분 분석, 기존 민감 후보와 `unknown`을 보존한다. 미지원 객체 속성을 만나도 같은 필드 예산 안의 뒤쪽 형제 속성까지 key·RHS·spread 후보를 합치며, 읽지 못한 나머지는 한도 진단으로 표시한다. 표현식 객체는 한도 뒤의 같은 이름 속성이 앞의 값을 덮어쓸 수 있어 앞부분 필드의 선택도 보수적으로 처리한다. 완전히 분석한 객체의 실제 미정의 필드만 `absent`로 판단한다.

## 고정 소스 근거와 검증

n8n 기준 커밋은 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`다.

- [Set 버전 연결](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/Set.node.ts), [Set V2 실행](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/SetV2.node.ts), [필드 합성·변환](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/helpers/utils.ts).
- [IF V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/IfV2.node.ts), [Switch V3](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Switch/V3/SwitchV3.node.ts).
- [Merge 모드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/index.ts), [chooseBranch](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/chooseBranch.ts), [위치 결합](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/combineByPosition.ts).

`test/value-flow.test.mjs`의 합성 사례는 민감도·외부 조작성 분리, 필드 매핑·제거, 정확한 조건 연결, 우회 분기, fallback, 병합, Code 미실행, 순환 종료를 검증한다. 128/129 필드 경계, 중첩 배열, 한도 뒤 속성 덮어쓰기, 비밀·개인정보 혼합 분류와 단일 필드 선택도 회귀 검증한다. 실제 팀 API·운영 환경·임의 프로그램의 완전 분석 검증은 포함하지 않는다.
