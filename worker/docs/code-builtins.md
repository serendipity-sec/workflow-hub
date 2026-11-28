# Code 변환과 Limit 프로파일 보완

이 문서는 #14의 0.9.0 작업 중 Code·값 흐름 담당 범위와 검증을 기록한다. 입력은 기존 0.8.0 고정 공개 25개이며 원본·0.8.0 결과는 수정하지 않았다. Acorn AST와 기존 추상값 분석을 재사용하며 공개 JavaScript·정규식·워크플로를 실행하지 않는다.

## 기존 진단의 구분

고정 비교 기록의 sample ID 25개를 기준으로 Code 노드는 66개다. 두 폴더의 10111 중복 파일을 별도 표본으로 세지 않았다. JavaScript 64개에 붙은 `code_logging_semantics_partial`과 `javascript_semantics_partially_analyzed`는 각각 로그 AST 검사와 JavaScript 검사 후 무조건 추가하는 일반 범위 설명이다. `code_logging_and_sensitivity_partially_analyzed`도 기본 규칙의 일반 설명이다. 이 문구만으로 해당 노드의 구체 기능이 미구현이라고 판정하거나, 반대로 문구를 제외한 것만으로 실제 실행 부작용 검사를 완료했다고 판정하지 않는다.

확장 규칙에서 Code 위치로 표시된 구체 진단은 `code_statement_profile_unresolved` 14개 노드, `code_call_effect_unresolved` 5개, `code_closure_capture_unresolved` 4개, `code_expression_profile_unresolved` 2개다. `field_projection_partial` 53개와 `flow_budget_exceeded` 21개는 상위 노드의 미확인 구조가 전달된 경우도 포함하므로 독립 결함 수가 아니다. Python 2개는 별도 제한 프로파일이다. 이 수치는 0.8.0 표본의 노드별 진단 집계이며 전체 탐지율이나 취약점 개수를 뜻하지 않는다.

위험한 목적지와 연결되는 사례에서 작은 내장 변환 때문에 노드 전체가 불명확해지는 경로를 우선했다.

| 표본·노드        | 실제 변환과 다음 단계                                                                                | 보완 결과와 남은 범위                                                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 8965 `/nodes/5`  | 이미지 URL의 `split(...).pop()`으로 이름을 만들고 여러 HTTP 요청에 전달                              | 원본과 후보 출처를 보존하며 imageUrl·filename·contentType 필드 구조를 전달한다. 동적 JSON 내용과 실제 타입·변환 성공은 미확인이다. |
| 10111 `/nodes/5` | 응답의 정규식 `match`, 문자열 분리와 배열 `slice/join`으로 메일 내용을 구성하고 Postgres 단계로 전달 | 이 내장 호출 때문에 중단하지 않고 이후 분석을 진행한다. 반복문 누적·객체 변경은 계속 명시적인 미지원이다.                          |
| 10111 `/nodes/3` | 입력 날짜·현재 날짜와 `Math.floor`로 알림 조건을 만들고 SQL 단계로 전달                              | 날짜·숫자 연산의 출처를 유지한다. 결과 날짜·숫자·조건 성공은 확정하지 않으며 반복 누적의 한계는 남는다.                            |

20459의 동적 SQL 조립·클로저·집계, 11007의 외부 HTTP 호출과 복잡한 반복, 6216의 구조 분해와 객체 순회·reduce 등은 이 제한 프로파일로 해결됐다고 표현하지 않는다. 외부 명령·SQL·요청으로 전달되는 입력 후보와 구체 미지원 진단을 유지한다.

## 제한된 변환 규칙

- `join`은 이미 확인된 추상 컬렉션의 원소와 구분자 의존성을 보존하고 문자열 결과에 배열 구조를 복사하지 않는다.
- 컬렉션 `slice`는 가능한 원소를 요약한다. 시작·끝 인자는 별도 의존성으로 유지하며 출력 위치·길이를 확정하지 않는다.
- `pop`은 구문상 즉시 생성한 `split` 결과에서만 허용한다. 별칭에 저장한 배열의 pop, 일반 배열 변경, 임의 메서드는 계속 불명확한 효과로 처리한다.
- 리터럴 정규식 `match`는 입력의 의존성을 가진 가능한 캡처를 요약한다. 정규식은 실행하지 않으며 매칭·검증 성공, 캡처 존재, 특정 출력 위치를 보장하지 않는다. 동적 matcher는 지원하지 않는다.
- 가려지지 않은 `Date` 생성자(0·1개 인자), `Date.now/parse`, 제한된 `Math.floor/ceil/round/trunc/abs/min/max`, `Number.isFinite/isInteger/isNaN/isSafeInteger`는 인자의 출처만 전달한다. 유한수나 안전한 입력이라는 검증 조건을 만들지 않는다.
- 즉시 생성한 Date와 `$now`/`$today`의 고정 형식 메서드도 지역 변수·함수 인자의 출처를 먼저 해석한다. 날짜 결과·형식 변환 성공은 확정하지 않는다. 다른 생성자·알 수 없는 메서드·동적 선택·spread·가려진 이름은 미지원으로 남기면서 생성자와 메서드 인자의 위험 후보를 보존한다.

새 `code_builtin_result_unverified`는 타입 변환·결과·성공이 미확인임을 명시한다. 기존 AST·형태·요청 예산은 늘리지 않았다. 동적 메서드, 전역 이름 가림, 일반 변경 효과, 외부 호출, 콜백 효과는 기존 미지원 처리를 유지한다. 이 규칙은 [ECMAScript 배열 메서드](https://tc39.es/ecma262/multipage/indexed-collections.html), [문자열 match](https://tc39.es/ecma262/multipage/text-processing.html#sec-string.prototype.match), [날짜·숫자 내장 함수](https://tc39.es/ecma262/multipage/numbers-and-dates.html)의 의존성과 반환 형태를 제한적으로 모델링한다.

## Limit 1

[고정 n8n Limit 구현](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/Limit/Limit.node.ts)은 입력 item 목록을 slice하며 각 item의 JSON을 변경하지 않는다. 값 흐름은 버전 1, 기본값 또는 양의 고정 정수 maxItems(최대 1000000), firstItems/lastItems, 알려진 필드와 빈 options, 표준 실행, 단일 main 입력 0·출력 0에서만 JSON 필드·출처·분류와 동일 값의 기존 guard를 보존한다. 실제 item 수·원래 목록의 위치·실행 성공은 증명하지 않는다. 동적 설정, 0·음수·분수, 알 수 없는 버전·설정, 다중 입력과 비표준 실행은 미확인이다.

## 검증 경계

새 합성 검사는 내장 변환 8개와 Limit 2개다. 비밀·개인정보 후보, 내부 분류, 형제 필드 제외, 구분자·slice 범위 의존성, 정상 공개 필드 분리, 동적 메서드·변경·콜백 반례, Limit의 정확한 값 guard와 우회 입력을 검사한다. 독립 리뷰에서 `const x=$json.body.password; new Date(x).toISOString()`의 기존 AST 전달이 지역 변수 출처를 잃는 것을 발견해 수정했다. 직접 입력·지역 별칭·함수 인자·형식 옵션·현재 시각·이름 가림·임의 생성자/메서드를 함께 검사한다.

공유 dist에 쓰지 않고 Node module hook과 메모리 TypeScript 변환으로 담당 모듈만 교체했다. 나머지 0.8.0 모듈과 조합한 관련 **281개** 회귀가 통과했다. 동시에 작업 중인 전체 0.9.0 통합 검사는 통합 담당자가 별도로 수행한다.

고정 공개 원본의 직접 정적 비교에서 8965 노드 5는 출력 필드 맵이 0개에서 3개로 바뀌고 `code_call_effect_unresolved`·`code_effects_partially_analyzed`가 사라졌다. 10111 노드 3·5는 날짜·숫자·match 호출의 초기 미지원 이후로 진행하면서 기존 반복 누적·객체 변경 한계를 드러냈다. 세 노드 모두 `partial`이며 이전 unknown·개인정보 후보 분류는 유지됐다. 이 비교는 전체 native 도구 검사·워크플로 실행·업무 기능 보존 검증이 아니다.
