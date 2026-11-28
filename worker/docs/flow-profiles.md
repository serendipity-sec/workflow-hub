# 정적 흐름 검사 프로필

현재 규칙 프로필 버전은 **1.5.0**이다. Set·Switch·Aggregate의 제한된 로컬 데이터 효과와 선언 연결을 추가했다. 1.3.0에서 추가한 고정 interval Wait 1/1.1 지원도 유지한다. webhook/form 재개·동적 시간·잘못된 단위와 실행 옵션은 여전히 미확인이다. 과거 프로필과 의미가 같은 검사로 비교하지 않는다. 상세 지원과 고정 소스는 [데이터 처리 효과](data-effects.md), [값 흐름](value-flow.md#waitaggregate외부-트리거의-추가-프로파일)을 따른다.

`src/rules/static-flow.ts`는 JSON 정의만 읽으며 표현식·SQL·HTTP 요청을 실행하지 않는다. 네 가지 규칙은 독립된 범위·근거·진단을 반환한다. 아래 지원은 파일에서 확인한 설정과 제한된 선언 경로에 대한 것이며 실제 공격 성공·데이터 유출·실행 환경의 안전 판정이 아니다.

| 규칙                    | 지원 범위                                                                                                                           | 반환하는 근거와 한계                                                                                                                                                                                                                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `N8N_HTTP_EGRESS`       | HTTP Request 3, 4, 4.1–4.5의 `url`, 활성화된 본문 설정                                                                              | 고정/동적 목적지와 본문 전달 설정을 검토 항목으로 기록한다. URL·본문·토큰 원문을 결과에 복사하지 않는다. 수신자가 허용됐는지 또는 데이터가 민감한지는 확정하지 않는다.                                                                                                                                                          |
| `N8N_HTTP_SSRF`         | 같은 HTTP Request 버전의 URL 표현식과 제한된 로컬 주소 리터럴                                                                       | 동적 전체 URL·authority와 고정 authority 뒤 경로/쿼리 값을 구분한다. 제한된 Webhook 참조 경로가 확인되면 `supported_path`, 출처를 해석하지 못하면 `candidate`와 미확인 진단을 반환한다. 로컬 주소 설정은 `configuration` 검토 항목이며 입력에 의한 SSRF로 단정하지 않는다. DNS·리다이렉트·실제 내부망 도달성은 검사하지 않는다. |
| `N8N_SQL_TEXT_FLOW`     | Postgres 2.4, 2.5, 2.6, 2.8의 `database/executeQuery`                                                                               | SQL 텍스트 표현식의 입력 경로를 확인한다. resource 생략은 database 기본값을 적용하지만 operation 생략은 insert로 취급한다. 정적 SQL의 전체 의미나 임의 SQL 안전성을 판정하지 않는다.                                                                                                                                            |
| `N8N_RESPONSE_EXPOSURE` | Respond to Webhook 1–1.5의 전체 아이템/JSON·text 응답, Webhook 2/2.1/2.2의 lastNode 응답, Code 1/2 JavaScript의 제한된 console 호출 | 전체 입력 응답과 전체 입력 로그 후보를 기록한다. `responseKey`는 전체 입력을 필드 안에 감싸므로 노출을 줄인 것으로 취급하지 않는다. 특정 필드 표현식은 전체 입력 노출로 부르지 않으며 데이터의 실제 민감성은 미확인이다.                                                                                                        |

## 경로와 검증 조건

- 지원 표현식은 `$json`의 점 표기 필드와 `$('Node').first().json`의 점 표기 필드다. 일반 JavaScript, 배열 접근, 변환 함수는 해석하지 않는다.
- HTTP URL과 응답 필드의 표현식은 n8n의 `=` 접두사가 있을 때만 해석한다. Postgres 쿼리는 별도 처리기가 원문 안의 `{{...}}`도 치환하므로 두 의미를 구분한다.
- URL의 숫자·축약 IPv4 표기는 WHATWG URL 정규화 후 비교한다. 현재 로컬 주소 프로필은 IPv4의 0/8, 사설·공유·루프백·링크로컬 범위와 `localhost`, IPv6의 미지정·루프백·unique-local·link-local 및 해당 IPv4-mapped 표기다. 전체 특수 주소·DNS·클라우드 메타데이터 인증 정책 목록은 아니다. HTTP/HTTPS 외 고정 스킴은 미지원으로 남긴다.
- 현재 아이템 참조는 단일 입력의 IF 2/2.1/2.2/2.3, No Operation 1, 고정 interval Wait 1/1.1과 아래 검증된 Switch rules 출력을 통과시킨다. IF와 Switch의 정상 출력은 원래 JSON 아이템을 전달하지만 Switch 조건이나 IF 2.3의 filter 3을 기존 숫자 보호로 승격하지 않는다. HTTP/DB 노드의 출력 JSON을 이전 Webhook 입력과 같다고 가정하지 않는다.
- 직접 원본 참조는 이름으로 지정한 Webhook과 실제 선언 연결 경로를 확인한다. 노드 이름은 내부 조회에만 쓰고 결과에 복사하지 않는다.
- Code, Merge, 미지원 노드의 효과는 해당 규칙의 미지원 범위로 남긴다. 이 때문에 별도로 확인된 URL·SQL 설정 근거를 지우지 않는다.
- Sticky Note 1의 정상적인 독립 주석, Manual Trigger 1, Schedule Trigger 1/1.1/1.2/1.3/1.4, No Operation 1에는 근거 없는 `opaque_node_effects`를 만들지 않는다. 정확한 버전·포트·표준 실행 옵션을 확인하며, 가짜 Sticky Note 연결이나 Trigger 입력 포트, 미래 버전은 미검토로 남긴다. Schedule은 시간 메타데이터를 내보내고 Manual은 빈 아이템을 시작하므로, 이 제외가 Webhook 입력 전달이나 데이터 민감성 분석을 의미하지 않는다. 다른 해당 sink가 없으면 `not_applicable`이다. 주석 문자열의 비밀/개인정보 검사는 별도 내용 규칙에서 유지한다.
- Set 3–3.5의 manual/raw, Switch 3–3.5의 rules, Aggregate 1은 [데이터 처리 효과 프로필](data-effects.md)에 따라 설정·표현식·버전·포트·실행 옵션을 검증한다. 이 프로필은 HTTP·SQL·응답의 외부 효과를 추가하지 않는 제한된 데이터 처리를 구분하고, 직접 원본 참조의 선언 경로를 실제로 통과시킨다. Switch만 현재 JSON 입력을 보존하며 Set/Aggregate의 변환 결과를 원래 Webhook 값과 같다고 가정하지 않는다. 미검토 connector·AI·Code의 효과 진단은 일괄 제거하지 않는다.
- Code 로그 검사는 Acorn AST로 `console.log/info/warn/error/debug/dir/table`에 직접 전달한 `$json`, `$input.all/first/last()` 및 이 값의 `JSON.stringify`만 찾는다. 주석·문자열 안의 가짜 호출을 제외하며 코드를 실행하지 않는다. 별칭·변수 추적·수신자 이름의 재정의·실제 로깅 여부·데이터 민감도는 해결하지 않아 후보와 부분 분석 진단을 함께 남긴다. 이 검사로 Code 노드의 데이터 변환을 해석했다고 처리하지 않는다.
- SQL의 IF 보호 판정은 기존에 검증한 `SELECT column FROM table WHERE column = {{ reference }}` 단일 조회 형태와 IF 2.2의 단일 엄격 숫자 동등 조건에 한정한다. 실제 출처·필드가 같고 경로를 보호해야 한다. 무관한 IF, 느슨한 형변환, 일반 SQL 표현식은 보호로 인정하지 않는다.
- 쿼리 문자열의 직접 삽입은 별도 Query Parameters 설정이 있어도 경고한다. 이 일반 규칙의 경고 소실은 바인딩 수정 효과나 정상 기능 보존의 증명이 아니다. 기존 정밀 SQL 분석·재검사 기록은 그대로 보존한다.
- 순환·복수 입력·해석할 수 없는 변환은 현재 입력 출처를 불확실하게 만든다. 탐색은 노드/연결 한도 안에서 종료한다.
- 직접 연결도 지원 노드의 출력 번호와 Webhook 메서드 설정이 맞아야 한다. 복수 메서드 기본값은 GET/POST 두 출력이다. 미지원 변환·실행 옵션을 포함한 직접 참조 경로는 입력 출처를 확정하지 않는다.

## #7 설계 대비 현재 범위

- 4번 외부 전송: HTTP 목적지와 본문 설정을 검토한다. 이메일·메시지 수신처, 사용자 허용 대상 정책, 전체 필드 민감도 전파는 아직 지원하지 않으며 해당 노드는 미지원 진단으로 남긴다.
- 5번 SSRF: 제한된 Webhook 입력 참조와 URL authority 영향, 로컬 주소 리터럴을 검사한다. 임의 URL 변환·DNS·리다이렉트·네트워크 집행은 미확인이다.
- 6번 SQL: 지원 Postgres 버전의 직접 SQL 문자열 삽입과 좁은 숫자 IF 보호 조건을 검사한다. 일반 SQL 파서·임의 바인딩 효과 증명·다른 DB 노드는 범위 밖이다.
- 9번 응답·로그: 전체 입력 응답과 제한된 전체 입력 console 후보를 검사한다. DB 결과의 필드별 민감도, 임의 로그 라이브러리와 메시지 노드는 아직 미확인이다.

10개 항목에 규칙이 존재하는 것과 #7의 확장 설계 전체 구현은 다르다. 실제 팀 API·실행 환경 연계도 이 모듈의 검증에 포함하지 않는다.

## 고정 n8n 소스 근거

기준 소스는 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`이다.

- [Webhook 정의](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/Webhook.node.ts): 버전과 복수 HTTP 메서드 기본값. [Webhook 설정](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/description.ts): 인증 none, 단일 메서드 GET, lastNode 응답과 noData.
- [IF V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/IfV2.node.ts): true/false 출력으로 입력 아이템을 전달한다. 현재 정밀 숫자 조건 판정은 기존 2.2 프로필 범위에 한정한다.
- [Postgres V2 기본 resource](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/versionDescription.ts), [기본 operation](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/Database.resource.ts), [쿼리·파라미터 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/executeQuery.operation.ts). 2.8부터 누락 배열 원소의 NULL 보존과 단일 표현식의 쉼표 처리가 달라지므로 2.5/2.6의 바인딩 의미를 2.8과 동일하다고 가정하지 않는다.
- [HTTP Request 버전 연결](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/HttpRequest.node.ts), [V3 필드 정의](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/V3/Description.ts), [실제 요청 옵션 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/V3/HttpRequestV3.node.ts). 버전 4 이상은 설정 생략 시 리다이렉트를 기본 허용하므로 고정 URL 원점만으로 네트워크 목적지를 보증하지 않는다.
- [Respond to Webhook](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts): 기본 firstIncomingItem, 전체 아이템 응답과 responseKey 래핑.
- [IF V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/IfV2.node.ts): IF 2.3의 filter 3과 true/false 배열에 원래 item을 넣는 동작. 본 모듈의 numeric guard는 IF 2.2/filter 2로 유지한다.
- [Sticky Note](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/StickyNote/StickyNote.node.ts), [Manual Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ManualTrigger/ManualTrigger.node.ts), [Schedule Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Schedule/ScheduleTrigger.node.ts), [No Operation](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/NoOp/NoOp.node.ts): 정확한 버전·입출력 포트와 제한된 실행 의미.
- [IANA IPv4 특수 주소](https://www.iana.org/assignments/iana-ipv4-special-registry/), [IANA IPv6 특수 주소](https://www.iana.org/assignments/iana-ipv6-special-registry/): 로컬 주소 리터럴 분류의 참고 근거. 주소 범위만으로 실제 라우팅이나 악용 가능성을 판정하지 않는다.

검증은 `test/static-flow.test.mjs`의 합성 정의로 수행한다. 원본 공개 템플릿, 실제 비밀값 또는 사용자 파일을 fixture에 추가하지 않는다.
