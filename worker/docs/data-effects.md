# 로컬 데이터 처리의 정적 효과 프로필

`static-flow.ts`의 base HTTP/SSRF/SQL/응답 규칙은 지원하지 않는 노드마다 `opaque_node_effects`를 남긴다. 같은 노드가 네 규칙에서 반복될 수 있다. 확장 connector·AI 규칙이 별도로 있다는 이유만으로 이 진단을 없애지 않는다. base 규칙이 실제 노드 효과·버전·포트와 경로 의미를 확인해야 한다.

base 프로필 1.5.0은 아래 노드 계열을 다룬다. 표현식·워크플로·노드를 실행하지 않으며 기존 Acorn과 제한된 값 흐름 해석기를 재사용한다.

| 노드                   | 확인한 효과                                                                                            | 경로에 사용하는 범위                                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Set 3–3.5 manual/raw   | 입력 필드의 로컬 구성·선택·변환. 알려진 옵션과 필드 선언 검증                                          | 이름으로 지정한 원본 노드의 직접 참조 연결만 통과. 현재 값이 원본과 같다고 하지 않음                                           |
| Switch 3–3.5 rules     | 고정된 규칙 목록과 fallback에 따라 입력 JSON을 출력으로 분배                                           | 검증된 출력 번호에서 현재 입력 출처 보존. 조건 실행이나 숫자 방어를 추가로 증명하지 않음                                       |
| Aggregate 1            | 필드·아이템을 로컬 목록으로 모음. 중복 필드·잘못된 선언 검증                                           | 직접 원본 참조 연결만 통과. 집계 위치·개수·민감도는 별도 값 흐름의 미확인 유지                                                 |
| Limit 1                | 고정 양의 정수 `maxItems`(기본 1, 최대 1,000,000)와 `firstItems`/`lastItems`(기본 first)로 아이템 선택 | 현재 아이템의 JSON 값·출처 보존. 실제 선택된 아이템 번호·개수나 새로운 입력 검증 조건을 증명하지 않음                          |
| Merge 3/3.1/3.2 append | 기본 모드는 append. 2–10개 고정 입력의 아이템 목록을 연결                                              | 유효한 입력 번호를 지나는 원본 직접 참조 경로만 통과. 현재 아이템 출처 하나를 선택하거나 combine/SQL 모드를 승인하지 않음      |
| Split Out 1/1.1        | 고정 JSON 필드 목록을 분해하고 지정된 다른 필드를 복사                                                 | 원본 직접 참조 경로만 통과. 변환된 현재 필드 위치는 동일하다고 하지 않음. binary 분할/복사, 동적·prototype·대괄호 경로는 제외  |
| Error Trigger 1        | main 입력이 없는 오류 정보 생성 출처                                                                   | 출력은 Webhook 원본 전달이 아님. 가짜 입력 연결은 미지원 유지                                                                  |
| Stop and Error 1       | 선택된 오류 메시지·객체를 예외에 담고 실행 중단                                                        | main 출력이 없는 종료 노드. 별도 오류 payload 검사로 비밀·개인정보·전체 입력 후보를 확인. 오류 후 계속 실행 옵션은 미지원 유지 |

매개변수의 표현식은 Acorn AST로 단순 n8n 데이터 읽기, 고정 필드 선택, 일부 계산·선택 구문만 허용한다. 임의 함수 호출, 대입, callback, 동적 키, 프로토타입 접근은 이 효과 프로필에서 인정하지 않는다. 노드·AST 방문 2,048회, 표현식 65,536자, 구조 깊이·배열/객체 항목 한도를 적용한다. 원본 문자열은 진단이나 문서에 복사하지 않는다.

Set/Aggregate의 선언은 기존 bounded 값 해석기로 다시 확인한다. 같은 분석에서 먼저 읽혀 캐시된 노드도 기존 진단을 함께 확인한다. 알 수 없는 upstream 값은 해당 값 분석에서 유지하며, 이 불확실성을 곧바로 새로운 HTTP·SQL 실행 효과로 취급하지 않는다. 반대로 선언 오류·분석 예산 초과를 정상 프로필로 인정하지 않는다.

미래 버전, 비정상 입력/출력 포트, AI 등 별도 연결 채널, `continueOnFail`·`executeOnce`·비표준 오류 처리 등의 실행 옵션은 이 범위에서 제외한다. 코드가 없는 node type이라는 이유만으로 무조건 검사를 완료하지 않는다. 실제 런타임·권한·네트워크 접근, 데이터 값과 안전성은 검증한 것이 아니다.

고정 n8n 기준은 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`다.

- [Set 버전 매핑](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/Set.node.ts), [Set 실행 분기](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/SetV2.node.ts), [manual](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/manual.mode.ts), [raw](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/raw.mode.ts).
- [Switch rules와 fallback 출력](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Switch/V3/SwitchV3.node.ts).
- [Aggregate 집계·중복·필드 선택](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/Aggregate/Aggregate.node.ts).
- [Limit 아이템 선택](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/Limit/Limit.node.ts).
- [Merge 버전 매핑](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/Merge.node.ts), [append 기본 모드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/index.ts), [append 구현](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/actions/mode/append.ts), [입력 포트](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Merge/v3/helpers/utils.ts).
- [Split Out JSON/binary 분해·복사](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Transform/SplitOut/SplitOut.node.ts).
- [Error Trigger](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ErrorTrigger/ErrorTrigger.node.ts), [Stop and Error 실행](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/StopAndError/StopAndError.node.ts), [오류 객체 전체 metadata 보존](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/StopAndError/utils.ts).

`test/static-data-effects.test.mjs`는 직접 원본 경로와 현재 값 경로를 구분하고, Switch 출력과 숫자 guard의 차이, 임의 호출 미실행, 잘못된 선언·포트·버전·실행 옵션, 캐시된 실패, 기존 connector 미지원 보존을 검증한다.

`test/static-effect-profiles.test.mjs`는 추가 효과 프로필의 정상·미지원·변형 사례와 오류 payload 검사를 검증한다. Stop and Error는 실제 로그 수집이나 외부 전송을 주장하지 않고, 예외 메시지·메타데이터에 들어갈 민감 후보와 오류 처리 검토 필요성을 보여준다. `errorObject`의 고정 JSON은 데이터로만 파싱하므로 그 안의 표현식처럼 생긴 문자열은 n8n 코드로 해석하지 않는다. 원본 내용·사용자 필드명은 결과에 복사하지 않으며 고정된 코드와 nodeKey/구조 위치만 남긴다. 선택되지 않은 저장 필드는 오류 노출로 계산하지 않는다.

base 규칙의 finding 생성은 중복 ID를 먼저 확인하고 계약의 256개 한도를 지킨다. 한도를 넘으면 후속 위치에 `definition_finding_limit`를 남긴다. 더 높은 심각도의 후보를 보존하기 위해 낮은 심각도 항목을 교체한 경우에도 이전 위치의 coverage를 partial/unsupported로 갱신한다. 원인 종류를 하나로 합쳐 숨기지 않는다. 255·256개 경계와 91개 노드의 270개 후보 사례에서 256개 결과, 높은 심각도 90개 보존, 누락 위치 표시와 스키마 유효성을 검증했다. 이 회귀를 포함한 해당 세 테스트 파일은 48개가 통과했다.

2026-11-23의 예비 source 회귀에서는 0.8.0 최종 공개 25개 입력(`v080-final` 15개 + `v080-final-extra` 10개, 기준 이미지 `28b673341d36`)을 그대로 읽어 base 4규칙을 비교했다. `opaque_node_effects`는 1,030→998건이었다. 감소 32건은 Error Trigger 8, Stop and Error 8, Limit 4, Split Out 8, Merge append 4건이며 각 노드가 여러 규칙에 걸쳐 집계되므로 워크플로 수나 취약점 수가 아니다. `partial_workflow_topology` 44건과 base의 비표준 실행 진단 22건은 유지됐다. `alwaysOutputData`가 켜진 다른 Merge append는 범위 밖으로 남겼다. 공개 사례의 두 Stop and Error는 상수 메시지였으며 새 오류 payload 민감 후보가 없었다. 합성 양성·음성과 기존 회귀 총 47개는 통과했다. 이 비교는 워크플로 실행이나 최종 Docker 전체 검사·탐지 정확도 벤치마크가 아니다.
