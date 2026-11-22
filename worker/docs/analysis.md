# Postgres 쿼리 분석

계약의 좁은 Webhook → 선택적 IF → Postgres 조회 경로를 검사합니다. [지원 범위와 고정 n8n 소스](contract.md#지원-범위)를 참고하세요. 분석기는 원본 바이트를 분석용 구조로만 읽습니다.

## 분류와 수정

- `interpolated`는 Webhook의 입력이 Postgres의 `parameters.query` 안에 들어가는 경로입니다. 같은 SQL 필드의 보간은 별도의 값 파라미터 옵션이 있어도 경고합니다.
- `guarded`는 같은 출처·필드가 두 출력에 공통인 엄격 숫자 검사를 통과한 보간입니다. true 출력만 리터럴 동등성을 갖습니다. 숫자 제약의 범위는 보고한 입력 하나입니다.
- `bound`는 고정 SQL의 값 위치에 `$1`을 두고, n8n `options.queryReplacement`에서 정확히 한 값을 배열식으로 전달한 구성입니다. `constant`는 입력 의존성이 없는 정수 조회입니다.
- `unsupported`는 분석할 수 없는 형태와 해당 위치를 반환합니다. `error`는 JSON·연결 실패와 같이 유효한 분석 결과를 만들 수 없는 경우입니다.

`use_value_parameter`가 반환되면 표시된 쿼리 필드의 동적 값 자리에 인용하지 않은 `$1`을 두고, 같은 입력을 수정 위치에 나타난 Query Parameters의 단일 배열 원소로 전달합니다. 값 위치에서만 사용하고, 기존 조회 조건과 권한을 유지하며 정상 입력 결과와 허용 부작용을 확인한 뒤 같은 분석 버전으로 재검사합니다.

## 재검사 대응

`compareAnalysis`에는 서버가 동일 워크플로의 버전으로 확인한 두 결과를 전달합니다. 원본 바이트 해시, 워크플로 버전, 엔진·규칙·어댑터·계약 버전과 분석 상태를 확인합니다. finding ID는 배열 위치와 표시 이름에 의존하지 않습니다. `shapeKey`는 SQL의 고정 식별자, Postgres 자격 증명 참조, Webhook 응답과 등록 경로, IF 조건과 출력의 의미를 반영합니다. 지원하는 고정 경로는 `webhookId`가 있으면 설정한 경로로 등록됩니다. `webhookId` 없이 n8n이 등록 경로 생성에 노드 이름을 쓰는 경우에는 이 이름을 입력에 포함합니다. [n8n Webhook 경로 구현](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/node-helpers.ts)

보고서는 비교 기준(`basis`), 이전과 새 분석의 상태 및 분석 범위 변화(`coverage`), 기존 경고의 재검사(`rechecks`), 대응이 성립하지 않은 새 결과의 경고(`newFindings`)를 제공합니다. 동일한 분석 기준과 조회가 확인되고 기준에 경고가 없을 때 새 경고를 `introduced`로 표시합니다. 조회가 바뀌었거나 기준이 불일치하면 새 결과에 관측된 경고를 `inconclusive`로 보존합니다. 분석 완료에서 미지원으로 바뀌면 `reduced`, 미지원에서 해당 경로 분석 완료로 바뀌면 `expanded`를 반환합니다. 실패나 검사 기준 차이는 `unknown`으로 반환합니다. 기존 `compareResults` 호출은 `rechecks` 배열을 반환합니다.

`binding_verified`는 같은 조회와 입력이 값 파라미터로 전환됐을 때의 구조 확인입니다. 기능 보존 검증을 포함하지 않습니다. 대응되는 경고가 유지되면 `persisting`을 반환합니다. 노드 교체·제거, 조회·경로 변경, 지원 범위 감소, 실패, 불일치하는 버전은 `inconclusive`를 반환합니다.

엔진 `0.1.1`은 지원하는 고정 Webhook 경로의 비교 키를 갱신했습니다. 이전 결과와 수정본을 비교하려면 양쪽 원본을 현재 엔진으로 다시 검사합니다. 이전 검사 결과의 구조를 읽을 수 있으면 해당 경고를 보존합니다. 서로 다른 검사 버전은 `different_analysis_versions`, 양쪽이 동일한 과거 기준이면 `unsupported_analysis_versions`, 버전 필드가 빠졌거나 형식이 잘못된 결과는 `invalid_result`로 남깁니다.

엔진 `0.1.2`는 숫자 IF의 거짓 분기를 보호된 경로로 보던 오류를 정정했습니다. `fixtures/cases-0.1.2.json`은 동일 원본의 해당 정답만 강화하고 기존 `cases.json`·실측 기록을 보존합니다. 구버전 결과와 경고 소실을 직접 비교해 수정 성공으로 처리하지 않습니다.
