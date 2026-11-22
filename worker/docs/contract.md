# 워커 계약 1.0.0

기준은 [Workflow Hub PR #7](https://github.com/serendipity-sec/workflow-hub/pull/7)의 정적 분석 설계입니다. Node.js 24.14.0과 TypeScript를 선택했습니다. 팀의 런타임과 일치하고, 내장 HTTP·해시·프로세스 API와 Zod 스키마로 입력과 출력을 검증할 수 있습니다. 코드는 Workflow Hub의 `worker/`에서 관리합니다. [관련 이슈와 선행 PR](../README.md#작업-이력)을 함께 추적합니다.

## 지원 범위

판정 대상은 n8n 2.48.7의 단일 JSON POST Webhook에서 선택적 IF 한 개를 거쳐 Postgres 읽기 쿼리 한 개로 이어지는 main 경로입니다. 지원표의 버전은 노드의 `typeVersion`입니다. 입력은 단일 JSON 아이템이며 최초 본문을 `body`에서 읽습니다.

| 노드                      | 버전 | 지원 설정                                                                                                                                                                                                                                       |
| ------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `n8n-nodes-base.webhook`  | 2    | 단일 POST, 빈 options, 수신 JSON, 고정 path. HTTP 응답 모드는 기본값 또는 `lastNode`. 인증은 기본 none 또는 명시적 none                                                                                                                         |
| `n8n-nodes-base.if`       | 2.2  | 단일 엄격 숫자 동등 조건, `and`, 정수 리터럴 비교, 전달 데이터 유지. true 출력 0, false 출력 1                                                                                                                                                  |
| `n8n-nodes-base.postgres` | 2.8  | database의 executeQuery. 기본 options 또는 `queryReplacement` 하나. SQL은 `SELECT column FROM table WHERE column = operand` 형태의 단일 값 조회. 식별자는 따옴표 없는 ASCII 식별자, operand는 정수 리터럴, 표현식 한 개 또는 인용되지 않은 `$1` |

표현식은 앞뒤 공백을 허용하는 `$json.body.field` 또는 연결된 동일 Webhook의 `$('Webhook').first().json.body.field`입니다. 노드 이름은 인용부호가 없는 ASCII 이름 범위만 지원합니다. SQL 필드 안의 보간은 `SELECT … {{ … }}`와 식 모드 `=SELECT … {{ … }}`를 지원합니다. `$1`에는 `={{ [ $json.body.field ] }}`처럼 지원 참조 한 개를 원소로 갖는 배열식을 요구합니다. 이를 n8n pg-promise 경로의 값 파라미터 처리로 기록합니다. 동적 값이 SQL 필드에 직접 들어가는 경우 options의 존재만으로 보호된 것으로 판단하지 않습니다. 동일 출처와 동일 필드를 엄격 숫자 조건으로 검증하고 그 IF가 유일한 경로를 지배하면, 해당 값은 참·거짓 출력 모두에서 임의 SQL 문자열이 될 수 없어 `guarded`로 분류합니다. 참 출력에서만 리터럴과 동등합니다. 다른 필드에 대한 검증과 같은 Webhook의 미검증 다른 필드 직접 참조는 대상 값을 제한하지 않습니다.

부분 분석에는 분석 범위와 누락 영향이 포함됩니다. 위 표 밖의 버전·노드·옵션과 표현식, Code, 하위 워크플로, Merge, AI 연결, 복수 입력·분기·경로, 순환, 비활성 노드, 핀 데이터, 오류 계속 실행, SQL 주석·다중문·인용된 자리표시자·일반 SQL을 미지원으로 반환합니다. 미지원 또는 불완전한 결과를 안전 판정으로 사용할 수 없습니다. JSON이 유효하지 않거나 연결에 존재하지 않는 노드를 가리키는 경우는 오류입니다.

소스는 [Webhook](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/Webhook.node.ts), [IF 분기](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/If/V2/IfV2.node.ts), [IF 조건 비교](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/node-parameters/filter-parameter.ts), [Postgres 쿼리 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/executeQuery.operation.ts), [Postgres 쿼리 실행](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/helpers/utils.ts)입니다.

## 작업과 결과

유효성 기준은 [코드 스키마](../src/contract.ts)입니다. `Task`는 contractVersion, taskId, attemptId, workflowVersionId, inputSha256, UTC leaseExpiresAt, file을 받습니다. 로컬 file은 경로를 사용합니다. 팀 file은 제어부에서 설정한 정확한 HTTPS 파일 origin의 단기 URL을 사용합니다. URL은 리디렉션을 따르지 않고 파일 요청에는 API 자격 증명을 첨부하지 않습니다. 실제 읽은 원본 바이트 SHA-256을 일치시킨 뒤 분석기에 전달합니다.

결과는 동일한 식별자와 원본 해시를 반복하며 계약·엔진·규칙·어댑터 버전을 함께 담습니다. `analyzed`에는 범위와 근거가, `unsupported`에는 영향 노드와 진단이, `error`에는 정해진 오류 코드와 가능할 때 원본 위치가 들어갑니다. 근거는 source, sink, 제어 경로, 표현식 종류, IF 관련성, 분석 전제와 수정 위치입니다. 근거의 JSON Pointer는 제출한 파일의 위치입니다. 노드 표시 이름·SQL·표현식·값·파일 URL을 결과나 로그에 덤프하지 않습니다. `analyzed`에 findings가 없으면 해당 규칙과 분석한 필드에서 경고가 없음을 뜻합니다.

`unsupported`의 `affectedNodeKeys`에는 각 영향 노드 키를 한 번만 담고, 각 진단의 `affected`에는 이 목록의 인덱스를 담습니다. 이렇게 하면 큰 그래프에서도 영향을 받은 모든 노드를 출력 한도 안에서 참조할 수 있습니다. 각 진단은 해당 원본 위치를 유지합니다.

비교용 노드 키는 노드 ID의 SHA-256입니다. `inputKey`는 출처 노드 키와 필드 키의 해시, `shapeKey`는 SQL 값 위치 이외에 의미가 유지되는 조회 형태의 해시입니다. finding ID는 규칙 ID, 출처·sink 노드 키와 입력 키, sink 필드 역할을 결합해 계산합니다. 배열 재배치나 표시 이름 변경은 finding ID를 바꾸지 않습니다. 다른 파일 버전·같은 분석 버전·같은 노드와 의미가 대응하는 경우에만 값 바인딩 전환을 검증합니다. 분석 범위 축소, 실패, 대응 노드 변경, 조회 형태 변경, 기능 제거, 다른 엔진·규칙·어댑터 버전은 해결 근거를 충족하지 않습니다. 기능 보존은 통제 사례의 별도 검증입니다.

## 팀 API 접점

이 표는 워커가 제안하고 계약 모의 서버로 검증할 접점입니다. 서버가 lease와 결과 수락을 결정합니다.

| 요청                                                                 | 응답                                                                                                         |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `POST /internal/worker/v1/claim`                                     | 200 작업 JSON, 204 빈 큐, 401/403 인증 실패                                                                  |
| `PUT /internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/result` | 201 수락, 200 동일 제출 재전송, 401/403 인증 실패, 409 충돌 또는 거절, 410 만료, 429/502/503/504 재시도 가능 |

API 요청은 서비스 Bearer를 사용합니다. 결과의 `Idempotency-Key`는 직렬화한 본문 바이트의 SHA-256으로 고정합니다. 일시적 제출 실패만 lease 이내에 같은 바이트와 키로 재시도합니다. 결과가 불확실한 claim은 자동 재전송하지 않습니다. API는 정상 분석에 최소 15초 lease를 할당하고 만료된 시도와 중복 제출을 확인합니다. 한 번에 작업 한 개를 처리하며 짧은 분석에 heartbeat가 필요할 경우 팀과 계약을 개정합니다.

최대 원본 256 KiB, JSON 깊이 32, 노드 64, 연결 128, 분석 출력 128 KiB, 분석 3초, HTTP 요청별 5초로 시작합니다. 분석기의 V8 힙 한도는 96 MiB입니다. 운영에서는 CPU 1개, 메모리 256 MiB, PID 32, 네트워크 차단, 읽기 전용 실행 환경과 비특권 실행을 인프라에서 실제로 보장해야 합니다. 분석기에 팀 API 토큰이나 다른 서비스 자격 증명을 전달하지 않습니다.

## 로컬 사례와 대조 도구

저장소 루트에서 `npm --prefix worker ci`와 `npm --prefix worker run verify`로 fixture와 스키마를 검증합니다. `worker/`에서 실행기는 `node dist/cli.js local <task.json>`과 계약 모의 서버용 `node dist/cli.js mock-once`를 제공합니다. `fixtures/task.json`의 고정 시각은 계약 검증용입니다. 실제 실행 때 새 lease가 있는 작업을 사용합니다. [선행 정답](../fixtures/cases.json)은 개발용과 검증용을 나누고 사례별로 상태, 판정과 근거를 지정합니다. 수정 전후 정상 입력은 숫자 ID 7, 업무 출력은 label이 book인 한 행이고 쓰기는 0건입니다. `direct-origin`은 n8n 비교에서 직접 SQL 경고가 수집되는지 확인하는 양성 대조 사례입니다.

비교의 단위는 해당 경로가 있는 워크플로 파일 한 개입니다. [n8n 2.48.7 database audit](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/cli/src/security-audit/risk-reporters/database-risk-reporter.ts)와 [FlowGuard](https://github.com/MohibShaikh/FlowGuard/tree/03b348d008eaafdebc3650973561d8091af1d8c8)를 기준선으로 사용합니다. SQL에 대한 직접 탐지와 일반 입력 검증 경고를 구분하고, 지원 여부와 실패를 측정합니다. 이 도구들은 워커 런타임 의존성이 아닙니다. 로컬 fixture와 모의 서버는 개발 경로이며 실제 팀 API 및 운영 격리는 팀 환경에서 검증합니다.
