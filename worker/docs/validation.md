# 워커 1차 검증

> 이 문서는 초기 0.1.0 실측 기록입니다. 0.1.2에서 IF 거짓 분기의 숫자 보호 가정이 정정됐으므로 당시 `type-constrained-false` 음성 표지와 집계는 현재 정확도 수치가 아닙니다. [현재 정답](../fixtures/cases-0.1.2.json)과 [후속 검증](public-partial-followup.md)을 확인합니다.

[Workflow Hub #18](https://github.com/serendipity-sec/workflow-hub/issues/18)의 실험 단위는 합성 n8n 워크플로 JSON 한 파일이다. [선행 정답](../fixtures/cases.json)과 [원본 바이트 SHA-256](../validation/case-sha256.json)을 고정했다. 전체 12개 중 경로 양성 4개, 경로 음성 4개, 지원 범위 밖 4개다. 이 중 검증용 분할에는 양성 3개, 음성 2개, 지원 범위 밖 4개가 있다. 개발용 3개는 전체 분모에 표시하고 검증용 분모에서 제외한다.

지원 양성을 처리하지 못하면 양성 분모에 미탐으로 남긴다. 실행 실패와 미지원 건수도 별도로 집계한다. 바이너리 정답이 정의되지 않은 네 파일은 도구별 원출력과 사례 판정을 보존하며 TP·FP·FN·TN 계산에서 제외한다. 탐지 과제는 해당 Webhook 입력이 Postgres 실행 쿼리 필드의 SQL 텍스트로 들어가는 경로다.

## 워커와 기존 도구 실측

한국 시간 2026-11-22에 세 실험을 실행했다. 컨테이너의 외부 연결을 막고 호스트 입력은 읽기 전용으로 마운트했다. [외부 검증 요약](../validation/external-results.json)의 각 사례는 [원본 출력과 종료 상태](../validation/raw)에서 다시 계산한다.

| 신호                              |  TP |  FP |  FN |  TN | 실패 |
| --------------------------------- | --: | --: | --: | --: | ---: |
| 워커 Postgres 정적 규칙           |   4 |   0 |   0 |   4 |    0 |
| n8n SQL 쿼리 필드 표현식          |   1 |   0 |   3 |   4 |    0 |
| n8n 미사용 Query Parameters 안내  |   4 |   4 |   0 |   0 |    0 |
| FlowGuard Postgres 입력 검증 경고 |   1 |   2 |   3 |   2 |    0 |

- n8n 2.48.7(노드 패키지 2.48.4)은 `import:workflow --separate --activeState=false`로 12개 정의를 임시 저장한 후 `audit --categories=database`를 실행했다. 쿼리 표현식 경고는 선행 `=`가 있는 양성 대조 `direct-origin`의 정확한 Postgres 노드에 보고했다. 선행 `=` 없이 쿼리 안에 표현식을 넣은 양성 세 건에는 해당 경고가 없었다. 미사용 Query Parameters 안내는 `additionalFields.queryParams`를 검사하며 바인딩·동일 필드 IF·상수 음성에도 표시됐다. [n8n 보안 감사](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security/run-security-audits.md) [고정 감사 코드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/cli/src/security-audit/risk-reporters/database-risk-reporter.ts)
- FlowGuard 0.2.0을 고정 커밋에서 빌드해 Node 20.20.2 컨테이너에서 12회 로컬 JSON 스캔했다. Postgres 노드 위치의 `missing-input-validation`을 일반 입력 검증 신호로 집계했다. IF가 없는 보간에서 경고했고, IF를 지나는 양성 세 건에서 이 경고가 없었다. 상수와 값 바인딩 정상 사례에도 해당 경고가 있었다. Webhook 인증 등 다른 규칙의 출력은 원본에 포함한다. [고정 규칙 코드](https://github.com/MohibShaikh/FlowGuard/blob/03b348d008eaafdebc3650973561d8091af1d8c8/src/rules/owasp/missing-input-validation.ts)

검증용 분할만 보면 워커는 TP 3, FP 0, FN 0, TN 2였으며, 지원 범위 밖 4개를 모두 미지원으로 반환했다. 전체와 검증 분할 모두 워커 실패는 0건이다. 비교 도구의 미지원 집계는 CLI가 별도로 보고한 상태를 뜻한다. 표의 결과는 이 합성 코퍼스와 선택한 경고 신호에 한정된다. 저장된 워커 결과에는 최초 검증에 사용한 엔진 `0.1.0`이 기록되어 있다. `worker` 재현 명령은 현재 엔진의 결과를 `evidence-local/worker`에 저장한다. [사례별 워커 결과와 재검사](../validation/worker-results.json)

## 수정 효과

재검사 하네스는 원본과 바인딩 수정본이 같은 조회 형태와 입력을 유지하는지 확인한다. 싱크 삭제, 미지원 노드 버전, 규칙 버전 변경 시 `inconclusive`를 요구한다.

CLI 검증 하네스는 같은 합성 사례의 역방향 비교도 `analysisComparisons`에 기록한다. 바인딩 버전에서 보간 버전으로 바뀌면 같은 분석 범위에 새 경고가 생긴다. 바인딩 버전에서 싱크가 삭제되면 분석 범위 축소를 표시한다. 비교 대상의 규칙 버전이 달라지면 새 경고의 대응은 `inconclusive`, 분석 범위 변화는 `unknown`으로 기록한다. [사례별 비교 결과](../validation/worker-results.json)

PostgreSQL 18.7의 격리된 임시 DB에 7/book과 9/pen을 입력했다. SELECT만 허용된 테스트 역할의 읽기 전용 트랜잭션에서 같은 정상 값 7을 상수 SQL과 수정본의 고정 SQL에 각각 적용했다. 고정 SQL은 `psql \bind`로 매개변수를 전달해 book을 반환했다. 값 9는 pen을 반환하고 존재하지 않는 13은 행을 반환하지 않았다. 테스트 전후 합성 테이블의 SHA-256이 같다. [PostgreSQL 18 psql 문서](https://www.postgresql.org/docs/18/app-psql.html)

위험 경로와 수정 후 값 파라미터 구조는 정적 워커에서 확인했다. PostgreSQL 상수 조회와 값 파라미터 조회는 정상 업무의 대조군이다. n8n의 원본·수정본 실행도 세 고정 숫자의 정상 조회 동작만 관측했다.

초기 수정본 시험은 경로 접두사 없이 호출해 세 요청 모두 HTTP 404를 받았다. 고정 n8n 소스가 `webhookId`가 없는 노드에 적용하는 경로를 확인한 뒤 재시험했다. [첫 실행의 404 응답](../validation/native-bound/report.json) [수정본 재시험](../validation/native-bound-correct-route/report.json) [n8n 경로 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/workflow/src/node-helpers.ts)

원본 `interpolated`와 수정본 `bound`의 고정 해시를 각각 확인하고 n8n 2.48.7에 넣었다. 게시된 각 노드 설정·연결·실행 순서가 시험 입력과 일치했고 `/healthz/readiness`가 HTTP 200을 반환했다. 결과에 버전별 실제 요청 경로와 게시·내보내기·일치 검사 로그를 포함했다. PostgreSQL 18.7은 `none` 네트워크를 사용하고 n8n과 같은 네트워크 namespace를 공유했다. 두 컨테이너의 호스트 포트 게시가 없고 n8n의 인터페이스 주소가 루프백뿐임을 확인했다. DB reader의 읽기 전용 트랜잭션, SELECT 권한과 쓰기 권한 부재도 실측했다. [Docker 네트워크 없음 드라이버](https://docs.docker.com/engine/network/drivers/none/) [정상 동작 비교 원출력](../validation/native-normal-parity.json)

| 고정 입력 | 원본과 수정본에서 관측한 같은 응답      |
| --------- | --------------------------------------- |
| 7         | HTTP 200, `{"label":"book"}`            |
| 9         | HTTP 200, `{"label":"pen"}`             |
| 13        | HTTP 500, `No item to return was found` |

직접 PostgreSQL에서 확인한 빈 조회 결과와 Webhook의 HTTP 응답은 각각 보고했다. DB 테이블의 SHA-256은 실행 전, 원본 실행 후, 수정본 실행 후 모두 같았다. 최종 실행은 PostgreSQL 데이터에 tmpfs를 사용했고, 연결된 볼륨 0개와 테스트 컨테이너 정리를 확인했다. 이전 실행의 익명 볼륨은 컨테이너 귀속 기록이 보존되지 않아 식별할 수 없었다. [테이블 해시와 정리 기록](../validation/native-normal-parity.json)

## 작업 API

`npm run verify`의 루프백 계약 테스트에서 작업 요청, 파일 수신과 해시 확인, 실제 분석 자식 프로세스, 결과 제출까지 연결했다. 인증 오류, 잘못된 해시와 파일 origin, 임대 만료·거절, 지연, 응답 유실과 같은 본문·키의 중복 수락도 확인했다. [계약 테스트](../test/runner.test.mjs)

## 재현 명령

저장소 루트에서 `worker/`로 이동해 Node.js 24.14.0과 npm으로 워커를 빌드한다. 아래 검증은 Docker 없이 재현할 수 있다.

```text
cd worker
npm ci
npm run verify
node validation/verify.mjs captured
node validation/verify.mjs worker
```

`worker/`에서 외부 도구의 고정 버전을 한 번 준비한다. FlowGuard의 빌드된 CLI도 SHA-256으로 확인한다. 런타임에서는 이미지 내려받기와 컨테이너 네트워크를 차단하고 실행 실패 시 해당 시험 컨테이너의 정리를 확인한다.

```text
git clone https://github.com/MohibShaikh/FlowGuard.git evidence-local/flowguard-validation
git -C evidence-local/flowguard-validation checkout --detach 03b348d008eaafdebc3650973561d8091af1d8c8
npm --prefix evidence-local/flowguard-validation ci --ignore-scripts --no-audit --no-fund
npm --prefix evidence-local/flowguard-validation run build
docker pull node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
docker pull docker.n8n.io/n8nio/n8n@sha256:fabce3e9678a07d2dde83bd8f5124017f3ec457d0a3fc6b63bb4cec465d63861
docker pull postgres@sha256:b6972e1115a4ff8eba5d7f7d19184926d1e16d7d1136ae1e1a7ebf286da0f015
node validation/verify.mjs external evidence-local/flowguard-validation
node validation/native-bound-control.mjs
```

Docker 없이 원본 출력의 분류를 다시 계산하려면 `captured` 명령을 사용한다. `worker`와 `external`의 기본 출력 경로는 각각 `evidence-local/worker`, `evidence-local/external`이다. n8n DB가 임시 워크플로 ID를 발급하므로 원본 감사 보고서의 ID는 실행마다 달라질 수 있다. `native-bound-control.mjs`는 고정 SHA-256과 일치하는 원본·수정본을 읽고 격리된 루프백에서 7·9·13만 요청한다. 시험 결과는 `evidence-local/native-normal-parity`에 남는다. 정상 조회, 빈 조회의 실제 HTTP 동작, DB 해시 또는 정리가 예상과 다르면 0이 아닌 종료 코드를 반환한다.

팀 API 작업 수신부터 결과 제출까지의 실제 검증은 열린 상태다. 테스트 API·허용 파일 origin과 서비스 자격 증명, 작업·시도 자료, 네트워크·메모리·CPU·PID를 실제로 제한하고 종료를 확인할 수 있는 분석 실행 환경이 필요하다.
