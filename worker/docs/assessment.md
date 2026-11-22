# 통합 정적 보안 검사

#14의 `assess`는 #7의 10개 검사 범주를 기존 정적 검사와 확장 검사로 함께 수행한다. 워커 패키지·엔진은 `0.3.0`, 통합 결과 계약은 `assessmentVersion: 1.0.0`이다. 결과 안의 `base`는 검증 이력을 보존한 정적 계약 `2.0.0`이다. 실제 팀 API는 포함하지 않는다.

[실행한 검사·코드 리뷰·해시 확인 기록](assessment-validation.md)을 함께 확인한다.

## 검사 순서와 지원 범위

1. 원본 바이트 해시와 크기를 확인하고 고정 이미지의 컨테이너로 전달한다. 원본·외부 근거는 stdin만 사용하며 호스트 디렉터리를 마운트하지 않는다.
2. UTF-8, 중복 JSON 키, 깊이, 노드 ID·이름, 연결·분기와 버전을 검증한다. 외부 근거 JSON도 크기·중복·출처·대상 해시를 검사한다.
3. Gitleaks와 Presidio를 실제 실행하고 JavaScript는 Acorn, Python은 `ast.parse`로 읽는다. 업로드한 코드·표현식·워크플로는 실행하지 않는다.
4. 외부 입력의 신뢰도와 데이터 민감도를 별도로 추적한다. Set 매핑, 직접 참조, 지원 IF/Switch 분기, 제한된 Merge·Code 매핑을 해석한다. 관련 값과 모든 도달 경로를 보호하지 않는 조건을 방어로 인정하지 않는다.
5. 아래 10개 범주의 기본·확장 규칙을 실행한다. 제공된 하위 워크플로 정의는 별도 파일 결과로 검사한다.
6. 제공된 정책을 별도로 평가하고 정확한 입력 해시에 연결된 수정 안내를 만든다. 정책·승인·환경 자료는 제공된 선언/관측이며 워커가 인증한 사실이 아니다.
7. 마스킹한 위치·고정 근거 코드·검사 범위·오류를 strict 계약으로 검증한다. 실패·미지원·부분 분석을 경고 없음이나 안전으로 바꾸지 않는다.

| 범주           | 현재 구현                                                                                                    |
| -------------- | ------------------------------------------------------------------------------------------------------------ |
| 비밀정보       | 디코딩된 키·설정·메모·고정 데이터의 Gitleaks 후보, 참조값과 실제 문자열 구분, 원문 비출력                    |
| 개인정보       | validator 형식 검사와 실제 Presidio·spaCy의 영어 PERSON/LOCATION 및 지원 형식 후보                           |
| 요청 인증      | Webhook 인증 설정, 제공된 상위 인증·권한 근거와 실제 집행의 미확인 상태                                      |
| 외부 전송      | HTTP 본문·헤더·쿼리, Send Email/Gmail/Slack/Telegram의 지원 필드로 가는 값·민감도, 목적지/데이터 정책        |
| SSRF           | 고정 origin의 경로 조작과 전체 URL 제어 구분, 내부 주소 후보·동적 목적지, 제공된 DNS/redirect 통제 근거      |
| SQL            | Postgres/MySQL/Microsoft SQL의 지원 작업·바인딩, 문자열 삽입과 동적 식별자 구분, SQL AST 작업 분류           |
| 명령·위험 코드 | Execute Command, JavaScript/Python의 제한된 별칭·대입·외부 입력→실행/평가/요청 후보                          |
| 통신           | 평문 HTTP, URL 내 인증정보, 지원 HTTP 인증서 검증 옵션                                                       |
| 응답·로그      | 전체 입력·DB 결과·민감도 후보의 응답/메시지/console/Python 출력 전달                                         |
| 의존성과 권한  | 위험 노드 기능, 설치 패키지/실행 환경의 제공 근거, npm 버전과 제공 OSV snapshot 비교, AI 모델·도구·승인 경계 |

정확한 노드·버전·옵션·구문은 [값 흐름](value-flow.md), [확장 전송](extended-sinks.md), [SQL·코드](advanced-risks.md), [네이티브 검사](native-inspection.md), [환경·정책](assessment-evidence.md)에 있다. 10개 범주를 호출한다는 사실은 임의의 모든 노드·코드를 해석한다는 뜻이 아니다.

## 하위 워크플로와 외부 근거

Execute Workflow 1/1.1/1.2/1.3/1.4의 고정 database 참조에는 부모 파일 해시·호출 노드 키·참조값·자식 원본 해시가 일치하는 정의가 필요하다. `source: parameter`의 고정 JSON도 검사한다. URL·로컬 파일 경로·동적 표현식에서 정의를 가져오지 않는다. 최대 자식 8개, 깊이 3이며 순환·누락·불일치는 미확인이다.

자식의 위험은 자식 파일·해시·호출 위치에 연결한다. 부모 인자와 자식 반환값의 전체 의미는 아직 확정하지 않으며 `subworkflow_argument_and_return_flow_unresolved`로 남긴다. 부모 노드의 분류·정책·인증 선언을 이름이 같은 자식 노드로 복사하지 않는다. [n8n 고정 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ExecuteWorkflow/ExecuteWorkflow/ExecuteWorkflow.node.ts)를 기준으로 한다.

선택적 근거 파일은 실제 입력 해시에 연결된다. 출처/라이선스, 정책, 패키지·OSV 자료, 환경·인증·네트워크 선언, 민감도, AI 승인, 공개 검토, 합성 시험 영수증을 받을 수 있다. 자료가 없으면 실제 설치 버전·권한·허용 목적지·정상 동작을 추측하지 않는다. JSON의 `typeVersion`은 설치 npm 패키지 버전이 아니다. [근거 입력 계약과 SEC 사례 25개 대응표](assessment-evidence.md)를 참조한다.

## 실행과 자원 경계

Docker Linux 데몬과 Node.js 24가 필요하다. 의존성·모델 다운로드는 이미지를 준비할 때만 수행한다. 실행은 이미지 ID를 고정하고 다운로드를 금지한다.

```powershell
cd worker
npm ci
npm run build
docker build -f Dockerfile.assessment-runtime -t workflow-worker-assessment-runtime:0.3.0 .
docker build -f Dockerfile.assessment -t workflow-worker-assessment:0.3.0 .
$env:WORKER_DOCKER_PATH = (Get-Command docker).Source
$env:WORKER_ASSESSMENT_IMAGE = docker image inspect --format '{{.Id}}' workflow-worker-assessment:0.3.0
node dist/cli.js assess .\workflow.json
node dist/cli.js assess .\workflow.json .\evidence.json
```

Linux에서는 `WORKER_DOCKER_PATH="$(command -v docker)"`와 `WORKER_ASSESSMENT_IMAGE="$(docker image inspect --format '{{.Id}}' workflow-worker-assessment:0.3.0)"`를 export한다. 운영자는 신뢰하는 실행 파일·이미지를 지정해야 한다. 업로드 JSON은 이 설정을 바꿀 수 없다.

- 입력 workflow 256 KiB, 외부 근거 1 MiB, 깊이/노드/연결 한도는 기존 파서와 동일하다.
- 네트워크 없음, 읽기 전용 root, UID 65532, capability 없음, 권한 상승 금지, 메모리 1 GiB, PID 96, CPU 1, 임시 tmpfs 64 MiB를 강제한다.
- 검사 전체 180초, 결과/오류 출력 합계 2 MiB, 네이티브 도구별 추가 한도가 있다.
- 컨테이너 생성 확인 후 시작한다. 생성 중 취소는 생성 응답을 기다린 뒤 제거하고, 실행 중 취소는 프로세스와 해당 컨테이너를 모두 정리한다. 생성 응답이 10초 안에 끝나지 않아 정리를 확정할 수 없으면 `sandbox_cleanup_failed`로 실패한다. 데몬 장애 시 운영자가 해당 작업의 중단된 컨테이너를 확인해야 한다.
- 기존 `scan`과 단위검사용 `assessBytes`는 이 OS 격리 보장을 제공하지 않는다. 기본 통합 CLI `assess`가 격리 경로다.

## 변화 비교와 수정

```powershell
node dist/cli.js diff-definitions .\before.json .\after.json
node dist/cli.js compare-static .\before-base-report.json .\after-base-report.json
node dist/cli.js apply-remediation .\workflow.json .\assessment.json PLAN_ID .\revised.json
```

`diff-definitions`는 인증·목적지·수신자·DB 작업·도구·연결·환경/정책/패키지의 지원 의미 변화를 원문 없이 반환한다. 선택적으로 전후 근거 파일 두 개를 추가한다. 이 로컬 비교 도구는 워크플로를 실행하지 않으며 Docker 격리 완료를 주장하지 않는다. 규칙 버전/범위와 finding 변화는 기존 `compare-static`으로 별도 비교한다.

수정 계획은 기본적으로 설명과 전제조건이다. 자동 적용은 지원 HTTP의 TLS 검증 활성화와 매우 좁은 Postgres 2.8 조회 바인딩만 허용한다. 사용자가 위 명령을 명시적으로 호출하면 해시와 구조를 다시 확인해 **새 파일**을 만들고 격리 검사한다. 기존 파일은 덮어쓰지 않으며 기존 정책/승인을 새 해시로 옮기지 않는다. SQL·URL·비밀값을 수정 계획에 복사하지 않는다. [정확한 조건](assessment-change.md)

`allow`도 서비스 승인·공개 권한이 아니다. `analyzed`, CLI 종료 코드 0, 탐지 0개도 안전을 뜻하지 않는다. 정상 업무 보존은 따로 실행한 합성 검증의 범위에서만 말할 수 있다.

## 검증과 남는 외부 조건

```text
npm run verify
node validation/verify-assessment-runtime.mjs
```

Docker 검증은 실제 도구, 5개 합성 assessment와 자식 파일, 수정 전후 재검사, 잘못된 근거 해시, 취소/시간 제한·정리, 9개 격리 조건을 확인한다. [실행 결과](../validation/assessment-runtime-results.json), [실제 NLP/AST 검사](../validation/native-inspection-results.json), [생성 SQL 수정본의 합성 실행](../validation/remediation-behavior-results.json)을 구분해서 읽는다. 기존 12개 SQL·27개 범주 코퍼스·공개 파일 5개 검증 기록은 별도로 보존한다.

실제 팀 API의 작업 수신·파일 저장·결과 제출·권한·화면 연결, 실제 환경의 패키지/권한/네트워크 수집, 제공 정책의 인증·승인 집행, 공개/다운로드 대상 바이트 검증은 해당 서비스와 환경에서 확인해야 한다. 임의 코드·복잡한 Merge·동적 자식 호출·한국어 전체 NER·AI 동적 공격 저항성·실제 비밀키 유효성은 이 정적 지원 프로파일이 보증하지 않는다.
