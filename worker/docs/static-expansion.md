# Code·커넥터·AI 정적 흐름 확장 — 0.6.0

2026-11-23, [#14](https://github.com/serendipity-sec/workflow-hub/issues/14)의 기존 `feat/14-integrate-security-worker` 브랜치에서 확장했다. 같은 공개 JSON 15개의 정의와 [#7의 보안 설계](../../docs/SECURITY_DESIGN.md)를 기준으로 실제 API 없이 해석할 수 있는 프로파일을 추가했다. 워크플로·Code·표현식·모델·외부 서비스는 실행하지 않는다.

## 추가한 검사

| 영역        | 새로 해석하는 내용                                                                                         | 유지하는 경계                                                                                                     |
| ----------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Code/표현식 | 지역 let·대입·분기, 소유한 객체의 고정 필드, 일부 순수 helper, 유한 map/for-of/push 요약, 문자열/JSON 변환 | 알 수 없는 호출·변경·반복 효과는 출처와 민감 후보를 포함한 부분 분석. 무한 프로그램이나 실행 결과를 증명하지 않음 |
| 커넥터      | Airtable record 작업, Sheets sheet 작업, Gmail·Notion·Docs 읽기 요청, 구조화된 활성 전송 필드              | 원격 데이터·표 헤더·빈 시트 fallback·권한·실제 수신자·바이너리는 미확인                                           |
| 응답/메시지 | Webhook 헤더·JWT·리다이렉트·바이너리, Slack 옵션·ephemeral 수신처                                          | 인증·토큰 유효성·실제 권한과 실행 순서를 검증하지 않음                                                            |
| SQL         | Code/Set의 정확한 문자열 상수로 정의된 쿼리 AST, 전체 동적 쿼리의 별도 후보, 생성형 Postgres Tool          | 동적 SQL 구조는 미확인. 고정 SQL 문자열 내부를 다시 n8n 표현식으로 해석하지 않음                                  |
| 파일·SSH    | 활성 로컬 read/write 경로, SSH cwd·upload/download 경로의 입력 영향                                        | 파일·호스트에 접근하지 않음. 실제 OS/SSH 권한·경로 제한·내용은 미확인                                             |
| AI          | 모델·도구·메모리·검색·파서의 등록 버전/포트/방향, 프롬프트·문맥의 모델 전송 후보, 도구 인자·승인 선언      | 실제 도구 선택·호출·모델 출력·메모리 내용·승인 집행은 미확인. 형식 스키마를 검증·권한 근거로 승격하지 않음        |
| Code Tool   | JavaScript query의 호출 인자와 Python _query의 AST 입력 출처                                               | 모델이 호출한 사실·입력 값·런타임 가용성은 미확인                                                                 |

세부 지원 버전·작업·옵션·문법은 [값 흐름](value-flow.md), [전송·응답](extended-sinks.md), [AI 정적 계약](ai-flow.md), [파일·DB·목적지](definition-risks.md), [SQL/코드](advanced-risks.md), [Python AST](native-inspection.md)를 따른다. Acorn·node-sql-parser·Gitleaks·Presidio/spaCy는 기존 고정 버전을 재사용했다. AI 연결 검사는 워커의 정적 규칙이며 외부 AI API나 LLM을 호출하는 검사가 아니다.

## 해석 결과의 의미

같은 전송 값에 개인정보·비밀 후보·미확인 성분이 함께 있으면 모든 분류를 정책 평가에 보존한다. 원격 서비스에서 읽은 결과는 원래 입력의 단순 복사가 아니며, 외부 출처와 미확인 구조를 별도로 남긴다. Sheets의 수동 append도 원격 시트가 비었을 때 전체 입력으로 바뀔 수 있으므로 수동 매핑만 보고 나머지 민감값이 전송되지 않는다고 단정하지 않는다.

Code의 내부 scalar `constant`는 정확한 정의에서만 얻는 분석 메타데이터다. 운영자가 public으로 분류했다는 이유로 값 상수를 만들지 않는다. 실제 날짜·외부 응답·모델 출력에 상수를 붙이지 않으며 보고서에 원문 상수를 복사하지 않는다. SQL·목적지의 정적 정의를 파악할 때만 이 내부 값을 사용한다.

객체 property 변경·push가 있는 Code는 관측한 RHS·환경·출처의 민감도 요약은 유지하지만, 별칭을 통한 변경을 완전히 추론했다고 표현하지 않는다. 최종 반환의 필드 정밀도와 상수를 버리고 `code_object_mutation_unresolved`를 남긴다. 바깥 지역 변수를 읽는 helper도 미확인 효과로 처리한다. 순수 매개변수 기반 helper와 기존 불변 const 프로파일은 별도로 유지한다. 이 보수 처리는 일부 독립적인 공개 필드까지 후보로 남길 수 있으며, 새로 경고가 사라지거나 분석 범위가 개선된 것으로 계산하지 않는다.

공개 7622·7643에는 모델/파서 연결이 공식 공급 방향과 반대로 저장된 경우가 있다. 원본을 뒤집거나 임의로 고치지 않고 연결 미확인과 필수 연결 누락을 기록한다. `partial`은 이런 정의·정적 지원 한계와 외부 근거 부재를 포함한다. 새 검사 때문에 새로운 후보·한계가 추가될 수 있으며, 진단 수 감소만으로 수정이나 정밀도 향상을 판단하지 않는다.

## 리뷰와 검증

Code·커넥터·AI를 나눠 구현하고, 구현자가 아닌 담당자가 교차 리뷰했다. 전체 Codex 리뷰와 지적 사항의 해결 리뷰도 별도로 수행했으며 최종 미해결 지적은 없었다. 중첩 별칭·함수의 바깥 변수·반복 누적·잘린 배열·동적 쓰기·예외·미지원 구문의 민감도 손실, 추상값/상수의 메모리 증가, 템플릿 문자열의 순서, Code Tool 모델 입력의 출처 누락을 재현하고 회귀로 검증했다. 주석·문자열·동명 바인딩·일반 속성을 실제 입력 출처로 오인하지 않는 음성도 포함한다. 처리할 수 없는 효과를 표현할 때도 이미 관측한 민감 분류·출처와 미확인을 함께 유지해야 한다.

현재 엔진은 기본 10개 범주와 확장 18개 규칙을 모두 요구한다. 과거 0.3–0.5 엔진의 13개 확장 규칙은 역사적 보고서로 읽고, 새 버전에서 규칙이 누락되면 거부한다. 다른 엔진의 경고 소실을 수정 성공으로 비교하지 않는다. 원본별 기능·수정 안내·재검사·전체 결과 비교와 0.3/0.4/0.5 실측은 보존한다.

실측 원본·이미지·도구·스크립트·산출물 해시는 [0.6.0 실행 요약](../validation/static-expansion-0.6.0-results.json)에 연결한다. 워커 전체 검사 410개, 루트 도구 검사 6개가 통과했다. 버전별 고정 코퍼스와 실제 도구 결과는 아래처럼 각각 기록한다. 합성 반례의 성공률을 일반 워크플로 정확도로 환산하지 않는다.

| 검증             | 범위와 결과                                                                                                                                          |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 고정 합성 코퍼스 | 규칙 단위·통제한 Gitleaks fixture로 27개 기대 결과 통과. 사실 판정 23개 중 TP 13·TN 10·FP 0·FN 0이며, 오류/미지원/부분 분석 상태 4개도 기대대로 확인 |
| 기존 SQL 계약    | 기존 엔진 0.1.2의 12개 사례 재검증. 미지원 4개를 정상 판정으로 바꾸지 않음                                                                           |
| 격리 Docker      | 8개 assessment·9개 파일, 격리 조건 9개·실패 조건 4개, 실행 중 취소와 컨테이너 정리 확인                                                              |
| 네이티브 검사    | 실제 Presidio/spaCy·Python AST의 44개 기능 조건 확인. Gitleaks도 통합 검사에서 실제 실행                                                             |
| 공개 원본        | 같은 n8n JSON 15개, 도구 실행 45회·도구 오류 0회·입력 거부 0개. 15개 모두 남은 범위가 있어 `partial`                                                 |
| 공개 회귀        | 원본 15개의 고정 정의에 대한 54개 조건 통과                                                                                                          |
| 수정·재검사·비교 | 통제한 수정 3개 통과, 원본 바이트 보존. 원본/수정본의 실제 업무 동작은 실행하지 않아 미확인                                                          |

이 결과는 [합성 코퍼스](../validation/static-corpus-0.6.0-results.json), [네이티브 프로파일](../validation/native-profile-0.6.0-results.json), [공개 검사](../validation/public-assessment-0.6.0-results.json), [공개 회귀](../validation/public-regressions-0.6.0-results.json), [수정·재검사](../validation/public-service-path-0.6.0-results.json)로 나누어 보존한다. 0.3/0.4/0.5 원본과 보고서는 덮어쓰지 않는다.

## 공개 15개의 이전 결과와 달라진 점

[같은 바이트의 0.5.0→0.6.0 비교](../validation/public-coverage-0.6.0-results.json)는 노드 기능을 읽는 범위와 남은 의미 해석 한계를 분리한다. 아래 수는 여러 규칙에 중복해서 기록된 진단 발생 횟수이며 독립 위험·취약점 개수가 아니다.

| 진단                           | 0.5.0 | 0.6.0 | 의미                                                                                            |
| ------------------------------ | ----: | ----: | ----------------------------------------------------------------------------------------------- |
| 기본 노드 기능 프로파일 미검토 |    71 |     0 | 고정된 공식 버전의 기능 목록을 추가함. 각 작업·실행 결과의 전체 분석 완료 수치가 아님           |
| 일반 AI 노드 의미 미검토       |    21 |     2 | 알려진 클러스터 정의를 전용 AI 규칙으로 분리. 주 실행 노드의 별도 전송 프로파일과 혼동하지 않음 |
| 비 main 연결 의미 미검토       |     9 |     2 | 지원 typed edge는 해석하고, 원본의 역방향 모델·파서 연결은 미확인으로 유지                      |
| 일반 Code 매핑 미지원          |    19 |     0 | 구체적인 호출·분기·예외·변경·한도 진단으로 바뀐 경우를 포함. 모든 Code를 해석했다는 뜻이 아님   |
| SQL 파서 미지원                |     4 |     0 | 전체 동적 쿼리는 정적 SQL 문자열처럼 파싱하지 않고 별도 구조 미확인 4건으로 기록                |
| 불투명 노드 효과               |   512 |   512 | 정의만으로 반환 구조와 외부 효과를 알 수 없는 범위가 계속 존재                                  |
| 전체 값 흐름 요청 한도         |     3 |     3 | 복잡한 20459의 유한 예산 경계 유지                                                              |

따라서 `partial` 해소율이나 전체 정확도 향상률을 계산하지 않는다. 의미를 해석하지 못해 더 일찍 중단한 경우, 일반 진단을 구체적인 진단으로 옮긴 경우, 새 규칙에서 새 한계를 관찰한 경우를 분석 범위 개선과 구분한다.

특히 7622·7643의 연결 방향과 누락된 모델/파서, 18521의 실제 시트 헤더·빈 시트 fallback, 10111의 실제 DB 스키마·권한, 20459의 동적 SQL·분석 예산, 11007의 바이너리·파일 권한·파싱 불가 코드, 10476의 SSH 권한이 남는다. 모든 원본에는 런타임/정책 근거와 영문 NLP의 지원 한계도 남는다. API 연결만으로 이 항목들이 확인되는 것은 아니다.

## 재현

Node.js 24에서 `npm ci`, `npm run verify`, `npm run build` 후 [통합 검사 문서](assessment.md#실행과-자원-경계)의 0.6.0 이미지 빌드·고정 설정을 적용한다.

```powershell
node validation/verify-static-corpus.mjs evidence-local/static-corpus-0.6.0.json
node validation/verify-legacy-current.mjs evidence-local/legacy-0.6.0.json
$env:WORKER_ASSESSMENT_VALIDATION_OUTPUT = 'evidence-local/runtime-0.6.0.json'
node validation/verify-assessment-runtime.mjs
node validation/verify-native-profile.mjs evidence-local/native-0.6.0.json
```

공개 입력은 [다운로드 절차](public-service-validation.md)에서 정한 manifest·원본 해시를 사용한다. 새 버전용 별도 디렉터리에 `downloads.json`과 같은 원본 JSON 15개를 복사한 뒤 실행한다. 아래 경로는 로컬 보관 위치에 맞게 바꾼다. 추적된 과거 결과 경로에 덮어쓰지 않는다.

```powershell
$env:WORKER_ASSESSMENT_RUNTIME_RECEIPT = 'evidence-local/runtime-0.6.0.json'
node validation/verify-public-assessment.mjs FROZEN_V060 evidence-local/public-0.6.0.json
$env:WORKER_PUBLIC_ASSESSMENT_RECEIPT = 'evidence-local/public-0.6.0.json'
node validation/verify-public-service-paths.mjs FROZEN_V060 evidence-local/service-0.6.0.json
node validation/verify-public-regressions.mjs FROZEN_V060 evidence-local/regressions-0.6.0.json
node validation/audit-public-coverage.mjs FROZEN_V050 FROZEN_V060 evidence-local/coverage-0.6.0.json
```

## API 및 별도 근거가 필요한 부분

실제 작업·파일·결과 API는 서비스 구현 후 #18에서 맞춘다. 별도로 실제 권한·설치 패키지·네트워크·업무 정책·실행 데이터·첨부 내용이 필요하다. 이 자료는 API 연결 자체로 생기지 않는다. 모델의 실제 출력·도구 선택·공격 저항성, 라이브러리 내부·동적 import·리플렉션·일반 반복/재귀의 전체 효과는 정적 JSON 정의만으로 보장하지 않는다.

추가 정적 프로파일은 지원을 명시한 구문과 노드에 적용한다. 공개 원본이나 사용자 파일의 실행·업무 기능 보존·운영 안전성 전체 완료로 표현하지 않는다.
