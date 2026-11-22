# #7을 기준으로 한 워커 완료 범위

기준은 [머지된 설계 PR #7](https://github.com/serendipity-sec/workflow-hub/pull/7)과 [최신 #14 결정](https://github.com/serendipity-sec/workflow-hub/issues/14)이다. 설계 당시의 1~2개 초기 경로보다 사용자가 확대한 **10개 검사 항목**을 우선한다. 구현 위치는 `worker/`, 작업 브랜치는 `feat/14-integrate-security-worker`이며 실제 팀 API는 서비스 구현 후 #18에서 맞춘다.

여기서 완료는 **명시한 정적 지원 범위에서 입력→검사→근거/한계→수정 안내→재검사→전체 결과 비교가 연결되고 검증되는 것**이다. 임의 n8n 노드·코드의 완전 분석, 모든 위험의 자동 수정, 운영 환경의 안전 보증을 뜻하지 않는다. 부분 분석을 안전으로 바꾸거나 미지원 수를 줄이기 위해 검사를 생략하지 않는다.

## 10개 검사와 구현 근거

| #   | 검사                    | 구현과 검증의 연결                                                                                                                                       |
| --- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | 비밀정보                | Gitleaks 8.30.1 실제 실행, 필드 위치·참조/예시·마스킹. `static-content`, `verify-static-tools`                                                           |
| 2   | 개인정보                | validator 형식 검사, Presidio/spaCy 실제 영어 NER. 구조 메타데이터와 실행 코드의 NER 제외를 명시하고 메모·고정 데이터의 후보를 보존. `native-inspection` |
| 3   | 요청자 검증             | Webhook 인증 설정, 입력값·IF/Switch 분기·우회·직접 참조의 지원 흐름. 실제 인증 집행은 미확인. `static-settings`, `static-flow`, `value-flow`             |
| 4   | 외부 전송               | HTTP·메일·메신저와 Notion/Docs/WhatsApp/Gemini의 지원 필드·목적지·데이터 분류. 업무상 허용 여부는 별도 정책. `extended-sinks`                            |
| 5   | SSRF                    | 고정 origin의 경로와 목적지 전체 조작 구분, 입력과 호스트 제한 관계. DNS·리다이렉트·네트워크 도달성은 미확인. `static-flow`                              |
| 6   | SQL 주입                | 지원 PG/MySQL/MSSQL 작업·SQL AST·문자열 삽입·바인딩. PG 문자열형 replacement의 동적 분할은 정확한 매핑 미확인. `advanced-risks`, `static-flow`           |
| 7   | 명령·위험 코드          | 고정 명령 기능과 입력 결합 구분, JS Acorn/Python AST의 제한된 경로. 원본 프로그램 실행 금지. `advanced-risks`, `native-inspection`                       |
| 8   | 통신 설정               | HTTP·URL 인증정보·TLS 검증 비활성 설정. TLS 자동 수정은 선언한 프로파일에 한정. `static-settings`, `assessment-change`                                   |
| 9   | 응답·로그 노출          | 입력·DB 결과·개인정보 후보의 출력 필드 흐름과 일부 고정 Code 출력 구분. `extended-sinks`, `value-flow`, `native-inspection`                              |
| 10  | 의존성·고권한·하위 노드 | SSH/파일/패키지/AI 기능, 해시가 맞는 자식 정의 검사, 제공 OSV·환경·승인 근거의 한계. `assessment-subworkflows`, `assessment-environment`                 |

정확한 노드·버전·옵션·표현식은 [통합 지원 문서](assessment.md)의 항목별 문서를 따른다. 관련 없는 IF, 직접 원본 참조, 기능 삭제·비활성화, 도구 실패, 규칙·분석 범위 감소의 부정 사례를 유지한다. [25개 SEC 사례의 워커/서비스 경계](assessment-evidence.md#유한한-완료-판정표)도 별도 기준이다.

## 두 서비스 흐름에서 워커가 제공하는 결과

1. **기존 템플릿 검사:** 정확한 원본 해시, 구조화된 기능 범주·연결, 10개 검사 결과, 위치·근거·범위·오류를 제공한다. `functionSummary`는 구조와 기능 범주이며 업무 목적을 자동으로 검증한 설명은 아니다. 서비스는 원본 위치와 고정 코드를 이용해 사람이 이해하는 설명을 표시한다.
2. **사용자 수정본 검사:** 새 바이트를 다시 검사하고 `compare-assessment`로 기본·확장 검사와 자식 파일의 변화를 비교한다. `diff-definitions`는 인증·목적지·수신자·작업·연결의 변경을 보완한다. 경고 소실만으로 해결이나 정상 업무 보존을 선언하지 않는다.
3. **수정본 생성:** #7의 기본은 수정 안내와 수동 수정 후 재검사다. 추가 구현한 자동 수정은 TLS 검증 활성화와 좁은 PG 2.8 조회 바인딩 두 종류다. 그 외 수정은 수동 검토가 필요하다. 생성된 파일은 새 경로에만 저장하며 원본·과거 승인을 덮어쓰지 않는다.

`findingPresentation.observations`는 정보성 사실이고 `reviewCandidates`는 검토 후보다. 두 배열의 크기는 실제 취약점 수가 아니다. 정보성 사실에서 불필요한 수정 계획을 생성하지 않는다.

## 별도 완료로 남는 조건

- 서비스가 실제로 구현한 작업 수신·파일/버전·결과 API에 맞춘 연결, 사용자 권한·불변 저장·공개·다운로드 바이트 일치 검증.
- 실제 설치 패키지·OAuth/DB/SSH 권한·네트워크 정보의 인증된 수집과 집행. 제공 선언을 실제 관측으로 승격하지 않는다.
- 임의 JS/Python·복잡한 병합·자식 인자와 반환값·동적 호출의 정밀 분석, 한국어 전체 개인정보 인식, AI 공격 저항성, 실제 키 유효성 확인.
- 새로운 자동 수정 패턴마다 위험 조건과 정상 기능을 확인하는 별도 합성 실행 증거. 공개 원본과 사용자 파일은 실행하지 않는다.

이 조건들은 API가 연결됐다는 사실만으로 충족되지 않는다. 워커 코드의 검증, 실제 공개 JSON의 호환성, 합성 실행의 기능 보존, 운영 서비스 연동은 각각 다른 증거로 기록한다.

## 0.4.0 검증 결과 — 2026-11-22

| 검증                  | 실제 결과와 근거                                                                                                                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 필수 코드 검사        | Node 24.14.0의 format/lint/typecheck/build, 단위·회귀 **261/261**, 루트 도구 **6/6**                                                                                                                  |
| 기존 정적 코퍼스      | **27/27**. 정답 분모 23개에서 TP 13/TN 10/FP 0/FN 0, 나머지 4개는 실패·미지원 상태 검증. 일반 정확도 수치가 아님                                                                                      |
| 실제 도구·격리        | Gitleaks 대조 7개, 통합 합성 assessment 5개/파일 6개, 격리 조건 9개, 실패·취소·정리 4개. [고정 이미지와 검증 요약](../validation/worker-completion-0.4.0-results.json)                                |
| 실제 개인정보 모델    | **18개 합성 대조 통과**. Docker Python 3.11.2, Presidio 2.2.366, spaCy 3.8.18, 영어 모델 3.8.0. [모델 실측](../validation/native-profile-0.4.0-results.json)                                          |
| 같은 공개 원본 15개   | 이전 14 partial/1 error → **15 partial/0 error**, 도구 실행 **45회/오류 0**. 자동 수정 대상은 여전히 0개. [원본별 결과](../validation/public-assessment-0.4.0-results.json)                           |
| 공개 원본 수정·재검사 | 인증 설정·수신자 변경·전송 비활성화 **3개 통과**, base와 확장 전체 관찰 수를 비교하고 원본 해시 유지. 기능 보존/인증 집행은 미검증. [비교 결과](../validation/public-service-path-0.4.0-results.json) |
| 알려진 공개 사례 대조 | 입력 호환성·SQL 경로/바인딩·고정 명령·전송 필드·NER 메타데이터·관찰/수정 계획 분리 **20개 확인**. [대조 결과와 남은 한계](../validation/public-regressions-0.4.0-results.json)                        |

공개 원본은 실행하지 않았다. 원본과 API 응답, 상세 보고서는 로컬에 보존하고 저장소에는 출처·해시·마스킹된 집계만 기록했다. 이전 0.3.0 실측 파일과 기존 합성 n8n/Postgres 실행 증거도 덮어쓰지 않았다. 자동 SQL 수정의 합성 원본·수정본 바이트는 이전 실행 검증과 동일함을 확인했으며, 이번 변경에서 n8n 업무 실행 시험을 새로 했다고 주장하지 않는다.

전체 Codex 리뷰와 독립 Astra 6 max 검토에서 날짜 포맷의 민감 리터럴, SQL 인용/주석 보존, 상위 부분 분석 범위, Code 객체 필드명 민감도 네 결함을 찾아 수정했다. Astra 후속 합성 재현 13개와 Codex 후속 검사 79개가 통과했다. 캐시된 런타임의 이전 lockfile 해시도 검증기가 거부하여 현재 lockfile로 재빌드한 뒤 측정했다.

**남은 정밀도 한계:** 공개 15403의 Code27은 상수·날짜 출력을 정확히 분리하지만, 실제 Gmail 제목에는 미지원 Code14와 IF 2.3 경로도 합류한다. 제목은 실제 원문상 상수·날짜인데도 개인정보 전송 **후보가 남는다**. 이 경고와 범위는 `candidate/partial`이며 확정 유출로 표시하면 안 된다. 초기 대조기의 “Gmail 제목 경고가 없어야 한다”는 기대는 한 분기의 지원을 전체 경로로 확대해 해석한 것이어서, 지원 분기와 미지원 합류·잔여 후보를 각각 확인하도록 정정했다. 검사 엔진이나 기존 테스트를 약화해 경고를 지우지 않았다.

또한 영어 모델은 두 글자 이름을 문맥에 따라 놓친다. 메타데이터 오탐 감소와 합성 양성 보존은 확인했지만 전체 개인정보 탐지율은 검증하지 않았다. 15개 모두 `partial`인 결과는 삭제하지 않은 미지원 경로·실제 값/권한·환경/정책 미확인 조건을 포함한다. “입력 오류 0”을 “전체 안전”으로 해석하지 않는다.

재현 시 [실행 문서](assessment.md)대로 이미지를 빌드하고 고정 image ID를 지정한다. 과거 기록을 보존하려면 다음과 같이 새 경로를 사용한다(`worker/`, PowerShell).

```powershell
$env:WORKER_ASSESSMENT_VALIDATION_OUTPUT = 'evidence-local/runtime-0.4.0.json'
node validation/verify-assessment-runtime.mjs
$env:WORKER_ASSESSMENT_RUNTIME_RECEIPT = $env:WORKER_ASSESSMENT_VALIDATION_OUTPUT
node validation/verify-native-profile.mjs evidence-local/native-profile-0.4.0.json
node validation/verify-public-assessment.mjs FROZEN_INPUT_DIRECTORY evidence-local/public-0.4.0.json
$env:WORKER_PUBLIC_ASSESSMENT_RECEIPT = 'evidence-local/public-0.4.0.json'
node validation/verify-public-service-paths.mjs FROZEN_INPUT_DIRECTORY evidence-local/recheck-0.4.0.json
node validation/verify-public-regressions.mjs FROZEN_INPUT_DIRECTORY evidence-local/regressions-0.4.0.json
```

공개 입력 디렉터리는 [이전 수집 설명](public-service-validation.md)의 `downloads.json`과 정확한 원본 바이트를 사용한다. 새로 다운로드한 템플릿이 변경됐다면 기존 정답·해시와 동일한 시험으로 취급하지 않는다. CI는 고정 합성 검사와 실제 도구/격리를 실행하며, 로컬 공개 원본 15개를 업로드하거나 CI에서 재검사하지 않는다.
