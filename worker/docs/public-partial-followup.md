# 공개 원본 15개의 partial 원인과 0.5.0 보완

2026-11-23, [#14](https://github.com/serendipity-sec/workflow-hub/issues/14)의 기존 `feat/14-integrate-security-worker` 브랜치에서 검증했다. [#7의 설계](../../docs/SECURITY_DESIGN.md)를 기준으로 워커만 보완했으며 실제 팀 API는 연결하지 않았다. 0.3.0·0.4.0 기록과 공개 원본은 보존했다.

## 왜 15개가 모두 partial인가

`partial`은 보고서에 **분석하지 못했거나 추가 근거가 필요한 범위가 있다**는 뜻이다. 하나라도 해당 범위가 있으면 전체 보고서가 partial이 된다. 일부 규칙의 unsupported도 전체 보고서에 포함된다. 검사 실행 실패나 확정 위험 개수와는 다르다.

15개 모두에 다음 조건이 공통으로 있다.

- **실제 환경 근거 없음:** `runtime_evidence_missing`. JSON만으로는 설치 패키지, 실제 권한, 네트워크 집행을 확인할 수 없다. 여기에 업무상 허용 목적지·민감정보 정책도 제공되지 않았다. 팀 API를 연결하는 것과 이 근거를 실제로 수집·확인하는 것은 별도다.
- **명시한 개인정보 모델 범위:** `nlp_english_model_profile`, 메타데이터의 형식 검사와 표현식 밖 문자만 검사한 범위. 영어 모델은 한국어 전체 개인정보나 모든 문맥의 이름을 보장하지 않는다.
- **남은 정적 해석 범위:** 커넥터별 실제 변환 효과, 복잡한 Code, AI 연결·도구 호출 등이 있다. 미지원 노드를 단순 통과 노드로 취급하면 입력의 출처·민감도·검증 조건을 잘못 이어 붙일 수 있다.

따라서 아래 보완 후에도 **15 partial / 0 error**가 맞는 결과다. 이를 `analyzed`나 안전으로 강제 변경하지 않았다. [원인별 전후 집계](../validation/public-coverage-0.5.0-results.json)는 같은 입력 해시와 원본 보고서 해시를 연결한다.

## 실제로 보완한 부분

| 진단                                    | 0.4.0 | 0.5.0 | 의미                                                          |
| --------------------------------------- | ----: | ----: | ------------------------------------------------------------- |
| `unsupported_node_version`              |    26 |     0 | 이 15개에서 만난 검토 대상 버전의 프로파일 추가               |
| `builtin_capability_profile_unreviewed` |   178 |    71 | StickyNote·기본 트리거와 검토된 노드의 기능 목록 정리         |
| `expression_parse_unavailable`          |    15 |     0 | Code 표현식을 n8n 템플릿으로 감싸던 파싱 오류 제거            |
| `expression_syntax_unsupported`         |    19 |     1 | optional chaining·고정 인덱스·기본값 표현식 지원              |
| `flow_budget_exceeded`                  |     9 |     3 | 동일 출력의 반복 해석을 줄임. 20459의 복잡한 경로 제한은 유지 |
| `native_field_size_limit`               |     1 |     0 | 3314의 장문을 예산 안에서 나눠 검사하고 범위 표시             |
| `opaque_node_effects`                   |   536 |   512 | 근거를 확인한 통과·주석 노드에 한해 불투명 처리 해소          |
| `code_mapping_unsupported`              |    20 |    19 | Code14의 독립된 고정 제목 필드를 해석                         |
| `node_transform_unsupported`            |    55 |    50 | 검토한 IF·Filter·Switch 버전의 제한된 흐름 추가               |

수치는 여러 규칙에서 같은 노드를 언급할 수 있는 **진단 발생 횟수**다. 독립 취약점 수, 해결한 위험 수, 일반 정확도나 전체 n8n 지원율이 아니다.

공개 **15403**에서는 Code14/27과 IF 2.3을 거치는 고정 제목의 전파를 보완했다. Gmail 제목과 Google Docs 생성 제목은 개인정보 전송 후보에서 제외됐고, 실제 본문의 개인정보 가능성과 수신자·정책 미확인은 유지된다. 제목 경고가 사라졌다는 이유로 본문 전송까지 안전하다고 판단하지 않는다.

EmailSend v1의 text/html·CC/BCC, Telegram 1.2의 sendDocument를 해석한다. 첨부파일의 실제 바이트가 JSON에 없으면 `binary_payload_unavailable`을 남긴다. 프로그램 문법과 일반 본문을 구분해 명령·IF 연산자·Set 대상 필드명·IMAP 검색 문법의 인명 오탐을 줄이되, 그 안의 이메일 등 형식 후보는 유지하고 실행 결과가 아니라는 근거를 붙인다. 장문은 16,384자 구간·256자 중첩으로 검사하며 총예산은 늘리지 않았다.

지원 범위는 [필드 흐름](value-flow.md), [기본 흐름](flow-profiles.md), [설정 프로파일](settings-profiles.md), [확장 전송](extended-sinks.md), [고급 코드 분석](advanced-risks.md), [실제 NLP/AST 도구](native-inspection.md)에 정의했다. n8n 원본 동작을 확인한 고정 커밋·공식 소스 링크도 각 문서에 있다.

## 원본별 남은 범위

아래 수는 해당 보고서의 규칙별 coverage 행이다. `partial`과 `unsupported`를 따로 세었으며, 노드 수나 위험 수가 아니다. 모든 행에는 위의 환경·정책·영어 모델 공통 한계가 추가된다.

| 공개 템플릿 ID | partial 전→후 | unsupported 전→후 | 추가로 남는 대표 범위                             |
| -------------- | ------------: | ----------------: | ------------------------------------------------- |
| 16081          |         18→17 |              17→6 | PG 문자열 파라미터의 실행 값별 매핑, 응답 권한    |
| 20541          |         44→41 |             43→35 | 복잡한 Code·객체 필드, 동적 목적지·응답 권한      |
| 20459          |         36→33 |             46→23 | Code/SQL 일부 문법과 흐름 예산 3건                |
| 14034          |           8→6 |             17→12 | Code 출력·실제 전송 데이터 분류                   |
| 2490           |         17→17 |             36→31 | 커넥터 변환·응답 데이터와 요청자 권한             |
| 7643           |         15→15 |             33→33 | AI 및 비-main 연결, 읽기 결과·수신자              |
| 18521          |         28→30 |             64→57 | AI/Code와 동적 필드, 문서 접근 권한               |
| 15403          |         39→31 |             88→69 | 나머지 Code·본문·AI 처리/보관·문서 권한           |
| 10111          |         33→31 |             79→52 | 일부 DB 작업·SQL 흐름, AI/Code                    |
| 10476          |         36→36 |           113→106 | Python/Code·Merge, 미확인 메시지 키보드 변환·옵션 |
| 6216           |         13→13 |             38→34 | Code 출력·명령의 실제 입력 출처                   |
| 3314           |         35→32 |             60→53 | Code/AI·동적 목적지, 장문 분할의 문맥 한계        |
| 11007          |         33→31 |            108→88 | 첨부 바이너리 부재, 일부 코드 구문·명령 출처      |
| 9638           |         23→24 |             47→38 | AI/Code·읽기 결과·동적 필드                       |
| 7622           |         14→14 |             32→28 | AI/비-main 연결·커넥터 변환·수신자                |

일부 partial 행이 증가한 것은 이전 unsupported를 더 분석하거나 기존에 숨겨졌던 한계를 명시했기 때문이다. 예를 들어 기본값/논리식 뒤의 필드 접근에서 출처는 보존하지만 구조를 확정할 수 없는 경우 `field_projection_partial`을 새로 남긴다(29건). 값을 public으로 낮추거나 원래 민감도·출처를 버리지 않는다.

## 리뷰에서 함께 고친 누락 위험

- 객체·스칼라의 `||`/`??` 뒤 필드 접근에서 개인정보·비밀값 출처를 잃던 문제를 고쳤다. 파싱 실패·지원 밖 문법에서도 원래 민감도와 한계를 유지한다.
- JS 고정 문자열에 n8n 구분자가 들어 있다는 이유로 실행 표현식으로 해석하던 오탐을 고쳤다. 실제 동적 eval/명령 입력 후보는 유지한다.
- Telegram의 선택적 키보드 생략을 필수 입력 누락으로 잡던 오탐을 고쳤다. 버튼 내부의 문구·콜백·웹앱 URL 표현식도 개별 추적하며, 임의 필드명은 결과에 노출하지 않는다. 구조나 처리 한계를 넘으면 데이터 등급 unknown과 정책 미확인을 유지한다.
- 숫자 IF의 거짓 분기에는 null/undefined 등이 남을 수 있으므로 숫자형 검증을 통과했다고 취급하지 않는다. 동적 loose 옵션, Switch의 동적·잘못된 fallback이나 같은 포트 fallback도 보호 근거를 상속하지 않는다.
- 과거 SQL 합성 사례 `type-constrained-false`의 음성 정답이 잘못돼 [현재 0.1.2 정답](../fixtures/cases-0.1.2.json)에서 위험 **후보**로 정정했다. 원본 바이트, 이전 정답과 실측 파일은 보존한다. [현재 12개 재검사](../validation/legacy-0.1.2-results.json)는 이 정정을 포함하며, 과거 정확도 수치를 현재 결과로 재사용하지 않는다.

전체 Codex 리뷰와 독립 Astra 6 max 검토를 수행했다. 숫자 조건·legacy 분기·Switch fallback·민감도 전파·JS 문자열의 합성 반례로 수정 결과를 확인했다. 이 검증은 실제 n8n 업무를 실행한 결과가 아니다.

## 검증 근거

| 검사                   | 실제 결과                                                                                                      |
| ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| 워커 필수 검사         | Node 24.14.0, format/lint/typecheck/build, 단위·회귀 **295/295**, skip 0                                       |
| 저장소 도구            | 문서 포맷·OpenAPI 검사, 도구 테스트 **6/6**, 커밋 제목 검사                                                    |
| 기존 정적 코퍼스       | **27/27**. 사전 선언한 사실 23개: TP13/TN10/FP0/FN0, 별도 상태 4개                                             |
| 현재 legacy SQL 코퍼스 | **12/12**. 후보 양성5/음성3/미지원4, FP0/FN0                                                                   |
| 실제 도구·격리         | 합성 assessment **5개/파일6개**, 격리 조건9개, 실패·취소4개, 컨테이너 정리 확인                                |
| 실제 개인정보 모델     | **44개 대조 통과**: 기존18 + 장문·문맥11 + helper 총예산15. Python3.11.2/Presidio2.2.366/spaCy3.8.18/모델3.8.0 |
| 같은 공개 원본         | **15 partial/0 error**, Gitleaks·NLP·Python 도구 **45회/오류0**                                                |
| 알려진 공개 사례       | **38개 대조 통과**, 고정 제목 오탐 제거와 본문 후보 보존을 각각 확인                                           |
| 수정·재검사·비교       | 인증 선언·수신자 변경·전송 비활성화 **3개 통과**, 원본 해시 유지                                               |

근거: [통합 요약·이미지/소스 해시](../validation/partial-followup-0.5.0-results.json), [모델 대조](../validation/native-profile-0.5.0-results.json), [공개 원본](../validation/public-assessment-0.5.0-results.json), [원인별 비교](../validation/public-coverage-0.5.0-results.json), [회귀 대조](../validation/public-regressions-0.5.0-results.json), [수정본 비교](../validation/public-service-path-0.5.0-results.json), [정적 코퍼스](../validation/static-corpus-0.5.0-results.json).

모델 총예산 대조는 일반 workflow의 256 KiB 입력 제한보다 큰 합성 문자열이 필요하므로, 같은 고정 이미지·격리 설정에서 native helper에만 직접 전달했다. 일반 workflow 제한을 우회해 서비스를 허용한 것이 아니다. 짧은 영어 이름의 한 문맥은 모델이 놓쳤고 그 관측을 그대로 남겼다. 개인정보 전체 재현율을 보증하지 않는다.

공개 원본과 수정본의 노드·Code·표현식은 실행하지 않았다. 3개 수정본은 통제된 수동 변경이며 실제 사용자 업로드나 기능 보존 검증으로 표현하지 않는다. 공개 15개에는 자동 수정 적용 대상이 없었다. 원문·실제 수신자·토큰은 로컬에만 두고 저장소에는 해시·구조 위치·고정 진단 코드와 집계만 기록했다.

## 재현과 다음 경계

`worker/`에서 [실행 문서](assessment.md)대로 0.5.0 이미지를 빌드하고 불변 image ID와 Docker 경로를 지정한다. 과거 기록을 덮어쓰지 않도록 새 출력 디렉터리를 사용한다. `FROZEN_INPUT_DIRECTORY`에는 같은 manifest와 원본 15개가 있어야 하며, 비교용 `BEFORE_040_DIRECTORY`의 원본 보고서를 보존한다.

```powershell
npm run verify
node validation/verify-static-corpus.mjs evidence-local/new-static.json
node validation/verify-legacy-current.mjs evidence-local/new-legacy.json
$env:WORKER_ASSESSMENT_VALIDATION_OUTPUT = 'evidence-local/new-runtime.json'
node validation/verify-assessment-runtime.mjs
node validation/verify-native-profile.mjs evidence-local/new-native.json
$env:WORKER_ASSESSMENT_RUNTIME_RECEIPT = $env:WORKER_ASSESSMENT_VALIDATION_OUTPUT
node validation/verify-public-assessment.mjs FROZEN_INPUT_DIRECTORY evidence-local/new-public.json
$env:WORKER_PUBLIC_ASSESSMENT_RECEIPT = 'evidence-local/new-public.json'
node validation/verify-public-service-paths.mjs FROZEN_INPUT_DIRECTORY evidence-local/new-service.json
node validation/verify-public-regressions.mjs FROZEN_INPUT_DIRECTORY evidence-local/new-regressions.json
node validation/audit-public-coverage.mjs BEFORE_040_DIRECTORY FROZEN_INPUT_DIRECTORY evidence-local/new-coverage.json
```

API 없이도 더 확장할 수 있는 범위는 남은 커넥터별 변환, 복잡한 Code·SQL 문법, AI 연결 구조다. 각각 실제 동작과 부정 사례를 확인한 유한 프로파일로 추가해야 한다. 운영 권한·정책·패키지·네트워크 근거, JSON에 없는 실제 데이터와 첨부파일은 별도로 받아야 한다. 실제 팀 작업·파일·결과 API는 프론트·백엔드 구현 후 #18에서 맞추며, 이번 보완을 API 연동 완료로 처리하지 않는다.
