# `partial`의 원인과 다음 조치

`partial`은 검사 프로세스 실패율이나 취약점 수가 아니다. 원래 결과 계약은 규칙 하나라도 `partial` 또는 `unsupported`이면 전체 결과를 `partial`로 집계한다. 영어 개인정보 모델의 범위 안내도 해당 규칙을 `partial`로 만들고, 실행 환경 근거가 없으면 환경 규칙은 `unsupported`다. 이 원래 판정과 정책 결정은 변경하지 않는다.

0.7.0의 확정 공개 25개는 모두 `partial`이지만 Gitleaks·Presidio/spaCy·Python 검사 상태는 각각 25개 모두 `completed`였다. 두 규칙 `PRESIDIO_PII_CANDIDATES`·`CONTEXT_RUNTIME_EVIDENCE`를 집계에서 제외해 보는 계산에서도 나머지 규칙이 25개 전부 `partial`이었다. 따라서 영어 모델 안내와 환경 정보만 보충하면 전부 완전 분석된다는 뜻도 아니다.

## 추가 결과

```sh
node dist/cli.js coverage assessment.json
node dist/cli.js coverage assessment.json inspection.json
```

프로그램 진입점은 `buildCoverageExplanation(assessment, llm?)`이다. 독립된 `coverageExplanationVersion: 1.0.0` 결과이며 팀 HTTP API 계약이 아니다. 엔진 0.9.0의 서비스 묶음은 1.1.0이고, 과거 보고서는 기존 1.0.0 설명을 재현한다. 최신 원인 등록부로 과거 보고서를 다시 분류하면 당시 저장한 원인 수와 다를 수 있으므로 진단 자체의 증감과 분류 변경을 구분한다. 과거 검증 파일은 덮어쓰지 않는다.

| 원인                   | 뜻과 다음 조치                                                                                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `environment_evidence` | 실제 권한·패키지·네트워크·외부 입력과 응답 등의 근거가 필요하다. 운영자가 확인할 조건으로 표시한다. 실제 키나 개인정보 원문 제출을 요구하지 않는다.                      |
| `definition_input`     | 하위 워크플로, 바이너리, 필수 필드·연결 등 검사 대상이 빠졌다. 가능한 정의를 추가한 뒤 재검사한다. 팀 API 연동 완료와는 별개다.                                          |
| `analyzer_extension`   | 파서·노드·흐름 지원 또는 처리 한도 개선 대상이다. 공식 동작과 오픈소스 AST를 근거로 지원 범위를 구현하고 회귀 검사한다. 모두 유한한 구현으로 해결된다고 보증하지 않는다. |
| `mixed_provenance`     | 실제 값 부족, 정의 오류, 미지원 변환, 정책 적용 실패 등이 섞일 수 있다. 상위 경로를 확인하기 전에는 환경 문제만으로 단정하지 않는다.                                     |
| `scope_boundary`       | 영어 개인정보 모델·제한된 정적 분석 등 범위나 본질적인 검증 한계다. 범위 안내만인지 `scopeOnly`로 별도 구분한다.                                                         |
| `unclassified`         | 새 진단이다. 원인을 조사해야 하며 자동으로 정상 또는 환경 문제로 분류하지 않는다.                                                                                        |

0.9.0은 정책이 없는 경우를 `transfer_policy_not_configured`·`ai_model_transfer_policy_not_configured`·`ai_vector_transfer_policy_not_configured`로 구분해 사용 전 주의사항으로 제공한다. 목적지·분류를 해석하지 못해 제공된 정책을 적용하지 못한 경우는 여전히 혼합 원인이다. 이미 알려진 금지 데이터 종류는 목적지를 몰라도 정책 위반 후보로 유지한다. `code_parse_unavailable`도 원문 오류와 파서 미지원 가능성을 함께 남긴다. 개별 사례는 코드·상위 경로를 추가 확인한다.

전체 원시 규칙의 진단을 집계하므로 서비스 카드의 표시 한도 때문에 원인이 사라지지 않는다. 한 진단이 여러 coverage 항목에 참조돼도 같은 규칙 안에서는 한 번 세고, 서로 다른 규칙의 진단은 각각 센다. `diagnosticOccurrences`는 독립 취약점 개수가 아니다. 각 코드에 최대 4개의 정확한 파일·분석·규칙·진단 참조와 생략 참조 수를 제공하며 합계는 전부 유지한다. `assessmentSha256`는 검증된 원래 보고서의 공백 없는 JSON 직렬화 해시다.

입력 오류·도구 실패·파일 분석 실패는 `error`, `toolFailures`, `fileFailures`로 따로 보존한다. 실패한 검사를 빈 원인 목록만 있는 성공으로 해석하면 안 된다. 원래 `decision`, `assessmentStatus`와 `workflowExecution: not_run`을 유지한다.

상세 원인 목록은 최대 256개 코드로 제한한다. 이를 넘는 가져온 보고서도 전체 집계는 유지하며 `truncated`, `omittedReasonCodes`, `omittedReasonOccurrences`에 생략 범위를 표시한다. 공개 사례 비교 검증은 코드가 생략된 결과를 거부한다.

## LLM이 돕는 부분

기존 OpenRouter GLM이 최소 요약에서 고른 근거에 한해 `selectedDiagnosticActions`를 제공한다. 모델의 선택을 정확한 분석·파일·진단과 결합하고, 조치 문장은 검증된 원인 분류표에서 가져온다. 다른 원본이나 다른 검사 문맥의 LLM 결과는 거부한다. `analysisGapResolved: false`이며 파서 미지원·권한 미확인을 모델 답변으로 해소하지 않는다.

원본 JSON·Code·이름·주소·키는 외부 모델에 보내지 않는다. 개인정보 문맥 모델의 언어·완전성만 초기 서비스 미완료 사유에서 제외하며 기존 탐지는 유지한다. 별도의 동적 분석 서비스도 추가하지 않는다. 초기 서비스는 실행 환경·권한·정책을 사용자에게 입력받지 않고 사용 전 주의사항으로 제공한다. 워커의 선택적 근거 계약은 기존 검증·확장 용도로 보존하지만 서비스의 필수 입력 절차로 제시하지 않는다.

## 검증 자료

`validation/compare-coverage-causes.mjs`는 같은 원본 해시를 가진 before/after 수집 목록을 대조한다. 빈 목록, 수집 실패, 중복·누락·변경된 사례, 같은 before/after 디렉터리를 거부한다. 비교용 파생 파일은 after 쪽에만 기록하여 이전 검증 자료를 보존한다. 두 단계의 이미지·엔진 버전·보고서 해시와 코드별 변화 및 원인별 발생 사례 수를 기록한다. 공개 원본의 실행 성공이나 탐지율을 계산하는 도구는 아니다.
