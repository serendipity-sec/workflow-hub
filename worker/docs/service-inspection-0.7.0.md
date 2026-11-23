# 0.7.0 서비스 검사·설명·LLM 연결

[#14](https://github.com/serendipity-sec/workflow-hub/issues/14)의 기존 워커 브랜치에서 구현했다. #7의 JSON 정적 분석 원칙과 10개 검사 범주는 유지한다. 실제 팀 API 적응과 운영 검증은 [#18](https://github.com/serendipity-sec/workflow-hub/issues/18)에 남긴다. 한국어 개인정보 모델 확대는 사용자 결정에 따라 이번 범위에서 제외했다.

## 서비스에 전달하는 결과

`inspect`는 원본 검사, 고정 한국어 설명, 선택적 LLM 근거 선택을 같은 원본 해시에 묶는다. 기능 구조, 위험 후보와 일반 관찰, 실제 분석 공백, 환경 확인 조건, 지원 언어·분석 방식을 구분한다. 근거의 호출별 `analysisKey`를 보존하여 같은 하위 정의가 반복되어도 서로 다른 호출의 근거가 섞이지 않게 한다.

`executionStatus=completed`는 검사 처리가 끝났다는 뜻이다. `analysisStatus=review_required`, `analysisGaps`, `environmentChecks`를 함께 표시한다. 원래 `assessment.status=partial`을 지우거나 안전 판정으로 바꾸지 않는다. 표시 계약은 [service-report.md](service-report.md), 실제 연결 자료는 [integration-handoff.md](integration-handoff.md)다.

## 구현한 보완

| 영역      | 변경과 경계                                                                                                                                                                                                              |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 흐름      | Wait 1/1.1의 고정 interval, Aggregate 1의 지원 필드 선택·이름 변경·목록 처리, Gmail/IMAP/Telegram/Form 외부 입력, 변경되지 않는 원시 const의 함수 캡처를 보완했다. 복잡한 배열 정렬과 미지원 변환은 불확실성을 유지한다. |
| 민감 출처 | Aggregate의 null 제거·펼치기에서 가능한 원출처와 분류를 보존한다. 정확한 출력 위치를 알았다고 주장하지 않는다. 함수 자기 이름과 바깥 const의 혼동, 잘못된 Wait 단위와 Aggregate 중복 설정도 거부한다.                    |
| 크기      | 노드 한도를 64→128로 확대했다. 256KiB 원본·128연결·깊이32는 유지한다. 10범주 기본 검사 출력은 512KiB로 분리하고 기존 SQL 128KiB·전체 assessment 2MiB는 유지한다.                                                         |
| 수정      | 고정 Postgres 2.8 SELECT의 최대 8개 AND 동등값을 바인딩하는 제한 프로필을 추가했다. 동적 식별자·함수·OR·주석·다중문장·기존 바인딩·프로토타입 접근은 자동 수정하지 않는다. 원본 보존·수정본 재검사가 필수다.              |
| 설명      | 고정 한국어 문장에 위치·근거·조치를 연결하고 일반 관찰을 취약점 수로 세지 않는다. 생략한 결과 수와 분석 한도를 노출한다.                                                                                                 |
| LLM       | OpenRouter `z-ai/glm-5.3-flash`를 연결했다. 모델은 기존 근거 ID를 최대 8개 선택하며 워커가 고정 설명을 작성한다. 새로운 판정·안전 주장·코드·자동 패치는 허용하지 않는다. 원본 JSON·Code·이름·주소·키는 보내지 않는다.    |

기존 Acorn, node-sql-parser, Zod와 실제 Gitleaks·Presidio/spaCy·Python AST 실행을 재사용했다. LLM 연결에 별도 SDK나 실행형 도구를 추가하지 않았다. [도구 선택 근거](oss-decisions.md), [LLM 가격·전송 경계](llm-review.md), [수정 프로필](assessment-change.md)을 함께 참조한다.

## 검증 근거 읽기

최종 소스에서 워커 475개·루트 도구 6개 테스트, format/lint/typecheck/build와 독립 리뷰를 통과했다. 최종 고정 이미지의 공개 25개에서 검사 도구 결과 75개가 정상 반환됐고 도구 오류·입력 거부는 0개였다. **25개 모두 분석 범위가 남아 `partial`**이다. 서비스 표시 결과 25개도 원본 판정을 유지했다. CLI `inspect`의 실제 격리 검사와 설명 결합은 합성 바인딩 사례로 별도 확인했다.

동일 공개 15개에서 `opaque_node_effects` 진단은 512→500, `node_transform_unsupported`는 30→17로 감소했다. 여러 규칙에서 반복되는 진단 발생 횟수이며 해결된 독립 취약점 수가 아니다. 최종 보고서의 LLM 문맥은 기존 실제 호출 문맥과 24개가 같고 1개가 다르다. 다른 문맥의 응답은 새 결과에 재사용하지 않았으며 API를 추가 호출하지 않았다.

- [최종 실행 요약](../validation/service-inspection-0.7.0-results.json)은 코드·실행 이미지·개별 영수증과 검사 수를 연결한다.
- [고정 15개](../validation/public-assessment-0.7.0-results.json), [추가 10개](../validation/public-additional-0.7.0-results.json)는 공식 n8n 템플릿 API에서 확보한 원본의 해시를 고정한 정적 호환성 시험이다. 원본 파일은 커밋하지 않는다. 일반적인 탐지율·오탐률 시험이 아니다.
- [동일 15개의 전후 비교](../validation/public-coverage-0.7.0-results.json)는 진단 발생 횟수와 미지원 범위를 비교한다. 규칙별 반복 진단을 독립 위험 개수로 계산하지 않는다.
- [공개 사례 LLM 15개](../validation/llm-public-15-0.7.0-results.json)와 [10개](../validation/llm-public-10-0.7.0-results.json)는 승인된 총 25회의 실제 모델 호출이다. 호출 당시 정적 보고서와 출력 해시에 연결되며 후속 정적 수정의 호출로 재계산하지 않는다.
- [합성 수정 실행](../validation/remediation-expansion-0.7.0-results.json)은 직접 만든 두 조건 조회의 DB 대조 7개와 원본/수정 응답 14개를 검증했다. 임의 업무 기능 보존을 보증하지 않는다. 최초 실행 실패와 후속 통과, 후속 방어 변경의 대표 바이트 동일성 확인도 구분한다.

초기·재리뷰 실행 기록은 로컬 `evidence-local/pre-review-receipts/`, `pre-policy-fix-receipts/`에 보존한다. 한 공개 사례의 중간 이미지 검사에서 Gitleaks 실패가 한 번 관측됐고 [동일 이미지 재검사](../validation/public-recheck-2490-0.7.0-results.json)는 통과했다. 최초 실패 원인은 확정하지 않았으며 이를 처음부터 무오류였다고 계산하지 않는다.

## 남은 범위와 출시 판단

임의 JavaScript/Python, 모든 커넥터와 런타임 배열 정렬, 동적 SQL·하위 호출 인자/반환·AI의 실제 선택을 완전히 증명하는 범용 분석기는 아니다. 정확한 하위 정의·실제 입력·권한·패키지·네트워크·정책이 없으면 그 조건은 미확인이다. LLM 참조 선택은 이 근거를 만들어내지 않는다.

공개 사례의 `partial`을 0으로 만든 완료 결과가 아니다. 초기 서비스는 **정적 검사 결과와 구체적인 수정·확인 목록을 제공하는 검토 도구**로 연결한다. 검사 완료와 분석 완전성, 위험 후보와 실제 취약점, 수정 후보와 업무 기능 보존을 구분해야 한다. 실제 팀 API·화면·배포 연동은 아직 수행하지 않았다.
