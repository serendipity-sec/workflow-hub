# 10개 정적 검사 구현·검증 기록

2026-11-22, #14의 독립 로컬 워커 구현이다. 보고서 계약은 `2.0.0`, 엔진·규칙은 `0.2.0`이다. 모든 10개 항목을 결과에 포함하며 각 항목의 지원 프로파일과 한계를 따로 표시한다. #7의 확장 설계 전체나 실제 서비스 연동의 완료를 뜻하지 않는다.

## 구현 범위와 실행 방식

[구현 설계와 담당 분할](implementation-plan.md), [내용 검사 도구](oss-decisions.md), [설정·코드 프로파일](settings-profiles.md), [흐름 프로파일](flow-profiles.md)을 함께 확인한다. 신뢰한 컨트롤러가 제한된 파일을 읽고 Gitleaks를 실행한 뒤, 파일 쓰기·자식 프로세스 생성 권한을 부여하지 않은 Node 분석기에 결과를 전달한다. 업로드된 노드·표현식·Code를 실행하지 않는다. Node 권한 제한은 운영 OS/컨테이너 격리 검증을 대신하지 않는다.

원문 대신 고정 근거 코드·구조 위치·불투명 노드 식별자를 반환한다. `findings`에는 정보성 기능·설정 확인과 위험 후보가 함께 있으므로 발견 수를 취약점 수로 해석하지 않는다. `partial`은 발견 여부와 별개로 미지원 또는 부족한 분석 근거가 있다는 뜻이다.

## 검증과 재현

저장소 루트에서 Node 24.14.0으로 실행한다.

```text
npm ci
npm run check
npm run test:tooling
npm --prefix worker ci
npm --prefix worker run verify
```

워커의 기존 51개 회귀를 보존하고 내용·설정·흐름·10개 항목 통합·재검사·기본값 검증을 추가했다. 기존 고정 합성 코퍼스 12개와 [이전 외부 도구 비교](../validation/external-results.json), [합성 정상 동작 근거](../validation/native-normal-parity.json)도 보존한다. 저장된 예전 실행 기록을 이번에 재실행한 결과로 표현하지 않는다.

| 실행한 검사                           | 결과와 분모                                                           |
| ------------------------------------- | --------------------------------------------------------------------- |
| 워커 format/lint/typecheck/build/test | 109개 테스트 통과, 실패·skip 0                                        |
| 루트 포맷/OpenAPI·도구 검사·제목 형식 | 통과, 도구 테스트 6개                                                 |
| 기존 SQL 코퍼스 재실행                | 12개 기대 결과 일치: TP 4, TN 4, FP/FN/실패 0, 미지원 4               |
| 저장된 외부 도구 원본·요약 대조       | 일치. 외부 도구를 새로 실행한 결과로 취급하지 않음                    |
| 실제 Gitleaks·내용 통합               | 고정 합성 7개 통과                                                    |
| 10개 항목의 선언된 패턴 코퍼스        | 27개 통과: 패턴 판정 23개(TP 13, TN 10, FP/FN 0)와 별도 상태 검증 4개 |
| 공개 원본 정적 호환성                 | 5개 처리·해시 일치, 오류 0, 모두 `partial`                            |

`worker/`에서 다음 명령을 실행한다. Gitleaks는 8.30.1의 신뢰한 절대 경로를 `WORKER_GITLEAKS_PATH`에 설정한다.

```text
node validation/verify.mjs captured
node validation/verify.mjs worker
node validation/verify-static-corpus.mjs
node validation/verify-static-tools.mjs
node validation/verify-public-static.mjs <download directory>
```

- `captured`: 보존한 원본 외부 도구 실행과 요약의 일치 검사다. 외부 도구 재실행 명령이 아니다.
- `worker`: 기존 12개 합성 입력을 현재 워커의 호환 CLI로 다시 분석한다.
- `verify-static-corpus`: [고정 합성 결과](../validation/static-corpus-results.json)의 10개 항목별 양성·음성 분모와 오류·미지원 상태를 확인한다. 스캐너는 `controlled_fixture`이며 실제 Gitleaks 정확도 측정이 아니다. 판정 23개는 사전 지정한 근거 코드의 존재/부재만 평가한다. 정보성 기능·설정도 포함하므로 TP/TN을 실제 취약점/안전 파일의 수로 읽지 않는다. 별도 상태 사례의 예상 오류 거절 2개, 미지원 대상 1개, 부분 검사 대상 4개를 숨기거나 분모에서 안전 판정으로 바꾸지 않는다.
- `verify-static-tools`: 실제 Gitleaks와 내용 검사 7개 합성 사례를 실행한다. [도구 실행 근거](../validation/static-tool-results.json)에 바이너리·입력 해시, 버전·인자·오류 처리 결과를 보존한다.
- `verify-public-static`: 다운로드 당시의 SHA·크기와 일치하는 공개 원본만 정적 검사한다. [공개 호환성 근거](../validation/public-static-results.json)에 원본·실행 모듈·lockfile·도구·검증 스크립트 해시와 항목별 결과를 보존한다. 원본 JSON과 그 내부의 값은 커밋하지 않는다.

공개 n8n 템플릿 16081, 20541, 20459, 14034, 2490은 모두 10개 항목 보고서를 생성했고 결과는 `partial`이다. 미지원 노드·표현식·데이터 변환·의존성을 그대로 남겼다. 이 5개는 정답이 있는 취약점 평가 집합이 아니므로 TP/FP/FN, 탐지 정확도나 전체 안전성의 근거로 사용하지 않는다. 업로드 파일 실행과 실제 API 호출은 하지 않았다.

CI의 worker 작업은 워커 검사 뒤 고정 Gitleaks 소스를 빌드하여 합성 네이티브 도구 검증을 실행한다. Gitleaks의 버전 문자열은 [공식 `version.Version` 빌드 변수](https://github.com/gitleaks/gitleaks/blob/v8.30.1/version/version.go)에 소스 태그와 같은 `8.30.1`을 지정한다. 로컬 Windows 실행과 GitHub Linux CI의 실행 결과는 구분한다.

## 리뷰와 재검사 경계

독립 모듈 점검과 Codex `/review`를 수행한다. 발견한 숫자 객체 키의 원문 위치 노출, Gitleaks 종료 제한, 응답 `responseKey` 의미, 비동기 Code AST, 문서·노드 범위 비교 문제를 고치고 회귀 사례로 보존했다.

저장소 Gitleaks 검사는 공개 검증 기록의 `dist/runtime/api-client.js` SHA-256을 `generic-api-key`로 오인했다. 실제 빌드 파일의 SHA-256과 일치함을 확인한 뒤 `.gitleaks.toml`에 해당 기록 파일·필드·정확한 해시 행만 결합한 예외를 추가했다. 해시 일반식이나 디렉터리 전체를 제외하지 않는다. 이 저장소 예외는 사용자 업로드를 검사하는 워커의 신뢰 기본 Gitleaks 설정에 전달하지 않는다.

`compare-static`은 같은 규칙 프로파일의 `persisting`, `newly_observed`, `not_observed`, `inconclusive` 관측을 제공한다. 문서 전체의 내용 검사와 노드 범위 설정 검사가 완료됐을 때 하위 필드 관측을 비교한다. 노드 삭제·도구 실패·지원 범위 상실·버전 불일치는 해당 근거의 수정 성공으로 계산하지 않는다. `not_observed`도 실제 비밀정보 폐기, 정상 기능 보존 또는 일반적인 보안 수정의 증명이 아니다. 목적지의 실제 값·데이터 민감도·인증 정책 전체의 의미 비교는 현재 일반 비교기가 제공하지 않는다. 기존 SQL의 좁은 바인딩 재검사 근거는 별도로 유지한다.

## 남은 범위

실제 팀 API는 프론트·백엔드 구현 후 #18에서 맞춘다. 작업 수신·인증·파일 다운로드·lease·결과 저장의 실제 계약, 테스트 주소·계정, 운영 격리 환경이 필요하다. 기존 모의 API 테스트는 이 조건을 충족했다는 증거가 아니다.

10개 카테고리의 규칙 구현과 #7의 확장 설계 전체를 구분한다. 이메일·메시지 수신처와 허용 대상 정책, 필드별 민감도 전파, 다양한 DB·노드·표현식, 일반 프로그램/복잡한 Merge/재귀 분석, 개인정보 NER, 설치 패키지 CVE·실제 권한·네트워크 검증은 지원 확대 또는 환경 정보가 필요한 범위다. Semgrep·Presidio를 실행한 것으로 보고하지 않는다.
