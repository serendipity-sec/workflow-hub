# 전체 assessment 비교

`src/assessment-compare.ts`는 두 `assess` 보고서의 base 규칙과 확장 18개 규칙에서 **이미 보고된 모든 finding**을 비교한다. 이전 엔진의 확장 13개 규칙은 해당 버전의 보고서로 읽는다. 원본 워크플로·표현식·SQL·Code를 실행하거나 파일을 수정하지 않는다. 기존 `compare-static`의 v2 계약과 저장된 결과는 유지한다.

이번 기능은 [실제 공개 템플릿 검증](public-service-validation.md)에서 확인한 전체 assessment 비교 공백을 보완한다. 아래 단위 테스트는 합성 입력과 명시적인 도구 결과 fixture를 사용한다. 실제 공개 템플릿 정확도, 정상 업무 보존, 실제 n8n 실행 또는 팀 API 연동을 검증한 것으로 해석하지 않는다.

## 호출과 반환값

```ts
import {
  compareAssessment,
  assessmentComparisonSchema,
} from "./assessment-compare.js";

const comparison = compareAssessment(beforeReport, afterReport);
assessmentComparisonSchema.parse(comparison);
```

입력은 `unknown`이며 먼저 전체 `assessmentReportSchema`로 검증한다. 반환 계약은 `comparisonVersion: "1.0.0"`이다.

| 필드                          | 의미                                                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| `beforeSha256`, `afterSha256` | 검증된 보고서가 가리키는 정확한 루트 입력 바이트 해시. 잘못된 보고서 쪽은 `null`          |
| `basis`                       | 동일 입력, 같은 assessment 계약의 다른 입력, 또는 호환 불가/실패                          |
| `status`                      | 비교 조건을 충족했는지. `inconclusive`여도 항목별 관찰과 불확실성 사유는 보존             |
| `files`                       | 루트·하위 파일의 대응과 각 파일의 해시, 분석 키, 깊이, `coverageStatus`, `policyDecision` |
| `rechecks`                    | 이전 finding마다 정확히 하나의 항목. `before`와 대응하는 `after` 참조                     |
| `newFindings`                 | 이전에 대응하는 관찰이 없는 이후 finding. 불확실한 추가도 삭제하지 않음                   |
| `counts`                      | 위 항목들의 개수. 정보성 관찰도 포함하므로 취약점 개수가 아님                             |
| `codes` 및 각 항목의 `codes`  | 고정된 비교 사유 코드                                                                     |

관찰 참조는 `id`, `ruleId`, `category`, `severity`, `claim`, `nodeKey`만 포함한다. 상세 근거와 필드 위치는 해당 파일의 원 보고서 finding ID로 연결한다. 비교 결과에 원문·수신자·주소·임의 필드명·근거 문자열을 복사하지 않으며, 민감 값의 새 해시도 생성하지 않는다.

출력에는 항상 다음 제한이 포함된다.

```json
{
  "scope": "all_reported_static_findings",
  "execution": "not_run",
  "behaviorPreserved": "not_verified",
  "exploitBlocked": "not_verified",
  "securityEquivalent": "not_claimed"
}
```

## 관찰 상태의 해석

| 항목 상태        | 허용되는 해석                                                                      |
| ---------------- | ---------------------------------------------------------------------------------- |
| `persisting`     | 대응하는 정적 관찰이 양쪽에 있음. 같은 비밀 값·실제 수신자·실행 결과라는 뜻은 아님 |
| `not_observed`   | 비교 가능한 동일 분석 범위에서 이전 관찰이 다시 나타나지 않음                      |
| `newly_observed` | 양쪽에서 해당 위치를 검사할 수 있었고, 이후 보고서에서 새로 관찰됨                 |
| `inconclusive`   | 규칙·근거·도구·범위·식별자 또는 파일 대응 때문에 변화의 의미를 판정할 수 없음      |

`not_observed`를 “취약점 해결”, “공격 차단” 또는 “정상 기능 보존”으로 표시하면 안 된다. `compared` 역시 워크플로 전체의 분석 완료나 안전 판정이 아니다. 파일의 `coverageStatus`가 `partial`일 수 있으며, 정보성 외부 전송 관찰이나 인증 설정이 계속 존재하는 것은 자연스럽다. 정책의 허용 여부와 실제 전송 기능의 존재는 별개다.

`detailsChanged`는 같은 관찰의 심각도·claim·근거 위치/코드·가정 또는 해당 finding의 정책 판단이 바뀌었음을 나타낸다. 원래 finding의 출처와 claim 수준을 그대로 확인해야 한다.

## 대응과 비교 조건

루트는 두 보고서의 루트끼리 대응시킨다. finding은 기존 `stableId`와 규칙·분류·안정적인 `nodeKey`·노드 배열 번호를 제거한 상대 위치로 대응시킨다. 값 자체는 대응 키에 사용하지 않는다. 따라서 배열 순서 변경은 대응을 깨뜨리지 않지만, 임의로 재사용된 ID 하나만으로 다른 위치를 동일 관찰로 보지 않는다.

하위 파일은 루트부터의 호출 노드 키 경로로 구분한다. 같은 파일을 두 노드가 호출하면 별개 분석으로 보존한다. 각 경로에서 정확한 child 입력 해시까지 같아야 `same_child_hash`다. 부모 루트의 다른 내용이 바뀌어 `analysisKey`가 달라져도 이 조건으로 대응할 수 있다. child 해시가 바뀌면 `changed_child_hash`로 남기며 그 파일의 전후 관찰은 `inconclusive`다. 손자 파일 해시가 같아도 중간 child 정의가 바뀌면 동일 호출 문맥으로 승인하지 않는다.

다음 조건은 관찰 소실의 확정적 해석을 막는다.

- assessment 엔진/계약, base 프로파일, 규칙 프로파일 또는 격리 경계 변경.
- 정책·제공 근거·패키지 평가 변경, 정책 적용 시 평가 시각 변경.
- Gitleaks/네이티브 도구 실패 또는 분석 도구·모델 프로파일 변경.
- 노드 삭제·추가·비활성화·종류 변경·식별 방식 변경, 근거 경로에 있던 노드의 누락이나 비활성화.
- 해당 규칙의 분석 범위/진단 변경, 대상 범위를 덮는 `checked` 부재, 겹치는 `partial`/`unsupported` 범위.
- 흐름 근거를 가진 관찰에서 연결 구조 변경.
- 하위 파일 미제공·무효·분석 제한·순환·호출 비활성화 또는 호출 경로 불일치.

범위 비교는 finding/diagnostic ID 개수 변화 자체를 비교 조건 변경으로 오인하지 않는다. 대신 노드 배열 순서를 제거한 실제 범위, 검사 상태와 진단 의미를 대조한다. 문서 전체의 `checked`가 있어도 더 좁은 범위의 미지원·부분 분석을 덮어 숨기지 않는다.

`functionSummary`가 없는 이전 `0.3.0` 보고서는 읽을 수 있지만 노드 존재·활성 상태를 확정할 수 없어 `node_inventory_unavailable`을 남긴다. `0.3.0`과 `0.4.0`의 전후 비교는 엔진 변경으로 불확실하다. 이름에서 유도한 식별자는 `name_derived_identity`로 표시하며 같은 이름·종류 안의 관찰 대응에만 사용한다. 이름 변경으로 대응이 끊기면 단순 해결이나 동일 노드의 확정적 삭제로 처리하지 않는다.

제공 근거의 `normalizedSha256`는 파일 해시 바인딩까지 포함한다. 동일 정책을 수정 파일에 새로 바인딩한 경우도 전체 근거 해시가 바뀌므로 현재 비교는 보수적으로 `evidence_context_changed`를 남긴다. 정책이 적용된 평가 시각 변경도 예외의 만료·승인 상태를 재사용하지 않기 위해 불확실하게 처리한다. 전후 파일을 동일 시각/근거라고 꾸미거나 이전 승인 해시를 새 파일에 재사용해서 이 제한을 우회하면 안 된다.

## 실패와 한도

보고서가 무효이거나 전체 분석이 실패하면 `basis: "incompatible_or_failed"`이며 `status: "inconclusive"`다. 반대쪽 보고서가 유효하면 그쪽의 finding 참조를 가능한 범위에서 보존한다. 재검사 실패 후 이전 항목을 빈 목록으로 바꿔 정상처럼 보이지 않게 한다. 무효인 쪽을 읽지 못했다는 것은 해당 파일의 finding이 0개라는 뜻이 아니다.

현재 알려진 base 10개와 확장 18개 규칙을 지원한다. 엔진 0.6.0은 18개 전체를, 과거 엔진은 13개 전체를 각각 요구한다. 모르는 규칙 세트나 모호한 파일 대응은 성공 비교로 처리하지 않는다. 비교 출력은 최대 4,096개 항목, 18개 파일 대응, 2 MiB로 제한한다. 초과하면 `comparison_output_limit`을 반환하며, 잘린 목록을 완료된 비교로 제공하지 않는다. strict Zod 검증은 중복 참조·불일치 집계·불가능한 상태 조합·추가 임의 필드·안전 보증으로 바꾼 값도 거부한다.

## 검증 범위

Node.js 24에서 `test/assessment-compare.test.mjs`의 회귀 16개를 실행했다. base와 확장 13개 전체 집계, TLS 및 네이티브 PII 관찰의 소실, 도구 실패/버전 변경, 노드 삭제·비활성·미지원, 배열 순서와 이름 기반 식별, 이전 엔진 보고서, 규칙/범위 축소, `/nodes` 전체의 부분 분석과 개별 노드 검사 범위 중첩, 정책/근거/시각/격리 변경, 반복 child 호출, child 누락·변경과 변경된 조상, 민감 문자열 비노출, strict 출력 검증, 전체 분석 실패 시 이전 결과 보존을 포함한다.

실행 명령은 `worker/` 기준이다.

```text
node node_modules/typescript/bin/tsc
node --test test/assessment-compare.test.mjs
```

CLI 연결과 Docker 통합 실측은 통합 담당자가 별도로 검증한다. 공개·버전 저장·사용자 권한·다운로드 바이트 연결과 실제 팀 API는 서비스 영역의 미완료 조건으로 유지한다.
