# Workflow Security Worker

Workflow Hub의 `worker/`에서 n8n JSON을 정적으로 분석합니다. 결과에 적용된 규칙과 분석 범위를 기록합니다. 설계 기준은 [보안 설계](../docs/SECURITY_DESIGN.md)와 [Workflow Hub PR #7](https://github.com/serendipity-sec/workflow-hub/pull/7)입니다.

현재 기본 진입점은 **`assess`**입니다. 10개 범주에 필드 흐름·메신저/이메일·실제 NLP/Python AST·SQL AST·정책·환경/패키지 근거·자식 정의·수정안을 연결합니다. Docker에서 네트워크·파일 쓰기·자원을 제한합니다. [통합 검사 실행법과 지원 범위](docs/assessment.md), [SEC 사례 25개 대응표](docs/assessment-evidence.md), [실측 검증](validation/assessment-runtime-results.json)을 먼저 확인하세요. 실제 팀 API는 연결하지 않았습니다.

[실제 공개 템플릿 15개로 서비스 적합성을 검증한 결과](docs/public-service-validation.md)는 14개 부분 분석·1개 입력 거부였습니다. ID 없는 템플릿, 개인정보 오탐, 실제 SQL/전송 노드의 지원 범위와 전체 검사 결과 비교 등 보완점이 확인됐습니다. 두 서비스 흐름의 완성 여부는 이 결과까지 함께 판단해야 합니다.

## 로컬 검사

저장소 루트에서 Node.js 24.14.0으로 워커 의존성을 설치하고 포맷, 린트, 타입, 빌드, 테스트를 실행합니다.

```sh
npm --prefix worker ci
npm --prefix worker run verify
```

다음은 호환성을 유지한 기본 `scan` 경로입니다. 확장 기능과 OS 격리는 위 `assess` 실행법을 사용합니다. `scan`의 Gitleaks 8.30.1은 별도로 설치하고 신뢰하는 절대 경로를 지정합니다.

```powershell
cd worker
$env:WORKER_GITLEAKS_PATH = 'C:\tools\gitleaks.exe'
node dist/cli.js scan .\workflow.json
node dist/cli.js compare-static .\before-report.json .\after-report.json
```

Linux에서는 `WORKER_GITLEAKS_PATH=/absolute/path/to/gitleaks node dist/cli.js scan workflow.json`으로 실행합니다. 경로가 없거나 도구 실행에 실패하면 해당 검사의 누락을 `partial`과 진단 코드로 남깁니다. 보고서의 `analyzed`는 선언된 프로파일의 검사 완료이며 안전 판정이 아닙니다. CLI 종료 코드 0도 경고 없음이나 안전을 의미하지 않습니다. `rules[].coverage`와 `findings`, `diagnostics`를 함께 확인해야 합니다.

[기본 구현 명세](docs/implementation-plan.md), [기본 흐름 지원표](docs/flow-profiles.md), [설정·코드 지원표](docs/settings-profiles.md), [오픈소스 선택과 실제 검증](docs/oss-decisions.md), [기본 10개 항목 검증 기록](docs/static-validation.md)을 보존합니다. `scan` 계약은 `2.0.0`, 통합 `assess` 계약은 별도 `assessmentVersion: 1.0.0`입니다. 실제 팀 API 형식은 프론트·백엔드가 구현된 뒤 #18에서 워커를 맞춥니다.

이전 SQL 계약과 모의 API 경로는 검증 이력과 함께 유지합니다. 다음 명령은 기존 `1.0.0` SQL 계약의 합성 작업을 분석합니다.

```sh
cd worker
node dist/cli.js local fixtures/task.json
```

[지원 표와 팀 연동 계약](docs/contract.md), [실행기와 계약 모의 서버](docs/runner.md), [탐지·재검사 기준](docs/analysis.md), [1차 검증 결과와 재현 명령](docs/validation.md)을 참고하세요.

## 작업 이력

단일 저장소 통합의 기준은 기존 워커의 [검증 커밋 `989b23a`](https://github.com/serendipity-sec/workflow-security-worker/commit/989b23aed9db5df9f0d338c3742c47e0cf969cc4)입니다. 원본 커밋과 PR은 별도 저장소의 이력으로 보존합니다. 워커의 코드, [합성 사례](fixtures/cases.json), [검증 기록](validation/)은 이 디렉터리에서 확인할 수 있습니다.

| Workflow Hub 이슈                                                                              | 기존 워커 PR                                                             | 근거                                                                             |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| [#14 보안 검사 10개 항목 구현·검증](https://github.com/serendipity-sec/workflow-hub/issues/14) | [#1](https://github.com/serendipity-sec/workflow-security-worker/pull/1) | [현재 구현 명세](docs/implementation-plan.md), [이전 SQL 계약](docs/contract.md) |
| [#15 작업 실행기](https://github.com/serendipity-sec/workflow-hub/issues/15)                   | [#3](https://github.com/serendipity-sec/workflow-security-worker/pull/3) | [실행기와 API](docs/runner.md)                                                   |
| [#16 그래프 정규화](https://github.com/serendipity-sec/workflow-hub/issues/16)                 | [#2](https://github.com/serendipity-sec/workflow-security-worker/pull/2) | [그래프 정규화](docs/normalization.md)                                           |
| [#17 탐지와 재검사](https://github.com/serendipity-sec/workflow-hub/issues/17)                 | [#4](https://github.com/serendipity-sec/workflow-security-worker/pull/4) | [탐지·재검사 기준](docs/analysis.md)                                             |
| [#18 검증](https://github.com/serendipity-sec/workflow-hub/issues/18)                          | [#5](https://github.com/serendipity-sec/workflow-security-worker/pull/5) | [검증 결과와 재현 명령](docs/validation.md)                                      |
