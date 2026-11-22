# Workflow Security Worker

Workflow Hub의 `worker/`에서 n8n JSON을 정적으로 분석합니다. 결과에 적용된 규칙과 분석 범위를 기록합니다. 설계 기준은 [보안 설계](../docs/SECURITY_DESIGN.md)와 [Workflow Hub PR #7](https://github.com/serendipity-sec/workflow-hub/pull/7)입니다.

## 로컬 검사

저장소 루트에서 Node.js 24.14.0으로 워커 의존성을 설치하고 포맷, 린트, 타입, 빌드, 테스트를 실행합니다.

```sh
npm --prefix worker ci
npm --prefix worker run verify
```

빌드 후 워커 디렉터리에서 합성 파일을 분석할 수 있습니다.

```sh
cd worker
node dist/cli.js local fixtures/task.json
```

[지원 표와 팀 연동 계약](docs/contract.md), [실행기와 계약 모의 서버](docs/runner.md), [탐지·재검사 기준](docs/analysis.md), [1차 검증 결과와 재현 명령](docs/validation.md)을 참고하세요.

## 작업 이력

단일 저장소 통합의 기준은 기존 워커의 [검증 커밋 `989b23a`](https://github.com/serendipity-sec/workflow-security-worker/commit/989b23aed9db5df9f0d338c3742c47e0cf969cc4)입니다. 원본 커밋과 PR은 별도 저장소의 이력으로 보존합니다. 워커의 코드, [합성 사례](fixtures/cases.json), [검증 기록](validation/)은 이 디렉터리에서 확인할 수 있습니다.

| Workflow Hub 이슈                                                                 | 기존 워커 PR                                                             | 근거                                        |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------- |
| [#14 지원 범위와 계약](https://github.com/serendipity-sec/workflow-hub/issues/14) | [#1](https://github.com/serendipity-sec/workflow-security-worker/pull/1) | [지원 범위와 계약](docs/contract.md)        |
| [#15 작업 실행기](https://github.com/serendipity-sec/workflow-hub/issues/15)      | [#3](https://github.com/serendipity-sec/workflow-security-worker/pull/3) | [실행기와 API](docs/runner.md)              |
| [#16 그래프 정규화](https://github.com/serendipity-sec/workflow-hub/issues/16)    | [#2](https://github.com/serendipity-sec/workflow-security-worker/pull/2) | [그래프 정규화](docs/normalization.md)      |
| [#17 탐지와 재검사](https://github.com/serendipity-sec/workflow-hub/issues/17)    | [#4](https://github.com/serendipity-sec/workflow-security-worker/pull/4) | [탐지·재검사 기준](docs/analysis.md)        |
| [#18 검증](https://github.com/serendipity-sec/workflow-hub/issues/18)             | [#5](https://github.com/serendipity-sec/workflow-security-worker/pull/5) | [검증 결과와 재현 명령](docs/validation.md) |
