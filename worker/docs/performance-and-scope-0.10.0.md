# 0.10.0 런타임 성능 개선과 정적 범위 확장

[#14](https://github.com/serendipity-sec/workflow-hub/issues/14)의 `feat/14-integrate-security-worker` 브랜치에서 진행했다. 기존 0.8.0·0.9.0 코드 호환성과 검증 기록을 보존하고, 격리 컨테이너 내부의 실행 경합·중복 추론 병목 제거와 선언형 노드·표현식·서비스 도달성 지표를 보완했다. 실제 팀 API 연결은 [#18](https://github.com/serendipity-sec/workflow-hub/issues/18)의 후속 범위다.

## 1. 런타임 병목 제거와 병렬 안정화

기존 Docker 샌드박스 보안 경계(`--network=none`, `--read-only`, `uid=65532`, `--memory=1g`, `--pids-limit=96`, `--cpus=1`)는 완화하지 않고 그대로 유지했다.

- **Go·Python 스레드 및 동시 실행 경합 제거:** `Dockerfile.assessment-runtime`, `Dockerfile.assessment`, `src/gitleaks.ts`에 `GOMAXPROCS=1`과 `MKL_NUM_THREADS=1`을 고정하고, 1-CPU 컨테이너 내부에서 `Promise.all`로 경쟁하던 Gitleaks와 Python 검사를 순차 실행(`src/assessment-entry.ts`)으로 전환했다. Gitleaks 기본 타임아웃 여유(15초)와 동일 바이너리 `stat` 기반 버전 확인 캐시도 추가했다.
- **Python 단일 프로세스 배치(`batch`) 실행:** 기본 `nlp` + `python` 검사 시 Python 인터프리터를 두 번 기동하던 구조를 단일 `batch` 호출(`src/native-inspection.ts`, `tools/native-inspection.py`)로 통합하고 모드별 출력 바이트 상한도 개별 검증한다. 개별 모드 호출과 2MiB 초과 시 폴백 경로는 그대로 유지한다.
- **Presidio/spaCy 중복 추론 제거:** `@`, 유니코드 숫자(`\d`), 콜론(`:`)이 전혀 없는 순수 영문·메타데이터 청크에서는 매칭 불가능한 형식 스캔 호출을 건너뛰고, 고유 청크별 `NlpArtifacts`와 엔티티 매칭 결과를 상한(512개) 안에서 메모이제이션해 동일 텍스트에 대한 이중 spaCy 추론을 제거했다. 탐지 오프셋과 진단 코드는 기존 프로필과 동일하다.

## 2. 노드 효과 카탈로그·표현식·서비스 도달성 보완

- **선언형 노드 카탈로그(`src/node-catalog.ts`):**
  - 읽기 전용 매개변수 AST 게이트(`isReadOnlyParameterTree`) 아래에서만 안전한 로컬 통과·병합 프로필(`removeDuplicates` 기본 모드, `sort` simple/random, `filter` 2.x, `merge` 2.x append)을 허용한다. `sort`의 `code` 모드, `removeOtherFields: true`, 이력 기반 중복 제거, 함수 호출·변경 표현식 등 부수 효과·변형 모드는 제외해 `opaque_node_effects`를 유지한다.
  - 외부 트리거(`slackTrigger`, `whatsAppTrigger`, `chatTrigger`), 읽기 전용 커넥터(`supabase` row 조회, `youTube`, `zendesk`, `box`, `dropbox` 목록/검색, `googleDrive` 목록/검색/메타 조회, `rssFeedRead`, `discord` 메시지 조회, `slack` 조회, `telegram` 채팅 조회), 명시적 `html` 추출(`extractHtmlContent`) 프로필과 `src/assessment-summary.ts`의 기능 분류를 확장했다.
- **표현식 및 Code 제어 흐름(`src/value-flow.ts`, `src/bounded-code.ts`):**
  - 논리 `&&`, 단항(`!`, `+`, `-`, `typeof`, `void`), 산술·비교 이항 연산자, 정규식 리터럴, `new Date(...)`·`Date.now()`·`$now`/`$today` 메서드 체인, `Math.*`, `Array.isArray`, URI 인코딩/디코딩, 런타임 메타데이터(`$workflow`, `$execution`, `$itemIndex`, `$runIndex`), `$('Node').last().json` 참조를 지원한다. 포맷·생성자 인자와 후속 프로퍼티 투영에서도 민감도 후보와 출처를 그대로 보존한다.
  - `for...of` 루프 내부의 어휘 스코프 격리 블록(`BlockStatement`), 분기(`if`/`try`) 안팎의 라벨 없는 `continue`/`break` 상태 병합, `++`/`--` 갱신식을 지원한다.
- **서비스 리포트 도달성 지표(`src/service-report.ts`):**
  - `0.10.0` 이후 `serviceScope`에 활성 보안 Sink(`write`, `send`, `execute`, `respond`, `unknown`, `lastNode`·`chatTrigger`·`executeWorkflowTrigger` 반환 체인, `stopAndError`, `rssFeedRead`, 하위 워크플로 호출 및 인증·출력·통신·의존성 경계)로 이어지는 공백 수(`sinkReachableGapCount`)와 고립 경로 공백 수(`isolatedGapCount`)를 분리해 제공한다. 표현식·비표준 코드 필드의 미연결 직접 참조(`direct_reference_unconnected`)가 있으면 전체를 보수적으로 Sink 도달 가능으로 계산한다. 과거 `0.9.0` 보고서는 기존 `serviceScope` 형태를 그대로 재현한다.

## 3. 동일 공개 원본 25개 실측 비교 (0.9.0 → 0.10.0)

검증 이미지: `sha256:fb0131d3b3fb53708c9cab724213f6bd89e14d95252ec2e8ea28fe242169a0a5`. 워크플로·표현식·Code는 실행하지 않았다.

| 지표                                                     |                      0.9.0 |                  0.10.0 | 비고                          |
| :------------------------------------------------------- | -------------------------: | ----------------------: | :---------------------------- |
| 25개 순차 총 소요 시간                                   |                 397,582 ms |           **93,371 ms** | **4.26배 향상 (76.5% 단축)**  |
| 건당 평균 소요 시간                                      |                  15,903 ms |            **3,735 ms** | 최소 2,818 ms / 최대 7,097 ms |
| 순차 도구 실행 성공                                      |                      75/75 |               **75/75** | 입력·도구 오류 0건            |
| 15개 병렬 스트레스 (`concurrency=5`)                     | `15403` Gitleaks 실패 이력 | **45/45 성공 (오류 0)** | 전체 벽시계 시간 17,306 ms    |
| 미확인 노드 기능 포함 샘플 (`unknown_node_capabilities`) |                      13/25 |                **3/25** | 외부 커뮤니티 노드 등만 유지  |
| 미분류 진단 코드 (`unclassified`)                        |                          0 |                   **0** | 전체 원인 분류 유지           |

채팅 트리거(`chatTrigger@1.1`)의 외부 신뢰도(`trust: "external"`)가 연결되면서 도구 연결 AI Agent에서 `ai_external_prompt_may_influence_tool_selection` 후보가 정탐으로 전환됐다.

## 4. 검증 근거와 남는 경계

- Node 24.14.0에서 워커 format/lint/typecheck/build 및 **595/595 단위·회귀 테스트**, 루트 `npm run check`·도구 **6/6 테스트** 통과.
- 정적 합성 코퍼스 **27/27**, legacy SQL 코퍼스 **12/12** 통과.
- 실제 Docker 런타임·격리 검증([assessment-runtime-0.10.0-results.json](../validation/assessment-runtime-0.10.0-results.json)), 개인정보·코드 네이티브 대조 **44개**([native-profile-0.10.0-results.json](../validation/native-profile-0.10.0-results.json)), 공개 원본 **15+10개**([public-assessment-0.10.0-results.json](../validation/public-assessment-0.10.0-results.json), [public-additional-0.10.0-results.json](../validation/public-additional-0.10.0-results.json)), 통제 수정본 재검사 **3쌍**([public-service-path-0.10.0-results.json](../validation/public-service-path-0.10.0-results.json)), 성능·범위 비교 요약([performance-and-scope-0.10.0-results.json](../validation/performance-and-scope-0.10.0-results.json))을 기록했다.
- 일반 `for`/`while`/`switch`·비동기 로컬 헬퍼·복잡한 동적 SQL·외부 패키지 내부·실제 런타임 권한과 네트워크 환경은 여전히 미확인(`partial` / `review_required`)으로 남긴다. 한국어 개인정보 모델 확대, 실제 워크플로 실행 기능 보존 시험, 새 외부 LLM 호출, 팀 백엔드 API 연동은 이번 범위에 포함하지 않았다.
