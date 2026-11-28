# PR #19 review follow-up — 2026-11-28

대상은 [팀원 리뷰 A~D](https://github.com/serendipity-sec/workflow-hub/pull/19#issuecomment-7185003645), [CodeRabbit Major 22건](https://github.com/serendipity-sec/workflow-hub/pull/19#pullrequestreview-6069204928), [Stop and Error 진단 한도](https://github.com/serendipity-sec/workflow-hub/pull/19#discussion_r4704419284)다. 기존 로컬 대응 커밋을 먼저 대조하고, 최신 main `198f3c2`를 반영했다. 프론트·백엔드의 별도 기능은 추가하지 않았다.

## 팀원 리뷰

| 항목  | 처리와 회귀 근거                                                                                                       |
| ----- | ---------------------------------------------------------------------------------------------------------------------- |
| A1~A2 | 최신 main 통합, 삭제된 OpenAPI 파일 참조 제거, 루트 정책·CI 설명 유지. 원격 CI는 push한 정확한 커밋에서 별도 확인한다. |
| A3    | Docker 검증을 관련 PR과 main push에서 실행하고 이미지 태그를 0.10.0으로 맞춤.                                          |
| B1    | 고정 접두사와 외부 트리거를 거쳐도 외부 입력 신뢰도를 유지.                                                            |
| B2~B4 | unknown spread, each-item Code, credential 객체 투영에서도 비밀정보 후보를 유지.                                       |
| B5~B6 | form/chat/MCP 입력 인증 설정과 HTTP Request Tool의 통신·전송 범위를 추가.                                              |
| C1~C4 | 중요한 네이티브 진단의 자리 확보, CR 줄바꿈, 빈 값·모드별 입력 한도, 필드 경계 Gitleaks 매치 처리.                     |
| D1~D2 | Sink에서 끝나지 않는 반환 경로 탐색, 비활성 노드의 main 통과 연결 유지.                                                |

회귀 사례는 `test/worker-upgrade-0.10.0.test.mjs`에 있다.

## CodeRabbit 주요 지적

| 영역                       | 수정                                                                                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Gitleaks                   | 신뢰하는 텍스트 헤더와 보정한 행 위치로 stdin 형식에 따른 검사 생략 방지.                                                                       |
| Native batch               | NLP와 Python을 순차적인 별도 프로세스로 실행해 stdin·시간·stdout+stderr 예산을 각각 적용. 한 모드 실패가 다른 모드의 확인된 근거를 지우지 않음. |
| Native language            | 사용자 JSON 값을 `String()`으로 강제 변환하지 않음.                                                                                             |
| Node catalog               | operation/resource 타입 검사. 배열·객체가 읽기 프로필로 승격되지 않음.                                                                          |
| Content                    | 마스킹한 표시 위치와 별개로 private 필드 경로를 해시해 탐지를 구분.                                                                             |
| JavaScript aliases         | 이름 있는 함수 표현식의 자기 이름은 함수 내부에만 바인딩.                                                                                       |
| SQL evidence               | 같은 후보를 합칠 때 뒤의 지원 경로·더 강한 근거·출처를 보존.                                                                                    |
| AI model selection         | 비활성 fallback 및 유효하지 않은 모델 연결을 전송 정책 평가에서 제외.                                                                           |
| Set selected fields        | 입력 경로와 실제 출력 이름을 구분해 점 표기 필드의 평탄화를 추적.                                                                               |
| Source annotations         | 각 자식 경로를 한 번 구성하는 트리로 바꿔 후손의 중복 재귀 제거.                                                                                |
| Set binary assignments     | combined 모드의 JSON 메타데이터 가능성을 부재로 확정하지 않고 미확인으로 유지.                                                                  |
| Postgres selectors         | 작업 값 타입 검사로 노드 하나의 잘못된 설정이 독립 검사를 중단하지 않게 함.                                                                     |
| Helper return paths        | 정상 종료하는 함수 경로의 암시적 undefined도 반환 대안에 포함.                                                                                  |
| Egress depth budget        | 깊이 한도에 걸린 하위 트리만 건너뛰고 남은 얕은 전송 필드 검사.                                                                                 |
| SQL remediation            | 대소문자가 다른 필드 참조를 `$json.body.id`로 바꾸지 않고 원래 참조 보존.                                                                       |
| Coverage comparison output | 두 동결 입력 밖의 새 결과 파일과 별도 파생 폴더 사용. 기존 파일 덮어쓰기 거부.                                                                  |
| Public report receipt      | 수집 manifest와 상세 보고서 바이트 SHA-256을 영수증에 연결하고 비교 전에 대조.                                                                  |
| Settings finding budget    | 규칙별 256개 상한을 적용하고 생략한 노드에는 범위 진단 유지.                                                                                    |
| Static comparison          | 겹치는 partial/unsupported 범위가 있으면 넓은 checked 범위만으로 경고 소실을 판정하지 않음.                                                     |
| Policy partial failure     | 기본 검사 실패 상태와 별개로 확장 검사에서 확인한 차단 결정을 유지하고 공개는 hold.                                                             |
| Service tool failure       | 계약상 유효한 analyzed 결과에 도구 오류가 있어도 예외 대신 partial 서비스 결과 제공.                                                            |
| Legacy validation          | worker 검증 모드에 현재 0.1.2 기대값을 적용하고 과거 corpus·영수증은 보존.                                                                      |
| Error payload diagnostics  | 진단 예산을 넘는 Stop and Error 입력도 다른 규칙의 근거를 지우지 않음.                                                                          |

신규 회귀는 `test/pr19-review-regressions.test.mjs`와 `test/native-modes.test.mjs`에 있다. 입력 바이트 스냅샷, 도구 대기 뒤 취소 확인, 잘못된 selector, 내부 노드 ID 예약 접두사, null/undefined 캐시 구분도 점검했다.

Set 해석의 기준은 [고정 n8n 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Set/v2/helpers/utils.ts)다. 업로드된 Code·표현식은 실행하지 않는다.

## 별도 Codex 리뷰에서 추가로 확인한 결함

읽기 전용 전체 리뷰에서 P2 5건을 재현해 수정했다.

- `compare-static`이 128 KiB의 이전 SQL 한도를 쓰던 문제: static 보고서 한도 512 KiB를 적용하고 128 KiB 초과 보고서의 실제 CLI 비교를 검증.
- `/nodes`의 문서 전체 분석 공백이 개별 노드와 겹치지 않던 문제: 전역 공백을 포함한 양방향 비교를 회귀 검사.
- 파일·Airtable·Google Sheets 등의 selector 강제 변환 예외: 문자열만 인정하는 공통 검사를 적용하고 독립 finding 보존 확인.
- 배치가 한 모드의 stderr에 다른 모드 예산까지 제공하던 문제: 서비스 제어기는 모드별 독립 프로세스를 사용. Python 3.12.10의 대량 SyntaxWarning 입력에서 단독·기본 실행 모두 `native_output_limit` 확인. 과거 Python helper batch는 재현을 위해 보존하며 서비스 제어기에서는 호출하지 않음.
- 내용 finding ID 변경에 버전 경계가 없던 문제: secrets/PII 프로필을 1.1.0으로 올려 이전 1.0.0과의 동일 입력 비교도 `inconclusive`로 표시. 원본 과거 영수증은 유지.

## 구조

46개 구현 모듈을 [역할별 7개 디렉터리](layout.md)로 나눴다. CLI `dist/cli.js`는 유지한다. subprocess의 읽기 허용 경로, Docker entrypoint, 테스트·검증 스크립트 및 재귀 artifact 해시 수집을 함께 갱신했다. 빌드 전에 이전 `dist/`를 정리해 이동 전 모듈이 남지 않게 했다. 기존 버전의 JSON 측정 기록은 수정하지 않았다.

## 검증

Node.js 24.14.0에서 실행했다. 원본 출력·로그는 로컬 `evidence-local/pr19-*`에 보존한다.

| 검사                           | 결과                                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------- |
| 루트 check / PR title          | 통과                                                                                  |
| 루트 tooling                   | 6/6 통과. Windows 샌드박스의 symlink 생성 실패 후 동일 테스트를 일반 환경에서 재실행. |
| worker verify                  | format, lint, typecheck, build 및 623/623 테스트 통과; skip 0                         |
| static corpus                  | 27/27. 사실 판정 23개에서 FP 0/FN 0; 의도한 실패·미지원 상태 사례는 별도 포함.        |
| legacy current / worker runner | 12/12, runner mismatches 0                                                            |
| 실제 static tools              | 7/7                                                                                   |
| Docker runtime                 | 평가 8건·파일 9개, 실패 경로 4개, 격리 확인 9개 통과; 새 컨테이너 잔존 없음           |
| Native profile                 | 44/44                                                                                 |
| 공개 정의 25개                 | 오류 0, 도구 75/75 성공. 모두 partial 유지.                                           |
| 통제 수정본 재검사·비교        | 3/3, 원본 보존. 정상 업무 동작 보존은 검증하지 않음.                                  |

공개 정의는 기존 수집 파일의 SHA-256을 확인하고 별도 디렉터리에 복사해 검사했다. 새 수집·외부 LLM 호출·실제 워크플로 실행을 하지 않았다. 공개 표본에서의 결과는 일반 정확도·취약점 개수·안전성 보증이 아니다.

별도 Codex 읽기 전용 전체 리뷰에서 P2 5건을 발견했고 모두 수정했다. 후속 리뷰는 해당 수정과 직접 호출 경로에서 잔여 P1/P2가 없음을 확인했다. 후속 리뷰의 읽기 전용 환경에서는 임시 파일을 쓰는 테스트 2개가 막혔으며, 주 작업 환경의 실제 집중 검사 22/22 및 전체 623/623 실행으로 이를 보완했다. 최초 리뷰 실행의 Windows 앱 연결 오류도 읽기 전용 정책을 유지한 독립 CLI 실행으로 해결했다. 원격 CI는 push한 커밋의 PR Checks에서 별도로 확인한다.

실제 팀 작업 API·배포 연동은 #18이다. 팀원 리뷰의 후속 제안과 CodeRabbit Minor 개선 목록 전체를 완료한 것으로 표시하지 않는다. 영구 공유 Docker 데몬의 중단 작업 복구, 의존성 전이 잠금, 추가 정밀도·지원 범위 확대는 현재 로컬 검증과 구분한다.
