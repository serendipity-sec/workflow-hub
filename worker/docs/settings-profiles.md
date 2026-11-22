# 설정·코드·의존성 정적 프로필

이 문서는 `static-settings.ts`의 네 범주와 `profileVersion: 1.0.0`을 설명한다. 결과는 업로드한 JSON에서 확인한 설정·후보·제한된 경로이며, 실제 실행이나 안전 인증이 아니다. 별도 `scan` 보고서 계약 2.0.0을 사용하며 기존 SQL 계약·검증 기록은 변경하지 않는다.

모든 소스 의미는 n8n 커밋 `86dff76e10efba250a4d3e57760e4eb5d2bbea25`를 기준으로 확인했다. 아래의 `typeVersion`은 노드 형식 버전이며 설치된 n8n·npm 패키지 버전의 증거가 아니다.

| 범주·규칙                                   | 지원하는 형식·필드                                                                                                                                  | 확인하는 내용과 한계                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 요청자 검증 · `N8N_REQUEST_AUTH_SETTINGS`   | Webhook 2, 2.1, 2.2의 `parameters.authentication`; `credentials`의 참조 ID 또는 이름                                                                | 생략 시 `none`, 명시적 `none`, `basicAuth`·`headerAuth`·`jwtAuth` 설정을 구분한다. 인증을 선택했으나 해당 자격증명 참조가 없으면 부분 분석이다. 자격증명 유효성·앞단 인증·실제 활성화는 확인하지 않는다. 다른 인증 모드·버전은 미지원이다.                                                                                                             |
| 통신 설정 · `N8N_TRANSPORT_SETTINGS`        | HTTP Request 3, 4, 4.1–4.5의 `parameters.url`, `parameters.options.allowUnauthorizedCerts`                                                          | 정적인 HTTP URL, URL 내 인증정보, 인증서 검증 해제를 표시한다. 동적 URL·잘못된 옵션·다른 버전은 미확인으로 남기면서 독립적으로 읽은 설정은 보존한다. HTTPS 표기만으로 실제 TLS·프록시·DNS·리다이렉트 동작을 확인했다고 하지 않는다.                                                                                                                    |
| 명령·코드 · `N8N_EXECUTABLE_CONTENT`        | Execute Command 1의 `command`; SSH 1의 `resource=command`, `operation=execute`, `command`; Code 1·2의 JavaScript `jsCode`                           | 고정 명령 기능과 동적 명령 표현식을 구분한다. 바로 연결된 지원 Webhook의 단일 본문 필드가 명령 표현식에 들어가는 제한된 경우만 입력 경로로 표시한다. JavaScript는 Acorn으로 `eval`, `Function`, 특정 `require`·프로세스 실행 구문을 후보로 찾는다. Python, 해석할 수 없는 구문·버전은 미확인이다. 셸 동작·변수 바인딩·샌드박스 권한은 검증하지 않는다. |
| 의존성·권한 · `N8N_DEPENDENCY_CAPABILITIES` | Execute Command 1, SSH 1, Read Binary File 1, Write Binary File 1, Read/Write File 1·1.1, Code 1·2, Execute Workflow 1·1.1–1.4; 노드 종류와 AI 연결 | 로컬 명령·원격 셸/파일·로컬 파일·사용자 코드·하위 워크플로·AI 도구 기능의 선언을 표시한다. 커뮤니티/외부 노드는 실제 패키지 버전·내용 미확인으로 남긴다. 하위 워크플로가 인라인 문자열이어도 재귀 분석하거나 실행하지 않는다. 설치 패키지의 악성 여부·실제 계정 권한·AI 승인 통제는 추정하지 않는다.                                                   |

의존성 목록에서 Webhook 2·2.1·2.2, HTTP Request 3·4·4.1–4.5, Postgres 2.8, IF 2.2, Respond to Webhook 1·1.1–1.5는 알려진 기본 노드 선언으로 분류한다. 이는 해당 노드의 모든 기능을 분석했다는 뜻이 아니다. 나머지 기본 노드 또는 미지원 버전은 의존성 프로필 미검토로 남긴다.

JavaScript 파서는 n8n의 비동기 실행 래퍼에 맞춰 최상위 `return`과 `await` 구문을 읽는다. 코드를 실행하지 않으며 최대 50,000개 AST 객체를 순회한다. 주석·문자열 안의 실행 함수 이름은 실행 구문으로 세지 않는다. 계산된 별칭, 복잡한 스코프, 모든 모듈 호출을 해석하는 일반 코드 분석기는 아니다. `console`에 전체 `$json` 또는 지원하는 `$input` 호출을 전달하는 구문은 공통 AST 도우미가 표시하고, 실제 결과는 별도 `output` 규칙에서 후보로 보고한다.

각 규칙은 노드별 `checked`·`partial`·`unsupported`·`not_applicable` 범위를 남긴다. 미지원 노드 하나 때문에 다른 노드에서 읽은 사실을 없애지 않는다. 비활성 노드의 설정도 보존하고 비활성 상태를 가정에 표시하지만 실행 경로로 확정하지 않는다. `checked`는 선언한 프로필 검사가 끝났다는 뜻이며 안전 판정이 아니다.

보고서에는 원문 코드·명령·URL·호스트·자격증명 이름을 복사하지 않는다. 근거는 고정 코드, 노드 키, 알려진 JSON 구조 위치로 표시한다. 임의 속성 이름이나 숫자로 된 객체 키는 민감정보일 수 있으므로 안전한 상위 위치로 줄인다. 실제 배열 인덱스만 유지한다. ID는 규칙·노드 키·필드 역할에서 만들며 비밀값이나 개인정보 값의 해시를 사용하지 않는다.

비교 결과는 이 프로필에서 관측한 항목의 지속·추가·미관측·판단 유보를 뜻한다. 모든 목적지·인증 의미의 변화나 수정 후 업무 동작 보존을 확인하는 비교가 아니다. 실제 팀 API와 실행 환경에 맞춘 연동은 프런트엔드·백엔드 준비 후 별도로 진행한다.

검증은 `test/static-settings.test.mjs`와 `test/static-contract.test.mjs`의 합성 입력으로 수행한다. 인증 기본값/미지원 값, TLS 설정/동적 값, 제한된 명령 경로와 반례, JavaScript 주석·문자열·비동기 구문, 미지원 언어, 하위 워크플로·AI·패키지 한계, 원문 비노출, JSON 구조 제한을 검사한다.

고정한 공식 소스:

- [Webhook 인증 필드와 기본값](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/description.ts), [Webhook 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/Webhook.node.ts)
- [HTTP Request 버전 매핑](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/HttpRequest.node.ts), [인증서 검증 옵션의 적용](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/V3/HttpRequestV3.node.ts)
- [Execute Command](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ExecuteCommand/ExecuteCommand.node.ts), [SSH](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Ssh/Ssh.node.ts)
- [Code 언어·버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Code/Code.node.ts), [JavaScript 비동기 래퍼](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/%40n8n/task-runner/src/js-task-runner/js-task-runner.ts)
- [Read Binary File](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ReadBinaryFile/ReadBinaryFile.node.ts), [Write Binary File](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/WriteBinaryFile/WriteBinaryFile.node.ts), [Read/Write File](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Files/ReadWriteFile/ReadWriteFile.node.ts)
- [Execute Workflow](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/ExecuteWorkflow/ExecuteWorkflow/ExecuteWorkflow.node.ts)
