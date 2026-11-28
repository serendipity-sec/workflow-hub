# 매핑을 거친 목적지·파일 경로·구조화된 DB 작업

`analyzeDefinitionRisks(context, valueFlow)`는 입력 JSON과 유한 추상값만 조사한다. 네트워크·디스크·SSH·DB에 접근하지 않는다. `N8N_MAPPED_HTTP_DESTINATION`(SSRF), `N8N_FILE_OPERATION_PATHS`(실행/파일), `N8N_DATABASE_OPERATIONS`(SQL)의 프로파일은 1.0.0이다.

HTTP Request 3/4/4.1–4.5와 같은 등록 버전의 생성형 Tool에서는 URL 전체·authority 입력과 고정 origin 뒤의 동적 경로를 구분한다. Code·Set 등의 지원된 변환 뒤 값도 공통 값 흐름으로 추적한다. 고정 로컬·사설 목적지는 검토 후보이며 DNS 해석·리다이렉트·실제 도달성을 확인한 결과가 아니다. 인코딩이나 경로 조건만으로 목적지 허용을 선언하지 않는다.

Read/Write Files 1/1.1은 생략된 operation을 read로 보고 read의 fileSelector, write의 fileName을 선택한다. Read Binary File 1의 filePath와 Write Binary File 1의 fileName도 조사한다. SSH 1은 command/execute의 cwd, file/upload 또는 download의 path를 각각 구분한다. 동적·외부 입력 경로를 후보로 표시하며 파일 바이트·실제 OS 권한·경로 제한·원격 계정 권한은 미확인이다. 저장된 비활성 작업 필드는 현재 작업의 근거로 사용하지 않는다. 이름에 따라 실제 파일을 열거나 원격 호스트에 접속하지 않는다.

Postgres 2.4/2.5/2.6/2.8 및 같은 생성형 Tool의 insert/update/upsert/select/deleteTable을 구조화된 작업으로 구분한다. operation 생략은 insert다. schema/table 선택, columns의 autoMapInputData/defineBelow 값 채널, 삭제 범위의 미확인을 기록한다. 공식 어댑터는 식별자 포맷과 값 채널을 구분하므로 raw SQL 문자열 삽입과 동일한 취약점으로 취급하지 않는다. 동적 테이블 선택은 접근 범위 검토 후보이며, 식별자가 인용된다는 사실이 권한 제한을 증명하지 않는다. DB 스키마에 따른 타입·JSON 변환, 제약, 매칭 열, 실제 영향 행과 결과의 민감도는 별도 근거가 필요하다.

고정 근거는 n8n `86dff76e10efba250a4d3e57760e4eb5d2bbea25`다.

- [디스크 노드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Files/ReadWriteFile/ReadWriteFile.node.ts), [read](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Files/ReadWriteFile/actions/read.operation.ts), [write](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Files/ReadWriteFile/actions/write.operation.ts)
- [SSH 작업과 실행 필드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Ssh/Ssh.node.ts)
- [Postgres insert](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/insert.operation.ts), [update](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/update.operation.ts), [upsert](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/upsert.operation.ts), [select](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/select.operation.ts), [deleteTable](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/deleteTable.operation.ts)
- [Tool 생성과 대응 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/cli/src/tool-generation/ai-tools.ts), [Tool 호출 경계](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/core/src/execution-engine/node-execution-context/utils/create-node-as-tool.ts)

`test/definition-risks.test.mjs`는 합성 JSON으로 분기·기본값·동적 입력·미지원·비활성화·민감값 비노출을 검증한다. 원본 표현식과 워크플로는 실행하지 않는다.
