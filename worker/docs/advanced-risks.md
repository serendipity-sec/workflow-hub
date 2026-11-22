# SQL·명령·JavaScript 확장 검사

`src/advanced-risks.ts`는 `value-flow.ts`의 값 모델을 사용해 Set·분기·지원 Merge를 거친 입력이 SQL과 명령·코드 실행 위치에 전달되는지 검사한다. 기존 정밀 SQL 프로필과 검증 기록은 교체하지 않는다. 업로드 SQL·명령·JavaScript를 실행하거나 DB·URL에 접속하지 않는다.

## 오픈소스의 실제 역할

- `node-sql-parser` **5.4.0, Apache-2.0**: SQL을 AST로 파싱한다. PostgreSQL·MySQL·TransactSQL 구문에서 SELECT, INSERT, UPDATE, DELETE, DROP 등 선언된 작업과 매개변수 노드를 구분한다. 파서가 지원하지 않는 구문은 미지원 진단이다.
- Acorn **8.19.0**: Code JavaScript를 AST로 파싱한다. 주석·문자열의 가짜 호출을 제외하고 제한된 변수·모듈 별칭과 호출 인자를 조사한다. JavaScript 실행기나 범용 프로그램 증명기로 사용하지 않는다.
- 자체 구현: n8n 버전·작업 기본값, 표현식 경로, SQL 템플릿·바인딩 구분, 정확한 값에 연결된 조건, 결과 마스킹과 부분 분석 범위를 담당한다.

## SQL 프로필

지원 범위는 Postgres 2.5/2.6/2.8, MySQL 2–2.5, Microsoft SQL 1/1.1/1.2의 `executeQuery`다. Postgres·MySQL resource 생략은 database, 세 노드의 operation 생략은 insert로 취급하여 SQL 실행으로 추정하지 않는다.

`inspectSqlOperation(query, dialect)`는 파싱 상태, 작업 종류, 최상위 문장 수, 값 매개변수 수, AST 해시를 반환한다. 원본 SQL·테이블명은 반환하지 않는다. 작업 정보는 권한·실제 영향의 증명이 아니라 재검토와 버전 비교에 쓰는 구조적 근거다.

SQL 템플릿은 실행하지 않고 고정 자리표시자로 바꿔 구조를 파싱한다. 지원 입력 경로가 확인되면 선언된 경로 근거를 붙인다. 위치가 식별자·따옴표·SQL 구조이거나 해석되지 않으면 후보와 진단을 남긴다. 숫자 IF 방어는 같은 `valueId`, 엄격한 숫자 검사, 지원되는 따옴표 밖 비교 값 위치, 단일 파싱 문장일 때만 해당 좁은 후보를 줄인다. 다른 값의 IF·우회 경로·동적 조건값은 보호로 인정하지 않는다.

n8n의 Query Parameters는 세 프로필 모두 `$N` 형태와 연결해 조사한다. MySQL은 이를 드라이버의 `?`로, Microsoft SQL은 `@pN`으로 변환한다. 업로드 쿼리의 `?`·`@name`이 자동으로 n8n 옵션과 연결된다고 추정하지 않는다. 배열 또는 제한된 배열 표현식으로 제공된 값의 개수와 참조 번호를 비교하지만, 실제 값과 정상 행 결과를 검증했다고 표현하지 않는다.

`:name` 식별자 포맷과 `:raw` 등은 값 바인딩과 구분한다. 따옴표·주석 안의 `$N` 텍스트를 확인된 값 바인딩으로 세지 않는다. 바인딩 설정이 있어도 같은 쿼리에 직접 삽입되는 표현식 경고는 유지한다. Postgres 2.8, MySQL 2.5 이전·이후의 바인딩 처리 차이를 일반적인 안전성 보증으로 합치지 않는다.

## 명령과 Code 프로필

Execute Command 1 및 SSH 1 command 설정에서 고정 실행 기능과 동적 값 전달을 분리한다. Code 1/2 JavaScript에서는 다음 선언을 제한적으로 조사한다.

- `require('child_process')`와 구조 분해·변수 별칭을 거친 exec/execSync/execFile/spawn 계열.
- `eval`, `Function`, `fetch` 및 해당 전역의 직접 별칭.
- http/https/axios/undici 모듈 호출, fs 모듈 호출과 외부 인자 후보.
- 단순 변수 대입을 거친 입력, 조건·반복문에서 남을 수 있는 외부 값의 가능성.

모든 Code 호출은 실제 도달성과 실행 권한을 확인하지 않은 **후보**다. 함수·입력 이름이 가려진 경우 원래 워크플로 입력으로 단정하지 않는다. 복잡한 별칭, 동적 모듈, `.apply`·리플렉션·런타임 재정의, 라이브러리 내부와 일반적인 프로그램 제어 흐름은 완전 분석하지 않으며 `javascript_semantics_partially_analyzed`를 남긴다.

`shell:false`와 argv 배열은 셸 문자열 결합과 구분하지만, 외부 값이 프로그램 옵션으로 해석될 가능성은 별도 후보로 남긴다. 이를 명령 실행 안전 판정으로 표시하지 않는다. Python Code 분석은 별도 프로필의 책임이다.

## 고정 근거와 검증

- [Postgres 쿼리 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Postgres/v2/actions/database/executeQuery.operation.ts).
- [MySQL 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/MySql/MySql.node.ts), [쿼리 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/MySql/v2/actions/database/executeQuery.operation.ts), [2.5 및 기존 바인딩 처리](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/MySql/v2/helpers/utils.ts).
- [Microsoft SQL 노드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Microsoft/Sql/MicrosoftSql.node.ts), [$N 바인딩](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Microsoft/Sql/GenericFunctions.ts).

`test/advanced-risks.test.mjs`의 합성 검증은 작업 종류, 값·식별자 바인딩, 직접 삽입, 정확한 숫자 조건, 명령 경로, 별칭, argv, 주석·문자열, 가려진 입력 이름과 미실행을 확인한다. SQL 파싱 입력은 16 KiB, SQL AST는 4096 노드, Code는 64 KiB·AST 4096 노드로 제한한다. 실제 팀 API, DB 권한, 운영 환경의 정상 동작·공격 성공 여부는 이 결과에 포함하지 않는다.
