# 네이티브 개인정보·Python 정적 검사

컨트롤러의 `runNativeInspection(context, options)`는 신뢰된 Python 실행 파일과 저장소의 고정 helper만 호출한다. `analyzeNativeInspection`은 마스킹된 도구 결과를 `pii`, `code_execution`, `output` 규칙으로 변환한다. 일반 제한 분석 자식 안에서 외부 프로그램을 실행하지 않는다. 실제 워크플로·업로드 Python·표현식·가져온 모듈은 실행하지 않는다.

| 구성              | 고정 구성                | 역할                                                      |
| ----------------- | ------------------------ | --------------------------------------------------------- |
| Presidio Analyzer | 2.2.366, MIT             | 개인정보 인식 결과를 유형·필드 인덱스로 반환              |
| spaCy             | 3.8.18, MIT              | 설치된 영문 모델의 언어 처리                              |
| en_core_web_sm    | 3.8.0, MIT               | 영문 PERSON·LOCATION 후보                                 |
| Python AST        | 검증 환경 Python 3.12.10 | Python 코드를 `ast.parse`한 뒤 호출·별칭·입력 영향을 조사 |

라이선스와 버전은 설치 배포물의 metadata로 확인했다. Python 실행 버전은 결과에 기록한다. NLP 의존성과 모델 버전은 helper가 정확히 확인하며, 맞지 않거나 없으면 오류다. 실행 중 패키지·모델 다운로드나 외부 PII 서비스 호출은 없다. 자동 다운로드를 포함하는 `SpacyNlpEngine.load()`는 호출하지 않고 설치된 모델을 직접 읽는다.

## 개인정보 범위

Presidio의 PERSON, LOCATION, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IP_ADDRESS 중 점수 0.5 이상인 후보만 받는다. 영문 인명·지역명과 지원 형식의 후보이며 실제 개인의 신원·주소·정보 유효성을 확인한 결과가 아니다. 카드·이메일의 합성 양성과 일반 문장의 음성을 검증했다. 한국 휴대전화 형식 검사는 별도 validator.js 규칙도 유지한다.

모든 NLP 결과에 영문 모델 범위를 표시한다. 한글·CJK·일부 비라틴 문자 범위는 별도의 지원 밖 진단을 남긴다. 이는 완전한 언어 식별기가 아니며 한국어 개인정보 NER나 모든 언어의 지원을 주장하지 않는다. 제한을 넘긴 필드와 남은 범위는 진단으로 표시한다. 템플릿의 일반 단어가 인명·지역명으로 분류되는 오탐도 가능하다.

`PRESIDIO_PII_CANDIDATES` 프로필 1.2.0은 형식 검사와 인명·지역명 검사의 범위를 구분한다. 이메일·전화·카드·IP 형식은 모든 문자열 키·값을 계속 검사한다. PERSON·LOCATION은 구조 키, 노드 ID·타입·표시 이름, 연결 정보, 알려진 형식 선택값, IF 연산자·Set 대상 필드 이름과 코드·SQL·명령·IMAP 검색 문법 전체에는 적용하지 않고 `nlp_metadata_formats_only` 또는 `nlp_program_formats_only`로 범위를 표시한다. 코드와 검색식 안의 인명을 완전히 검사했다는 뜻이 아니다. 프로그램 안에서 발견한 형식 후보에는 `format_candidate_in_program_text`와 `program_text_is_not_runtime_output` 근거를 붙인다. 코드 리터럴의 이메일을 숨기지 않되, 그 문구가 실행 결과나 실제 개인정보라고 주장하지 않는다.

메모와 일반 데이터 값은 인명·지역명 검사를 유지한다. `pinData`의 실제 값과 JSON 문자열 안의 문자열 값도 검사하며, JSON 문자열에서 발견한 후보의 범위는 원본 필드 전체로 표시한다. JSON 키를 인명으로 처리하지 않는다. 템플릿은 `{{ ... }}` 표현식 밖의 문자 부분을 검사하고 `nlp_template_literal_text_only`를 남긴다. 표현식 내부의 인명 리터럴을 완전하게 해석하지 않는다. 대괄호로 감싼 일반 문장을 JSON 오류로 버리지 않는다.

문서·문자 템플릿에서 JSON, Gmail, PostgreSQL 등 정확히 일치하는 기술 토큰은 인명·지역명 후보에서 제외하며 필터 진단을 남긴다. 이 필터는 `pinData`와 파싱한 JSON 데이터 값에는 적용하지 않는다. 짧다는 이유로 인명을 제외하지 않는다. 합성 검증에서 두 글자 이름, 메모 속 이름, JSON 값, 템플릿 문자 부분의 이름을 실제 모델로 확인했다. 같은 짧은 이름도 문맥에 따라 모델이 놓칠 수 있으므로 일반 인명 탐지율을 보증하지 않는다.

## Python 코드 범위

Code 버전 2의 `python`/`pythonNative`와 `pythonCode` 문자열을 읽는다. import문을 실행하지 않고 모듈 별칭, from-import, 단순 대입의 유한 합류 분석을 수행한다. `_json`, `_input`, `_items`, `_item`, `items`를 입력 후보로 추적한다. Python 입력 API의 실행 환경별 가용성은 이 정적 분석으로 보증하지 않는다.

- `os.system/popen`, 주요 `subprocess` 호출에서 명령 실행 기능과 입력 영향을 구분한다. 리스트 인수·shell=False를 입력 기반 셸 주입으로 자동 분류하지 않는다.
- `eval/exec/compile`과 별칭의 동적 평가, 입력 영향 여부를 구분한다.
- requests/httpx의 직접 요청과 urllib 직접 호출, print/logging, 직접 파일 접근 호출을 찾는다.
- 주석·문자열에 적힌 호출은 호출로 취급하지 않는다. 구문 오류·동적 import·와일드카드 import·분석 제한은 진단이다.

모든 Python 결과는 후보이며 검사 범위는 partial이다. 임의 객체 메서드·렉시컬 재바인딩·분기·함수 간 모든 관계·네이티브 확장·실제 모듈 권한을 완전하게 해석하지 않는다. Python source를 `eval`, `exec`, `compile` 또는 import 대상으로 넘기지 않는다.

## 실행·출력 경계

호출은 `python -I -B <고정 helper> <nlp|python>`이며 shell을 쓰지 않는다. 환경변수는 운영체제의 최소 경로만 상속하며 OMP·OpenBLAS·MKL 스레드는 고정값 1로 제한한다. stdin으로 필드 인덱스·문자열과 컨트롤러가 정한 인명 검사 범위를 전달한다. helper stdout은 고정 코드·인덱스·범위·행 번호·버전만 허용한다. 원문·예외 메시지·stderr·인명·주소·토큰·코드를 결과로 전달하지 않는다. 엄격한 스키마와 입력 필드 대응을 다시 검증한다.

기본 제한은 모드별 60초, stdin 2 MiB, stdout와 stderr 합계 256 KiB다. NLP는 2,048개 필드·총 262,144자를 제한한다. 이 예산 안의 장문은 호출당 최대 16,384자, 앞 구간과 256자 중첩으로 나눈다. 구간 끝의 가까운 공백을 우선하고 원본 위치를 복원한다. 말미를 버리지 않지만 구간보다 긴 문맥의 정확도는 보장하지 않으므로 `nlp_chunked_text_profile`을 남긴다. 합성 검사에서 경계와 말미의 이메일·인명 보존 및 총예산 초과 시 partial을 확인한다. 예산을 초과하는 필드는 `native_input_scope_limit`으로 표시하고 검사하지 않는다. Python은 개별 65,536자·AST 10,000개·대입 전파 8회를 제한한다. 취소·시간·출력 제한은 SIGKILL 뒤 close를 기다리고 오류로 반환한다. 도구 부재나 실패를 발견 0개로 바꾸지 않는다. 개발용 로컬 실행과 네트워크·메모리·프로세스를 제한한 배포 컨테이너 검증은 별개다.

## 검증 재현

단위 검사는 Python 설치 여부와 무관하게 전부 실행한다. 실제 모델의 장문 회귀 검사는 조건부 skip 대신 정식 Docker 검증 단계로 옮겼다. `WORKER_DOCKER_PATH`는 신뢰한 Docker 실행 파일의 절대 경로, `WORKER_ASSESSMENT_IMAGE`는 빌드한 이미지의 불변 `sha256:` ID여야 한다.

```text
npm run build
node --test test/native-inspection.test.mjs
node validation/verify-native-profile.mjs evidence-local/native-profile-results.json
```

Docker 프로필 검증은 기존 18개 조건과 `contextSensitiveShortNameObserved` 기록을 유지한다. 장문 구간 경계·말미의 이메일과 인명, command·metadata의 형식 검사/NER 구분 11개, 단일 필드와 여러 필드 합계의 262,144자 예산 초과·미확인·정리 검증 15개를 더해 총 44개 기능 조건을 기록한다. 모델·도구 부재나 Docker 실패는 이 단계를 실패시키며 건너뛰지 않는다. JSON 스키마·입력 해시·컨테이너 경계 확인도 함께 수행한다.

예산 초과 검사는 정상 파일의 256 KiB 제한보다 큰 네이티브 입력이 필요하므로 동일 이미지·격리 설정에서 고정 합성 필드만 직접 네이티브 컨트롤러에 전달한다. 단일 과대 필드는 발견 0개와 scope-limit/partial, 여러 필드의 합계 초과는 첫 필드 말미 발견 보존과 다음 필드의 명시적 미검사를 확인한다. 임의 워크플로·Code는 실행하지 않는다. 요약 결과 옆의 `.assessment.raw.json` 파일은 합성 assessment의 원본 보고서이며, 요약에 해당 SHA-256을 남긴다. 이전 로컬 Python 검증 기록을 덮어쓰지 않는다.

개발용 Python 검증은 신뢰한 Python 절대 경로를 `WORKER_PYTHON_PATH`에 제공하고 `node validation/verify-native-inspection.mjs <새 결과 경로>`로 별도 실행할 수 있다.

[실행 근거](../validation/native-inspection-results.json)는 합성 텍스트·코드의 후보 유형, 오류 상태, 버전·도구·helper·입력 해시만 보존한다. NER 양성·음성·지원 밖 문자, 이메일·카드 형식, Python 별칭·입력·주석·문자열·고정 명령·구문 오류를 검사했다. 코드에 파일 생성문이 있어도 표식 파일이 생기지 않는 비실행 조건을 검증한다. 실제 사용자 코드의 안전성과 일반 탐지 정확도 평가를 대신하지 않는다.

근거: [Presidio 공식 프로젝트](https://github.com/microsoft/presidio), [spaCy 영문 모델](https://spacy.io/models/en#en_core_web_sm), [Python 3.12 AST](https://docs.python.org/3.12/library/ast.html). 특정 실행 API의 의미는 설치된 고정 버전의 소스에서도 확인했다.

IMAP 검색식의 JSON 파싱·검색 문법 사용은 [고정 n8n EmailReadImap V2 소스](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/EmailReadImap/v2/EmailReadImapV2.node.ts)에 근거한다. 형식 검사는 유지하며 검색 문자열을 임의 코드로 실행하지 않는다.
