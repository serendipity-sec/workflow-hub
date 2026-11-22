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

모든 NLP 결과에 영문 모델 범위를 표시한다. 한글·CJK·일부 비라틴 문자 범위는 별도의 지원 밖 진단을 남긴다. 이는 완전한 언어 식별기가 아니며 한국어 개인정보 NER나 모든 언어의 지원을 주장하지 않는다. 파일의 모든 문자열 키·값을 입력으로 받지만 제한을 넘긴 필드와 남은 범위는 진단으로 표시한다. 템플릿의 일반 단어가 인명·지역명으로 분류되는 오탐도 가능하다.

## Python 코드 범위

Code 버전 2의 `python`/`pythonNative`와 `pythonCode` 문자열을 읽는다. import문을 실행하지 않고 모듈 별칭, from-import, 단순 대입의 유한 합류 분석을 수행한다. `_json`, `_input`, `_items`, `_item`, `items`를 입력 후보로 추적한다. Python 입력 API의 실행 환경별 가용성은 이 정적 분석으로 보증하지 않는다.

- `os.system/popen`, 주요 `subprocess` 호출에서 명령 실행 기능과 입력 영향을 구분한다. 리스트 인수·shell=False를 입력 기반 셸 주입으로 자동 분류하지 않는다.
- `eval/exec/compile`과 별칭의 동적 평가, 입력 영향 여부를 구분한다.
- requests/httpx의 직접 요청과 urllib 직접 호출, print/logging, 직접 파일 접근 호출을 찾는다.
- 주석·문자열에 적힌 호출은 호출로 취급하지 않는다. 구문 오류·동적 import·와일드카드 import·분석 제한은 진단이다.

모든 Python 결과는 후보이며 검사 범위는 partial이다. 임의 객체 메서드·렉시컬 재바인딩·분기·함수 간 모든 관계·네이티브 확장·실제 모듈 권한을 완전하게 해석하지 않는다. Python source를 `eval`, `exec`, `compile` 또는 import 대상으로 넘기지 않는다.

## 실행·출력 경계

호출은 `python -I -B <고정 helper> <nlp|python>`이며 shell을 쓰지 않는다. 환경변수는 운영체제의 최소 경로만 상속하며 OMP·OpenBLAS·MKL 스레드는 고정값 1로 제한한다. stdin으로 필드 인덱스·문자열을 전달한다. helper stdout은 고정 코드·인덱스·범위·행 번호·버전만 허용한다. 원문·예외 메시지·stderr·인명·주소·토큰·코드를 결과로 전달하지 않는다. 엄격한 스키마와 입력 필드 대응을 다시 검증한다.

기본 제한은 모드별 60초, stdin 2 MiB, stdout와 stderr 합계 256 KiB다. NLP는 2,048개 필드·총 262,144자·개별 16,384자, Python은 개별 65,536자·AST 10,000개·대입 전파 8회를 제한한다. 취소·시간·출력 제한은 SIGKILL 뒤 close를 기다리고 오류로 반환한다. 도구 부재나 실패를 발견 0개로 바꾸지 않는다. 개발용 로컬 실행과 네트워크·메모리·프로세스를 제한한 배포 컨테이너 검증은 별개다.

## 검증 재현

운영자가 신뢰한 Python 환경의 절대 경로를 `WORKER_PYTHON_PATH`로 제공한 뒤 `worker/`에서 실행한다.

```text
npm run build
node --test test/native-inspection.test.mjs
node validation/verify-native-inspection.mjs validation/native-inspection-results.json
```

[실행 근거](../validation/native-inspection-results.json)는 합성 텍스트·코드의 후보 유형, 오류 상태, 버전·도구·helper·입력 해시만 보존한다. NER 양성·음성·지원 밖 문자, 이메일·카드 형식, Python 별칭·입력·주석·문자열·고정 명령·구문 오류를 검사했다. 코드에 파일 생성문이 있어도 표식 파일이 생기지 않는 비실행 조건을 검증한다. 실제 사용자 코드의 안전성과 일반 탐지 정확도 평가를 대신하지 않는다.

근거: [Presidio 공식 프로젝트](https://github.com/microsoft/presidio), [spaCy 영문 모델](https://spacy.io/models/en#en_core_web_sm), [Python 3.12 AST](https://docs.python.org/3.12/library/ast.html). 특정 실행 API의 의미는 설치된 고정 버전의 소스에서도 확인했다.
