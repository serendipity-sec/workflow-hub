# LLM 설명 연결

0.7.0은 OpenRouter의 GLM을 선택적으로 연결한다. 모델은 기존 근거 중 먼저 읽을 항목을 최대 8개 선택하고, 워커가 원래 검사 결과의 고정 한국어 설명으로 문장을 작성한다. 자유로운 모델 문장에 미확인 항목의 검증 완료 주장이 섞일 수 있어, 응답을 참조 ID 선택으로 제한했다. LLM을 흐름 분석의 증명, 미지원 해소, 실제 실행, 개인정보 모델 확장 또는 자동 패치로 사용하지 않는다.

## 설정과 실행

Node.js 24에서 Git에 포함되지 않는 `worker/.env.local`을 준비한다. 키는 파일·환경변수로만 읽고 CLI 인자나 결과에 복사하지 않는다. Docker 분석 컨테이너에는 이 키나 네트워크 권한을 주지 않는다.

```dotenv
OPENROUTER_API_KEY=replace_locally
WORKER_LLM_MODEL=z-ai/glm-5.3-flash
WORKER_LLM_MAX_OUTPUT_TOKENS=1800
```

```powershell
# 전체 새 검사와 서비스용 설명. 이미지 설정은 assessment.md를 따른다.
node --env-file=.env.local dist/cli.js inspect workflow.json --llm

# 이미 생성한 정적 보고서에 서비스 설명만 붙임: 외부 호출 없음
node dist/cli.js present assessment.json

# 정적 보고서에 선택적 모델 설명 추가: 외부 전송 승인 범위에서 실행
node --env-file=.env.local dist/cli.js explain assessment.json
```

`inspect`에서 `--llm`을 생략하면 모델을 호출하지 않는다. 키가 없거나 공급자·응답 검증에 실패해도 정적 보고서와 고정 한국어 설명을 반환한다. `llm.status: unavailable`과 원인을 남기며 모델 실패를 검사 성공이나 보완된 분석으로 취급하지 않는다. HTTP 인증·잔액·속도제한·공급자 오류를 구분하고 자동 재시도하지 않는다.

## 모델과 비용

2026-11-23 OpenRouter 공개 카탈로그의 GLM 실시간 모델 중 `z-ai/glm-5.3-flash`가 입력 $0.0399/백만 토큰, 출력 $0.0784/백만 토큰으로 가장 낮았다. `:batch`는 더 저렴하지만 비동기 일괄 처리이므로 이 실시간 클라이언트에서 선택하지 않았다. 움직이는 `latest` 별칭 대신 모델 ID를 고정한다. 가격은 공급자·시점에 따라 바뀔 수 있다.

요청은 가격순 라우팅, 입력 $0.04/백만·출력 $0.08/백만의 상한, 요청당 고정요금 $0 상한, `require_parameters: true`, `data_collection: deny`를 설정한다. 이 조건에 맞는 제공자가 없으면 실패하며 더 비싼 모델이나 완화한 데이터 정책으로 자동 전환하지 않는다. 필수 추론을 끌 수 없는 제공자가 있어 낮은 추론 수준을 요청하고 추론 원문을 결과에 포함하지 않는다.

최대 24KiB의 설명 문맥, 최대 48개 참조, 기본 출력 1,800토큰(설정 범위 256~4,096), 전체 45초, 응답 96KiB를 제한한다. 근거 일부만 선택한 수는 `omittedReferences`로 표시한다. 전체 검사는 `assessment`와 `serviceReport`에 남는다. 가격 상한은 제공자 단가를 제한하며 토큰 수·플랫폼 청구 방식에 따른 최종 비용은 응답의 사용량과 계정 내역으로 확인한다.

## 전송·신뢰 경계

- 고정 서비스 설명, 범주·위험 후보 수준·주장 종류, 활성 기능 종류·개수, 노드 번호와 임시 참조 ID만 전송한다. 파일 해시와 분석 인스턴스 식별자는 로컬 결과에만 보존한다.
- 원본 JSON·Code·표현식·메모·노드 이름·주소·수신자·원격 데이터·패키지 이름·자격 증명 값은 전송하지 않는다. 알려지지 않은 진단 문자열도 그대로 전송하지 않는다.
- 끝점은 `https://openrouter.ai/api/v1/chat/completions`에 고정하고 리다이렉트를 거부한다. 원본 파일이 모델·API 주소·키·도구·프롬프트를 설정할 수 없다.
- structured output과 로컬 Zod 검증으로 참조 ID 선택만 허용한다. 존재하지 않는·중복·빈 선택, 다른 모델, 잘린 응답, 추가 필드와 모든 자유 문장을 거부한다. 워커가 작성한 최종 문장도 원래 근거와 재계산하여 변조를 거부한다.
- 결과의 `method: model_selection_with_deterministic_text`는 모델이 근거를 고르고 워커가 설명을 작성했다는 뜻이다. `authority: explanation_only`, `affectsVerdict: false`, `requiresHumanReview: true`를 유지한다. 참조는 파일 해시뿐 아니라 `analysisKey`로 같은 하위 정의의 서로 다른 호출까지 구분한다.
- 모델은 정적 판정·severity·coverage·수정 계획·공개 승인을 변경할 수 없다. 공급자의 데이터 정책 설정은 로컬에서 관측한 무보관 증거가 아니다.

## 검증과 승인 범위

모의 전송 테스트는 키 유출 방지, 근거 참조·해시 변조, 네트워크/401/402/429/503, 취소·시간·출력 한도, 잘린 JSON·거짓 완료 문구를 확인한다. 실제 모델 연결은 `validation/verify-llm-synthetic.mjs`의 직접 만든 합성 예제로 별도 검증한다. 여기서 native 도구 결과는 API 어댑터 시험용 모의 자료이며 실제 검사도구 실행으로 보고하지 않는다.

처음 공개 사례 전송은 구체적 범위 승인 부족으로 자동 검토에서 거절됐다. 이후 사용자가 원본·코드·이름·주소·키를 제외한 최소 검사 요약 25개 전송을 명시적으로 승인했고, [기존 15개](../validation/llm-public-15-0.7.0-results.json)와 [추가 10개](../validation/llm-public-10-0.7.0-results.json)의 실제 GLM 호출이 모두 유효한 참조 선택을 반환했다. 보고된 비용 합계는 $0.0045401516다. 자유문장 품질·위험 탐지율·실제 업무 실행을 검증한 결과는 아니다.

이 영수증은 호출 당시의 정적 보고서 해시에 연결된다. 그 15개 중 한 보고서는 Gitleaks 일회성 실패를 포함했으며 LLM은 해당 미완료 판정을 바꾸지 않았다. 이후 정적 분석 수정·재검사는 별도 영수증으로 기록하며 이전 모델 호출을 새 분석의 호출로 계산하지 않는다. 승인한 공개 사례 API 호출은 총 25회이고 동일 사례를 임의 재호출하지 않았다.

공식 근거: [모델 가격](https://openrouter.ai/z-ai/glm-5.3-flash), [구조화 출력](https://openrouter.ai/docs/guides/features/structured-outputs), [가격·데이터 정책 라우팅](https://openrouter.ai/docs/guides/routing/provider-selection). 기존 Acorn, node-sql-parser, Zod를 재사용하며 이 연결에 새 SDK나 실행형 에이전트 도구는 추가하지 않았다.
