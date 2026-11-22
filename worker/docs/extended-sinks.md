# 전송·응답·로그 데이터 검사

`analyzeExtendedSinks(context, valueFlow, evidence?)`는 `egress`와 `output`에 규칙을 추가한다. 원본 JSON과 표현식은 실행하지 않는다. 전송의 존재, 지원 경로의 데이터 출처, 운영자가 제공한 정책과의 불일치를 구분한다. 전송 또는 개인정보 후보가 있다는 이유만으로 악의나 실제 유출을 확정하지 않는다.

현재 확장 전송·출력 규칙의 `profileVersion`은 1.2.0이다.

Telegram의 `replyKeyboard`·`inlineKeyboard` 생략은 기본 빈 객체로 처리해 필수 필드 누락으로 표시하지 않는다. 알려진 rows/row/buttons 구조의 text·추가 필드 스칼라·web_app.url을 개별 표현식으로 검사한다. 최대 128행·행당 128버튼·총 256필드를 제한하며, 지원 밖 객체·제한 초과는 진단과 데이터 등급 unknown을 유지한다. 변환·옵션의 미확인 범위인 `message_reply_markup_unverified`도 유지한다. `chatId`·활성 본문 등 실제 필수 입력의 누락은 별도로 남긴다.

| 노드·지원 버전                       | 작업                                            | 확인하는 필드                                              |
| ------------------------------------ | ----------------------------------------------- | ---------------------------------------------------------- |
| Send Email 1, 2, 2.1                 | v1 고정 발송, v2 email/send                     | toEmail, CC/BCC, subject, 버전별 활성 text/html            |
| Gmail 2, 2.1, 2.2                    | message/send                                    | sendTo, CC/BCC, subject/message                            |
| Slack 2–2.7의 등록 버전              | message/post, schedule                          | channel/user locator, text, blocksUi, attachments          |
| Telegram 1, 1.1, 1.2                 | message/sendMessage, sendDocument               | chatId, text 또는 caption, 활성 file 참조·fileName         |
| HTTP Request 3, 4–4.5의 등록 버전    | 활성 요청                                       | URL, 켜진 query/header/body의 keypair·JSON·raw·form 필드   |
| Respond to Webhook 1–1.5의 등록 버전 | firstIncomingItem, allIncomingItems, json, text | 전체 입력 또는 responseBody                                |
| Webhook 2, 2.1, 2.2                  | lastNode 응답                                   | 도달 가능한 마지막 노드의 결과와 고정 responsePropertyName |
| Code 1, 2 JavaScript                 | console의 직접 메서드 호출                      | 정적 AST로 찾은 인수와 해당 표현식의 출처                  |

추가 커넥터 프로필:

| 노드·버전                      | 지원 작업                                        | 전송 데이터·대상                                                   |
| ------------------------------ | ------------------------------------------------ | ------------------------------------------------------------------ |
| Notion 2, 2.1, 2.2             | databasePage/create·update, page/create          | 제목, 속성 키의 타입에 따라 선택되는 값, 아이콘, databaseId/pageId |
| Google Docs 1, 2               | document/create, update의 text/insert·replaceAll | 생성 제목·폴더, 삽입 텍스트·찾기 문자열·바꿀 문자열, 문서 ID       |
| WhatsApp 1, 1.1                | message/send, text                               | textBody와 recipientPhoneNumber                                    |
| 직접 Google Gemini 1, 1.1, 1.2 | text/message                                     | messages.values[].content, options.systemMessage, 선택된 도구 설정 |

Notion은 실제 구현처럼 속성 `key`의 마지막 `|` 뒤 타입으로 전송 필드를 선택한다. 비활성 필드의 값은 전송으로 취급하지 않는다. 블록·원격 첨부·알 수 없는 속성 선택은 부분 분석 진단으로 남긴다. 대상 ID와 실제 문서 접근 권한은 별개이며 URL locator의 ID 해석과 Google Docs URL의 문서 ID 변환은 미확인으로 남긴다. Google Docs의 다른 수정 작업, WhatsApp의 템플릿·미디어·연락처 작업, 미등록 버전은 지원했다고 표시하지 않는다. WhatsApp 기본 작업은 `sendTemplate`이므로 operation 생략을 일반 텍스트 발송으로 추정하지 않는다.

Gemini 서버 주소는 실제 n8n 구현에서 자격 증명의 host 설정으로 바뀔 수 있다. 따라서 JSON만으로 기본 Google 서버가 승인된 목적지라고 추정하지 않고 `provider_endpoint_from_credentials_unverified`를 남긴다. 모델 입력은 추적하지만 목적지 정책 판단은 미확인이다. 모델의 저장·이용 정책, 제공자 내 도구 실행과 실제 수신 권한도 별도 확인 조건이다. 운영자 정책의 sink 종류는 `notion`, `google_docs`, `whatsapp`, `gemini`이며 자동 승인이나 악성 판정을 뜻하지 않는다.

Gmail message/get·getAll은 읽기 기능으로 구분한다. 발송 기능이나 미지원 발송 작업 경고를 만들지 않으며, 읽은 응답 데이터의 분류는 별도 미확인 진단으로 남긴다.

Send Email v1은 top-level `ccEmail`·`bccEmail`을 사용하며 text/html 두 본문을 함께 전달한다. fromEmail·replyTo도 전송 메타데이터로 분석하고 top-level attachments의 실제 내용은 미확인으로 남긴다. v2는 options의 CC/BCC를 사용하며 기본 형식은 버전 2에서 text, 2.1에서 html이다. 꺼진 HTTP 본문이나 비활성 형식의 필드를 실제 전송으로 취급하지 않는다. `noData`는 본문 전송 결과를 만들지 않는다. 알 수 없는 노드 버전·작업은 외부 연동 노드의 존재와 미지원 진단을 남기며 send 작업이 실행된 것으로 표현하지 않는다.

Telegram sendDocument는 수신 chatId와 additionalFields.caption을 분석한다. binaryData=true면 파일 내용은 `binary_payload_unavailable`, false면 file ID/URL 참조는 분석하되 실제 내용은 `remote_attachment_content_unavailable`이다. 동적 binaryData 선택도 미확인으로 남기며 비활성 text/file을 전송 데이터로 섞지 않는다. binaryPropertyName은 데이터가 아닌 선택자다. 분석하지 못한 파일 내용은 목적지 정책에도 unknown 등급으로 전달하므로 알려진 caption이 허용됐다는 이유로 전체 파일을 승인하지 않는다. reply markup과 미해석 추가 옵션은 별도 제한으로 표시한다.

값 흐름 엔진의 출처와 지원 경로를 이용해 전체 객체·DB 결과·비밀정보 후보·개인정보 후보·일반 필드 전달을 구분한다. 필드 이름에 따른 민감도는 후보이며 실제 데이터 확인이 아니다. 신뢰된 sidecar의 정확한 노드 키·필드 분류도 사용할 수 있다. 데이터 출처가 내부라는 사실만으로 데이터 등급을 internal 또는 public으로 바꾸지 않는다. 일부 분류만 제공된 전체 객체나 알 수 없는 합류 경로는 미확인 범위를 유지한다.

정책 검사에는 가장 높은 민감도 하나가 아니라 전달 값에 포함된 분류 집합을 사용한다. 예를 들어 비밀정보 전송을 허용해도 개인정보 전송을 금지한 정책이라면 두 종류가 섞인 전체 객체, JSON 직렬화 결과, 문자열 결합은 모두 개인정보 정책 위반을 남긴다. 지원되는 필드 선택으로 빠진 정보는 전송 분류에 남기지 않는다. 미해석 부분의 `unknown`은 별도로 유지한다.

운영자 sidecar는 컨트롤러가 입력 파일 해시와 결합해 검증한 `AssessmentEvidence`여야 한다. JSON 안의 정책·설명·목적 주장은 허용 근거가 아니다. 목적지와 데이터 등급은 `assessDestination`에 전달하며, 이메일은 To·CC·BCC를 모두 확인한다. 동일 노드의 정책 발견을 합칠 때도 뒤에 검사한 수신처의 거부 이유를 보존한다. HTTP는 origin, 메일과 메시지는 정규화된 정확한 대상 문자열을 비교한다. 응답과 로그의 정책 대상은 각각 `caller`, `execution_log`다. 고정 대상이 정책에 맞아도 실제 수신자의 신원·권한이나 런타임 네트워크 통제까지 검증한 것은 아니다.

바이너리 첨부, 동적 수신처, 이름/URL locator의 실제 대상, 구조화된 Slack 본문의 목적지 덮어쓰기, 미해석 추가 옵션, 리다이렉트, 여러 마지막 노드의 실행 순서, 응답 대상의 권한은 명시적 진단으로 남긴다. Code 로그는 파싱된 호출 후보이며 렉시컬 바인딩·임의 함수·모든 로그 API의 완전 분석이 아니다. 확실한 사실을 보존하면서 해당 검사 범위는 `partial`로 처리한다.

결과에는 노드 해시·안전한 구조 위치·고정 근거 코드만 포함한다. 원본 이름, 수신처, 본문, 필드 이름, 내부 URL, 원본 코드와 정책의 자유 문구를 복사하지 않는다. 규칙별 발견·진단과 AST 인수 수를 제한하고 제한 도달은 불완전 진단으로 표시한다.

검증: `node --test test/extended-sinks.test.mjs`. 이메일 형식과 BCC, Slack/Telegram 수신처, 활성 HTTP 데이터 필드, DB 응답, AST 비실행, 첨부·미지원 설정, 위조 정책, 비활성 노드, 목적지 덮어쓰기와 과다 수신처, 운영자 필드 분류를 검증한다.

공식 근거는 모두 n8n `86dff76e10efba250a4d3e57760e4eb5d2bbea25`에 고정했다.

- [Send Email 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/EmailSend/EmailSend.node.ts), [v1의 두 본문·수신처·첨부](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/EmailSend/v1/EmailSendV1.node.ts), [v2 send 필드와 실행 옵션](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/EmailSend/v2/send.operation.ts)
- [Gmail V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Gmail/v2/GmailV2.node.ts), [메일 필드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Gmail/v2/MessageDescription.ts)
- [Slack V2](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Slack/V2/SlackV2.node.ts), [대상·본문 변환](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Slack/V2/GenericFunctions.ts)
- [Telegram의 문서·바이너리 분기](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Telegram/Telegram.node.ts), [추가 필드·reply markup 병합](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Telegram/GenericFunctions.ts)
- [HTTP 필드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/HttpRequest/V3/Description.ts), [Webhook 응답](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Webhook/description.ts), [Respond to Webhook](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/RespondToWebhook/RespondToWebhook.node.ts)
- [Notion 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Notion/Notion.node.ts), [V2 요청 구성](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Notion/v2/NotionV2.node.ts), [속성 값 선택](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Notion/shared/GenericFunctions.ts)
- [Google Docs 실행](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Docs/GoogleDocs.node.ts), [기본값·수정 필드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/Google/Docs/DocumentDescription.ts)
- [WhatsApp 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/WhatsApp/WhatsApp.node.ts), [작업·텍스트 필드](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/nodes-base/nodes/WhatsApp/MessagesDescription.ts)
- [Gemini 버전](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/nodes/vendors/GoogleGemini/actions/versionDescription.ts), [텍스트 요청](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/nodes/vendors/GoogleGemini/actions/text/message.operation.ts), [자격 증명 host 사용](https://github.com/n8n-io/n8n/blob/86dff76e10efba250a4d3e57760e4eb5d2bbea25/packages/@n8n/nodes-langchain/nodes/vendors/GoogleGemini/transport/index.ts)
