# Binary Analyzer MCP Server

의심스러운 바이너리 또는 코드에서 위험 함수와 보호기법을 분석해
취약점 가능성과 익스플로잇 난이도를 설명하는 MCP(Model Context
Protocol) 서버입니다. 실제 ELF 파일을 넣으면 심볼과 보호기법
(NX/PIE/Canary/RELRO)을 직접 파싱하고, 여러 파일을 배치로 스캔해
결과를 JSONL 로 적재합니다.

## 분석 흐름

```
ELF 파일 ──► analyze_elf ──► 심볼 분류 + 보호기법 판정 + 난이도 추정
(또는 심볼/코드 직접 입력)
여러 파일 ──► scan_directory ──► JSONL 적재(멱등)
```

## 제공 기능 (MCP Tools)

### analyze_elf
ELF 바이너리 경로를 받아 임포트 심볼과 보호기법(NX/PIE/Canary/RELRO)을
직접 파싱한다. checksec 판정을 `pyelftools` 로 구현해 외부 실행 파일
없이 동작한다. 심볼 분류와 보호기법 기반 난이도까지 한 번에 돌려준다.

### scan_directory
디렉터리 안의 ELF 파일을 모두 분석해 결과를 JSONL 로 적재한다. 파일
경로를 기본키로 upsert 하므로 재실행해도 결과가 같다(멱등). 입력 대비
처리/스킵/에러 건수를 로그로 남긴다.

### analyze_symbol
함수 이름 목록을 network / execution / file / memory 카테고리로 분류하고
분석 우선순위를 매긴다. 한 심볼이 여러 카테고리에 걸리면 모두 보존한다.

### check_risky
C/pseudo 코드에서 위험 함수(gets, strcpy, sprintf 등) 호출을 찾는다.
주석 속 함수명이나 유사 이름(mystrcpy)은 오탐하지 않으며, 걸린 함수마다
사유와 권장 수정법을 함께 돌려준다.

### mitigation
보호기법 조합을 받아 익스플로잇 난이도를 추정한다. `NX enabled` 와
`NX disabled` 를 구분해 판정하며, 각 보호기법이 공격에 주는 제약을
설명한다.

## 설정

탐지 룰(위험 함수 목록, 카테고리, 난이도 가중치·구간)은 코드가 아니라
[`config.yaml`](./config.yaml) 에서 읽는다. 룰을 바꾸려면 이 파일만
고치면 되고, 모든 툴이 같은 설정을 공유한다.

## 설치 및 실행

```bash
pip install -r requirements.txt
python -u mcp_server.py        # stdio MCP 서버 기동
```

Docker:

```bash
docker build -t binary-analyzer-mcp .
docker run -i --rm binary-analyzer-mcp
```

## 테스트

```bash
pytest                          # 루트/tests 어디서 실행해도 동일
```

핵심 변환 로직과 배치 멱등성을 검증한다. ELF 관련 테스트는 gcc 로
보호기법이 다른 바이너리를 즉석에서 만들어 확인하며, gcc 가 없으면
자동으로 스킵한다.

## 선택 기능: 로컬 LLM

`llm/ollama_client.py` 는 로컬 Ollama 서버로 자연어 설명을 보강하는
선택 모듈이다. 기본 분석 툴은 이 모듈 없이도 동작하므로, 배포
환경(도커/Smithery)에 Ollama 가 없어도 문제없다.

## 한계

- 카나리 판정은 `__stack_chk_fail` 심볼 유무로 본다. 정적 링크
  바이너리는 libc 쪽 심볼 때문에 실제로 스택 보호를 안 써도 카나리가
  있는 것으로 오탐될 수 있다(checksec 도 같은 한계가 있다).
- `check_risky` 는 "위험 함수 호출 여부"를 표시할 뿐, 실제 취약점
  존재를 증명하지 않는다. `scanf("%d")` 처럼 안전하게 쓴 경우도 사용
  자체는 표시된다. 결과 해석 시 참고한다.
- ELF 판정은 x86/x86-64 ELF 를 기준으로 검증했다. 다른 아키텍처나
  특수 링크 옵션에서는 결과가 다를 수 있다.
- 정적 링크(static/static-pie) 바이너리는 임포트 함수가 없어
  `critical_functions` 가 비어 있을 수 있다. 실제로 strcpy 등을 써도
  심볼 분석으로는 드러나지 않는다(호출 그래프 분석이 아니라 임포트
  심볼 기반이기 때문).
- 같은 출력 파일(`output_path`)에 대한 동시 실행은 지원하지 않는다.
  배치는 읽기→수정→쓰기 방식이라, 두 호출이 같은 파일을 동시에 다루면
  나중에 끝난 쪽이 앞선 결과를 덮어써 유실될 수 있다(원자적 쓰기는 파일
  손상만 막는다). 동시에 돌릴 때는 출력 파일을 분리한다.
- `analyze_elf`/`scan_directory` 는 호출자가 지정한 경로를 읽고 결과를
  지정 경로에 쓴다. 신뢰할 수 없는 입력을 다룰 때는 접근 가능한 경로를
  운영 측에서 제한하는 것을 권장한다.
- C23 UTF-8 문자 리터럴(`u8'x'`)의 홑따옴표는 앞 글자가 숫자 8 이라
  자릿수 구분자로 오인될 수 있다(매우 드문 경우).

## 문서

- [설계 결정 기록](./docs/decisions.md): 기술 선택의 이유와 버린 대안
- [트러블슈팅 기록](./docs/troubleshooting.md): 발견한 문제의 증상·원인·해결·회귀 테스트
