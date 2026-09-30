# 설계 결정 기록

기술 선택과 트레이드오프를 한두 줄씩 남긴다.

## MCP SDK 버전 (mcp>=2.0)
- 왜: 기존 코드가 `mcp.server.fastmcp.FastMCP` 를 썼는데, 버전을 고정하지
  않아 최신 2.x 가 설치되면서 `FastMCP` → `MCPServer` 개명으로 import
  단계에서 죽었다.
- 방식: 2.x 기준으로 재작성하고 requirements 에 `mcp>=2.0,<3.0` 로 고정.
  구버전에서도 돌아가도록 `MCPServer` import 실패 시 `FastMCP` 폴백.
- 버린 대안: `mcp<2` 로 되돌리기 → 최신 생태계와 멀어져 배포 시 다시
  깨질 위험이 커서 제외.

## ELF 파싱: pyelftools (checksec 직접 구현)
- 왜: 실제 바이너리를 자동 분석하려면 심볼·보호기법 추출이 필요.
- 방식: `readelf`/`checksec` 외부 실행 파일 대신 순수 파이썬
  `pyelftools` 로 NX(GNU_STACK 실행권한)·PIE(ET_DYN)·Canary
  (__stack_chk_fail)·RELRO(GNU_RELRO + BIND_NOW)를 판정.
- 버린 대안: `subprocess` 로 checksec 호출 → 도커/Smithery 등 유틸이
  없는 환경에서 깨지고 파싱도 취약해서 제외.

## 보호기법 판정: enabled/disabled 구분
- 왜: 기존 로직은 문자열에 "NX" 가 있는지만 봐서 "NX disabled" 도 켜진
  것으로 오판했다.
- 방식: 별칭 바로 앞의 부정 접두(no/not/without)와 바로 뒤 상태어
  (disabled/off)만 확인해 활성 여부를 가림. 넓은 윈도우로 보면 뒤따르는
  다른 항목의 부정어까지 삼켜 오판하므로 인접 문맥만 검사.

## 배치 멱등성: 파일 경로 기본키 upsert
- 왜: DE 원칙 — 같은 입력을 다시 넣거나 중간에 죽고 재시작해도 결과가
  같아야 한다.
- 방식: 기존 JSONL 을 {경로: 레코드} 로 읽어 들고 덮어쓴 뒤 전체를 다시
  기록. 재실행해도 행이 늘지 않는다.
- 버린 대안: append 방식 → 재실행 시 중복 행이 쌓여 멱등성 위반.

## 탐지 룰의 config 분리 (config.yaml)
- 왜: 위험 함수 목록·카테고리·난이도 가중치는 사람이 조정하는 값이라
  코드에 박으면 안 된다. 비교/재실행 시 룰이 어긋나지 않도록 단일 소스가
  필요.
- 방식: 모든 툴이 `config_loader` 를 통해 같은 `config.yaml` 을 읽음.

## 로컬 LLM(Ollama)을 선택 기능으로 분리
- 왜: 기존 README 는 mitigation 이 LLM 을 쓴다고 했으나 실제로는 호출하지
  않는 죽은 코드였다. 배포 서버에 Ollama 를 강제하면 환경이 깨진다.
- 방식: 핵심 경로에서 import 하지 않는 선택 모듈로 명시하고 README 를
  실제 동작에 맞게 수정.
