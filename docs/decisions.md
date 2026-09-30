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

## mitigation 파서 재작성 (문맥 훑기 → 토큰+부정 패턴)
- 왜: "별칭 주변 8자 훑기" 방식이 checksec 출력("NX: NX disabled"),
  구분자(:/=), 부정 표기(non-PIE, not enabled), 부분 문자열
  (independent 안의 dep)에서 줄줄이 오판했다.
- 방식: 보호기법마다 별칭을 단어 경계로 매칭하고, 별칭 근처의 명시적
  부정 패턴(disabled/off/no/non/not)을 콤마 이전 구간에서만 확인.
  회귀 테스트로 checksec 형식 케이스를 고정.

## RELRO full/partial 가중치 분리
- 왜: Partial RELRO 는 .got.plt 가 여전히 쓰기 가능한데 이전엔 Full 과
  똑같이 +1 점을 줘서, 카나리 없는 기본 빌드가 High 로 나왔다.
- 방식: relro_full=1, relro_partial=0 으로 config 에서 분리. Partial 은
  이론 설명도 "완전히 막지는 못한다"로 정확히 기술.

## NX 기본값을 checksec 기준으로
- 왜: GNU_STACK 세그먼트가 없을 때 이전엔 NX 켜짐으로 봤으나,
  checksec/pwntools 는 이 경우를 NX disabled 로 본다. "checksec 을
  구현했다"는 설명과 모순이었다.
- 방식: 세그먼트 없으면 disabled 로 판정.

## PIE 판정을 DF_1_PIE + PT_INTERP 로
- 왜: ET_DYN 만 보면 공유 라이브러리(.so)도 PIE 로 오판한다.
- 방식: DT_FLAGS_1 의 DF_1_PIE 비트 또는 PT_INTERP 세그먼트 존재로
  PIE 실행 파일과 .so 를 구분한다. DF_1_PIE 는 비교적 최근 binutils
  부터 설정되므로, 오래된 툴체인 PIE 를 놓치지 않도록 PT_INTERP 를
  함께 본다(.so 는 PT_INTERP 가 없다). 참고로 checksec.sh 는 전통적
  으로 DT_DEBUG 유무로 판별한다.

## 심볼 추출을 임포트 함수로 한정
- 왜: 이전엔 .symtab 의 모든 심볼(파일명 Scrt1.o, 변수 _DYNAMIC,
  로컬 심볼)을 다 모아 위험 함수 분류가 오염됐다.
- 방식: STT_FUNC 이면서 SHN_UNDEF 인 심볼만 수집(= 외부에서 가져다
  쓰는 함수).

## 우선순위 카테고리에서 malloc/free 제외
- 왜: memory 카테고리에 malloc/free 가 있고 high priority 라, 거의 모든
  바이너리가 High 로 분류돼 우선순위가 무의미했다.
- 방식: 오버플로우를 직접 유발하는 함수만 dangerous_memory 로 남김.

## scan_directory 안전성/멱등성 강화
- 왜: 출력 경로를 LLM 이 정하는데, JSONL 아닌 기존 파일을 넘기면 전체를
  덮어써 데이터가 파괴됐다. 경로 문자열을 그대로 키로 써서 b/./b/절대
  경로가 다른 행으로 쌓였고, open("w") 로 먼저 비워 쓰다 죽으면 결과가
  통째로 날아갔다.
- 방식: (1) realpath 를 기본키로 → 경로 표기 무관 멱등. (2) 기존 파일이
  우리 JSONL 형식이 아니면 UNSAFE_OUTPUT 으로 거부. (3) 임시 파일 +
  os.replace 로 원자적 쓰기. (4) 이번 스캔이 실제로 볼 수 있었던 파일
  (해당 디렉터리 직속 + pattern 일치)만 stale 판정 대상으로 삼아, 사라진
  파일의 행만 제거한다. 내용까지 비교하는 멱등성 테스트 추가.

## risky 탐지에서 문자열 리터럴 처리
- 왜: 정규식으로 주석만 지웠을 때, puts("http://a.b") 의 "//" 를
  한줄주석 시작으로 오인해 그 줄 뒤쪽(실제 strcpy 호출 포함)을 통째로
  주석 처리해 위험 호출을 놓쳤다(미탐 회귀).
- 방식: 상태 기계로 주석과 문자열/문자 리터럴을 함께 인식해 공백 치환.
  리터럴을 먼저 인식하므로 리터럴 안의 "//" 나 함수명이 파싱에 영향을
  주지 않는다. 닫는 따옴표 없이 줄이 끝나면(잘린 코드) 리터럴을 그
  줄에서 끝내 여는 따옴표 하나가 뒤 코드를 삼키지 않게 하고, C23 자릿수
  구분자(1'000)의 홑따옴표는 리터럴로 보지 않는다. 회귀 테스트 추가.

## 2차 리뷰 대응 (batch/mitigation 정밀화)
- stale row 오삭제 수정: 1차 수정본은 "scan_root 하위 전체"를 stale
  후보로 봐, 하위 디렉터리나 다른 pattern 으로 적재한 행까지 지웠다.
  이번 스캔이 볼 수 있었던 파일(직속 + fnmatch(pattern))로 한정.
- RELRO 판정을 별칭 주변 구간으로: 문자열 전체에서 full/partial 을
  찾던 것을 relro 별칭이 속한 구분자 구간 안에서만 찾도록 바꿔,
  "Canary: full, RELRO: partial" 오판과 "RELRO none → partial" 오판을
  함께 해결.
- 줄바꿈 구분자 처리: _is_enabled 의 뒤쪽 창을 줄바꿈에서도 끊어
  다음 줄 상태가 새지 않게 함.
- _load_existing 이 dict 아닌 JSON 줄([1] 등)에 TypeError 로 죽던 것
  수정.
- 원자적 쓰기 보완: output_path 가 심링크면 대상 실제 경로에 쓰고,
  기존 파일 권한을 보존(mkstemp 기본 0600 으로 바뀌지 않게).
- .o(ET_REL) 재배치 오브젝트는 분석 대상에서 skip.
