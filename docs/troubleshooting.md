# 트러블슈팅 기록

원본 버전에서 출발해 여러 차례 코드 리뷰를 거치며 발견하고 고친 문제를
정리한다. 항목마다 **증상 → 원인 → 해결 → 검증(회귀 테스트)** 순서로
적었다. 기술 선택의 이유와 버린 대안은 [decisions.md](./decisions.md) 에
따로 기록한다.

모든 항목은 실제 실행으로 재현하고 수정 후 다시 확인했다.

- 검증 환경: Linux(Docker `python:3.12`, gcc 14) / macOS(Apple clang)
- 최종 상태: Linux 45 passed, macOS 29 passed · 16 skipped(ELF 테스트,
  아래 E-1 참고), MCP stdio 기동 및 도구 5종 호출 확인
- 견고성: 정상 ELF 를 무작위 변조한 파일 500개로 `analyze_elf` 를
  돌려 멈춤 0건, 처리되지 않은 예외 0건

---

## 한눈에 보기

| ID | 영역 | 증상 | 심각도 |
|---|---|---|---|
| O-1 | 서버 | mcp 2.x 설치 시 import 단계에서 서버가 죽음 | 치명 |
| O-2 | 테스트 | 실행 위치(cwd)에 따라 테스트 실패 | 중간 |
| O-3 | mitigation | `NX disabled` 를 NX 켜짐으로 판정 | 높음 |
| O-4 | symbol | 여러 카테고리 중 마지막 하나만 남음, `None` 입력 시 TypeError | 중간 |
| O-5 | risky | `mystrcpy` 를 `strcpy` 로 오탐, 사유·수정법 미반환 | 중간 |
| M-1 | mitigation | checksec 출력(전부 꺼짐)을 High 로 판정 | 치명 |
| M-2 | mitigation | Partial RELRO 를 "GOT 보호"로 계산 | 높음 |
| M-3 | mitigation | RELRO 판정이 다른 항목·다른 줄의 값을 가져옴 | 중간 |
| M-4 | 설계 | 정확한 값을 문자열로 바꿨다가 다시 파싱 (M-1~3 의 근본 원인) | 높음 |
| E-1 | 테스트 | macOS 에서 ELF 테스트가 전부 skip 되어 핵심 기능 미검증 | 높음 |
| E-2 | elf | GNU_STACK 이 없을 때 NX 를 켜짐으로 판정 | 중간 |
| E-3 | elf | 공유 라이브러리(.so, libc.so.6)를 PIE 로 판정 | 중간 |
| E-4 | elf | 파일명·변수까지 심볼로 수집, 거의 모든 바이너리가 우선순위 High | 중간 |
| E-5 | elf | `.o` 파일을 분석해 "보호기법 전부 꺼짐"으로 보고 | 낮음 |
| B-1 | batch | JSONL 이 아닌 임의 파일을 덮어써 파괴 | 치명 |
| B-2 | batch | 경로 표기만 달라도 중복 행 생성 (멱등성 깨짐) | 높음 |
| B-3 | batch | 쓰는 도중 죽으면 기존 결과 전체 유실 | 높음 |
| B-4 | batch | stale row 처리: 안 지움 → 과하게 지움 → dotfile 오삭제 | 치명 |
| B-5 | batch | dict 가 아닌 JSON 줄에서 크래시 | 낮음 |
| B-6 | batch | UTF-8 이 아닌 파일명 하나로 배치 전체 실패 | 치명 |
| R-1 | risky | 문자열 속 `//` 때문에 뒤쪽 실제 호출을 놓침 (수정이 만든 회귀) | 높음 |
| R-2 | risky | 닫히지 않은 따옴표·`1'000`·`L'"'` 뒤의 호출을 놓침 | 중간 |

심각도 기준은 다음과 같다. **치명**은 크래시, 데이터 파괴, 핵심 결과가
정반대로 나오는 경우다. **높음**은 결과가 틀리지만 동작은 하는 경우다.

---

## 1. 원본 버전의 버그

### O-1. mcp 2.x 에서 서버 기동 실패
- **증상**: `pip install -r requirements.txt` 후 서버를 실행하면 import
  단계에서 `ModuleNotFoundError: No module named 'mcp.server.fastmcp'` 가
  발생한다.
- **원인**: `requirements.txt` 에 `mcp` 버전을 고정하지 않았다. 그래서
  최신 2.x 가 설치됐는데, 2.x 에서는 `FastMCP` 가 `MCPServer`
  (`mcp.server.mcpserver`)로 이름이 바뀌었다.
- **해결**: 2.x API 로 옮기고 `mcp>=2.0,<3.0` 으로 고정했다.
- **검증**: stdio 클라이언트로 서버를 띄워 `list_tools` 와 `call_tool` 을
  확인했다.

### O-2. 테스트가 실행 위치에 의존
- **증상**: `tests/` 안에서 `pytest` 를 실행하면 픽스처 JSON 을 찾지 못한다.
- **원인**: `open("tests/test_symbol.json")` 처럼 cwd 기준 상대 경로를 썼다.
- **해결**: `__file__` 기준 경로로 바꾸고 `conftest.py` 에서 프로젝트
  루트를 `sys.path` 에 추가했다.

### O-3. `NX disabled` 를 켜짐으로 판정
- **증상**: `"NX disabled, No PIE, No canary"` 를 넣으면 Low 가 아니라
  Medium 이 나온다.
- **원인**: `"NX" in protection` 처럼 부분 문자열만 검사했다.
- **해결**: 별칭 주변의 부정어를 확인하도록 바꿨다. 이 방식도 M-1 에서
  다시 깨졌다.
- **검증**: `test_mitigation_disabled_is_low`, `test_mitigation_nx_only_is_medium`

### O-4. 카테고리 덮어쓰기 / None 입력 크래시
- **증상**: `["socket", "system", "strcpy"]` 를 넣으면 카테고리가 하나만
  남는다. `symbols=None` 이면 TypeError 가 난다.
- **원인**: 루프 안에서 `category` 단일 변수를 계속 덮어썼고, 입력 검증이
  없었다.
- **해결**: 결과를 `{카테고리: [함수]}` 로 담고, 잘못된 입력에는 표준 에러
  객체(`INVALID_INPUT`)를 반환한다. 문자열이 아닌 원소(중첩 리스트 등)는
  걸러낸다.
- **검증**: `test_symbol_multi_category`, `test_symbol_invalid_input`

### O-5. risky 탐지의 부분 문자열 오탐
- **증상**: `mystrcpy(a, b)` 를 `strcpy` 로 탐지한다. 주석 속 함수명도
  탐지한다. 문서에 적힌 `reason`/`suggested_fix` 는 실제로 반환되지 않는다.
- **해결**: `(?<![A-Za-z0-9_])name\s*\(` 패턴으로 호출 형태만 매칭한다.
  config 의 사유·수정법·심각도를 결과에 싣는다. 주석 제거는 R-1 에서 다시
  손봤다.
- **검증**: `test_risky_no_false_match_on_prefix`, `test_risky_ignores_comments`

---

## 2. mitigation (보호기법 판정)

### M-1. checksec 출력에서 수정했던 버그가 재발
- **증상**: O-3 을 고친 뒤에도 다음 입력들이 모두 틀렸다.

  | 입력 | 기대 | 실제 |
  |---|---|---|
  | `Stack: No canary found, NX: NX disabled, PIE: No PIE, RELRO: No RELRO` | 전부 꺼짐, Low | nx·pie·relro 켜짐, **High** |
  | `NX: disabled`, `NX=off`, `NX not enabled` | 꺼짐 | 켜짐 |
  | `non-PIE` | 꺼짐 | 켜짐 |
  | `PIE: position independent` | pie 만 | **nx** 도 켜짐 |

- **원인**
  1. 상태어가 `^\s*disabled` 처럼 별칭 바로 뒤에만 허용돼서, 사이에
     `:`/`=` 가 끼면 매칭되지 않았다. checksec 은 `NX: NX disabled` 처럼
     라벨에 한 번, 상태에 한 번 별칭이 나오는데, 첫 번째 라벨을 "켜짐"으로
     판정했다.
  2. 별칭에 단어 경계가 없어서 `independent` 안의 `dep`(DEP) 가 NX 로
     잡혔다.
  3. `non-`, `not ... enabled` 같은 부정 표기를 다루지 않았다.
- **해결**: 별칭을 `(?<![a-z])…(?![a-z])` 로 감싸고, 뒤쪽 상태어는 구분자
  (`,;|` 와 줄바꿈) 앞까지만 보며, 앞쪽 부정 접두(`no/non/not/without`)는
  구분자 `:=_-` 를 허용해 검사한다.
- **검증**: `test_mitigation_checksec_all_disabled`,
  `test_mitigation_negation_forms`, `test_mitigation_no_substring_false_match`

### M-2. Partial RELRO 를 GOT 보호로 계산
- **증상**: 카나리가 없는 gcc 기본 빌드(NX·PIE·Partial RELRO)가 High 로
  나오고, 이론 설명으로 "GOT 덮어쓰기 차단"이 붙었다.
- **원인**: RELRO 를 켜짐/꺼짐으로만 보고 Partial 에도 Full 과 같은 +1 을
  줬다. Partial RELRO 에서는 `.got.plt` 가 여전히 쓰기 가능하므로 사실과
  다른 설명이 나갔다.
- **해결**: config 에서 `relro_full: 1`, `relro_partial: 0` 으로 가중치를
  나누고, Partial 전용 이론 설명을 추가했다.
- **검증**: `test_mitigation_partial_relro_not_counted`

### M-3. RELRO 판정이 주변 문맥을 잘못 가져옴
M-2 를 고친 뒤 RELRO 수준 판정에서 연쇄적으로 문제가 나왔다.

| 입력 | 잘못된 결과 | 원인 |
|---|---|---|
| `RELRO none` (elf_tool 이 실제로 만든 문자열) | `relro:partial` | 부정어를 별칭 **앞**에서만 찾았고, 못 찾으면 partial 로 처리 |
| `Canary: full, RELRO: partial` | `relro:full` | `full` 을 문자열 **전체**에서 검색 |
| `NX enabled\nPIE: No PIE` | NX 꺼짐 | 줄바꿈이 구분자가 아니라 다음 줄 `No` 가 새어 들어옴 |
| `NX disabled PIE enabled Full RELRO` | RELRO 없음 | 구분자가 없어 구간이 문자열 전체가 됐고, NX 의 `disabled` 를 가져옴 |

- **해결**: RELRO 별칭 주변을 "구분자 구간 ∩ 앞 8자·뒤 16자 창"으로
  제한하고, 그 안에서만 부정어, `full`, `partial` 을 찾는다.
- **검증**: `test_mitigation_relro_none_not_partial`,
  `test_mitigation_relro_disabled_forms`, `test_mitigation_full_scoped_to_relro`,
  `test_mitigation_newline_separator`, `test_mitigation_no_separator_relro`

### M-4. 근본 원인: 구조화된 값을 문자열로 왕복
- **증상**: norelro 바이너리를 분석하면 `protections.relro = "NONE"` 인데
  `enabled_protections` 에는 `relro:partial` 이 들어 있었다. 같은 응답
  안에서 두 필드가 서로 모순됐다.
- **원인**: `elf_tool` 은 `nx=True`, `relro="NONE"` 같은 **정확한 값**을
  이미 알고 있다. 그런데도 이 값을 `"NX enabled, …, RELRO none"` 문자열로
  조립한 뒤 자연어 파서로 다시 해석했다. 그래서 파서의 버그가 핵심 경로에
  그대로 전파됐다. M-1~M-3 에서 파서를 여러 번 고쳐야 했던 이유가 이 구조다.
- **해결**: 점수 계산을 순수 함수 `score_protections(nx, pie, canary, relro)`
  로 분리했다. `elf_tool` 은 이 함수를 직접 호출한다. 텍스트 파서는 사람이나
  LLM 이 문자열을 넣는 `mitigation` 도구에서만 쓰며, 파싱 결과도 같은 순수
  함수에 넘긴다. 이제 핵심 경로에서 파서 버그가 구조적으로 발생할 수 없다.
  이어서 응답 딕셔너리(`analysis` 문구 포함)를 두 경로가 각자 조립하던
  중복도 `build_mitigation_result` 한 곳으로 모았다. 한쪽만 수정돼 두 도구의
  출력이 어긋나는 일을 막기 위해서다.
- **검증**: `test_score_protections_pure_function`,
  `test_text_parser_matches_pure_function`, `test_analyze_elf_norelro_is_none`

---

## 3. elf (ELF 분석)

### E-1. 핵심 기능이 한 번도 실행되지 않음
- **증상**: macOS 에서 `pytest` 를 돌리면 "통과"로 끝나지만, ELF 테스트
  3개는 전부 skip 됐다. `analyze_elf`/`scan_directory` 는 실제로 한 번도
  실행되지 않은 상태였다.
- **원인**: macOS 의 `gcc` 는 clang 별칭이라 ELF 가 아니라 Mach-O 를
  만든다. CI 도 없었다.
- **해결**: 컴파일 산출물의 매직 넘버(`\x7fELF`)를 확인해 ELF 가 아니면
  명시적으로 skip 한다. GitHub Actions(ubuntu)에서 전체 테스트를 실행한다.
- **교훈**: skip 된 테스트는 검증된 것이 아니다. 로컬 결과만 보지 말고
  skip 사유까지 확인해야 한다.

### E-2. GNU_STACK 이 없을 때 NX 판정
- **증상**: docstring 에는 "checksec 판정을 구현했다"고 적었지만 판정
  결과가 반대였다.
- **원인**: `PT_GNU_STACK` 세그먼트가 없으면 NX 를 켜짐으로 봤다.
  checksec/pwntools 는 이 경우를 NX disabled 로 판정한다.
- **해결**: 세그먼트가 없으면 disabled 로 판정하도록 바꿔 checksec 관례에
  맞췄다.

### E-3. 공유 라이브러리를 PIE 로 판정
이 항목은 수정이 두 번 더 필요했다.

1. **ET_DYN 만 확인** → `.so` 가 PIE 로 나옴. `DT_FLAGS_1` 의 `DF_1_PIE`
   비트로 판정하도록 바꿈.
2. **`DF_1_PIE` 또는 `PT_INTERP`** → `DF_1_PIE` 가 없는 오래된 툴체인의 PIE 를
   살리려고 `PT_INTERP` 를 추가했다. 그러자 `libc.so.6` 가 PIE 로 나왔다.
   libc 는 직접 실행할 수 있는 라이브러리라 `PT_INTERP` 를 가진다. 문서에
   적었던 ".so 는 PT_INTERP 가 없다"는 문장도 사실이 아니었다.
3. **최종**: `DF_1_PIE` 가 있거나, `PT_INTERP` 가 있으면서 `DT_SONAME` 이
   없을 때만 PIE 로 본다. 공유 라이브러리는 거의 항상 SONAME 이 있다.
- **검증**: `test_scan_shared_object_not_pie`, `test_executable_shared_object_not_pie`

### E-4. 심볼 수집 범위와 우선순위
- **증상**: `puts`·`malloc` 만 쓰는 프로그램이 분석 우선순위 High 로
  나왔다. 심볼 목록에는 `Scrt1.o`(파일명), `_DYNAMIC`(변수) 같은 것까지
  섞여 있었다.
- **원인**
  1. `.symtab` 의 모든 심볼을 타입·정의 여부와 무관하게 수집했다.
  2. high priority 카테고리 `memory` 에 `malloc`/`free` 가 들어 있어서
     사실상 모든 C 바이너리가 High 가 됐다.
- **해결**: `STT_FUNC` 이면서 `SHN_UNDEF` 인 심볼(외부에서 가져오는 함수)만
  모은다. 오버플로우를 직접 유발하는 함수만 `dangerous_memory` 로 분리했다.

### E-5. `.o` 파일 분석
- **증상**: 빌드 디렉터리를 스캔하면 `.o` 가 "NX 꺼짐, 보호기법 없음"으로
  보고됐다.
- **해결**: `ET_REL` 은 `UNSUPPORTED_ELF_TYPE` 으로 반환하고 배치에서는 skip
  으로 집계한다. 처음에는 `NOT_ELF` 를 썼는데, `.o` 도 ELF 이므로 코드
  이름을 바로잡았다.
- **검증**: `test_scan_skips_object_files`, `test_object_file_error_code`

---

## 4. batch (디렉터리 스캔)

### B-1. 임의 파일 덮어쓰기 (데이터 파괴)
- **증상**: `output_path` 에 기존 텍스트 파일을 지정하면 원래 내용이
  사라지고 스캔 결과로 바뀌었다.
- **원인**: 출력 경로는 LLM 이 정한다. 기존 파일의 줄을 "손상된 JSONL"로
  보고 모두 버린 뒤 파일 전체를 다시 썼다. 프롬프트 인젝션 한 번이면
  `~/.zshrc` 같은 파일이 파괴될 수 있었다.
- **해결**: 기존 파일의 첫 줄이 `"path"` 키를 가진 JSON 객체가 아니면
  `UNSAFE_OUTPUT` 으로 거부한다.
- **검증**: `test_scan_directory_refuses_non_jsonl`

### B-2. 경로 표기에 따라 행이 늘어남
- **증상**: 같은 디렉터리를 `b`, `./b`, `/tmp/b` 로 스캔하면 `total_rows`
  가 5 → 10 → 15 로 늘었다.
- **원인**: 경로 문자열을 정규화하지 않고 그대로 기본키로 썼다.
- **해결**: `os.path.realpath` 결과를 기본키로 쓴다.
- **검증**: `test_scan_directory_idempotent_path_variants`,
  `test_scan_directory_content_stable`. 기존 멱등성 테스트는 주석에
  "내용도 동일"이라고 적어 놓고 실제로는 줄 수만 비교했기 때문에 이 버그를
  잡지 못했다.

### B-3. 비원자적 쓰기
- **증상/원인**: `open(path, "w")` 로 파일을 먼저 비우고 썼다. 쓰는 도중
  죽으면 이전 결과까지 전부 사라진다.
- **해결**: 같은 디렉터리의 임시 파일에 쓴 뒤 `os.replace` 로 교체한다.
  이후 보완 사항은 두 가지다. 첫째, 기존 파일 권한을 유지한다(`mkstemp`
  기본값 0600 으로 바뀌는 문제). 둘째, 출력 경로가 심링크면 링크를 일반
  파일로 바꾸지 않고 링크 대상에 쓴다.

### B-4. stale row 처리: 세 단계에 걸친 수정
삭제된 파일의 오래된 행을 정리하는 로직은 고칠 때마다 새 문제가 생겼다.

| 단계 | 규칙 | 문제 |
|---|---|---|
| 1 | 정리하지 않음 | 삭제된 파일의 행이 계속 남음 |
| 2 | `scan_root` 하위에서 이번에 못 본 행을 모두 삭제 | **데이터 손실.** `sub/` 스캔 결과가 상위 스캔 때 삭제되고, `*.so` 스캔이 나머지 행을 모두 삭제 |
| 3 | 직속 파일이면서 `fnmatch(pattern)` 일치 | `.*` 로 적재한 dotfile 행이 `*` 스캔 때 삭제됨. glob `*` 는 dotfile 을 보지 않지만 fnmatch `*` 는 매칭하기 때문 |
| 최종 | 직속 + pattern 일치 + **glob 의 dotfile 규칙 적용** | — |

- **핵심**: "이번 스캔이 볼 수 있었던 파일"만 삭제 대상이 되어야 한다.
  삭제된 파일은 glob 결과에 나오지 않으므로 glob 결과만으로는 판정할 수
  없다. 그래서 glob 과 **같은 규칙**을 다시 계산한다.
- **검증**: `test_scan_does_not_delete_other_scans`,
  `test_scan_removes_deleted_file`, `test_scan_dotfile_not_deleted_by_star`

### B-5. dict 가 아닌 JSON 줄에서 크래시
- **증상**: 결과 파일에 `[1]` 같은 줄이 섞여 있으면 `TypeError` 로 스캔이
  중단됐다.
- **해결**: 해당 줄을 손상된 줄로 보고 건너뛴다.
- **검증**: `test_load_existing_survives_non_dict_line`

### B-6. UTF-8 이 아닌 파일명 하나로 배치 전체 실패
- **증상**: 디렉터리에 `bad\xffname` 같은 파일이 하나라도 있으면
  `UnicodeEncodeError: surrogates not allowed` 로 스캔 전체가 실패했다.
  악성 샘플 폴더에는 이런 파일명이 흔하다.
- **원인**: Python 은 디코딩할 수 없는 파일명 바이트를 surrogate 문자
  (`\udcff`)로 보존한다. 이 문자는 UTF-8 로 인코딩할 수 없어서 JSONL 기록
  단계에서 예외가 났다.
- **해결**: 경로를 `surrogateescape → backslashreplace` 로 변환해 표시용
  문자열(`bad\xffname`)로 만든다. 파일 하나에서 예외가 나도 스캔이 계속되도록
  파일 단위로 예외를 격리했다.
- **검증**: `test_scan_survives_non_utf8_filename`. 처음 작성한 테스트는
  "죽지 않았는지"와 결과가 1행 이상인지만 확인했다. 지금은 해당 파일이 실제로
  적재돼 `scanned` 가 1 늘었는지, 결과 행 수가 `scanned` 와 같은지까지 검사한다.

---

## 5. risky (위험 함수 탐지)

### R-1. 수정이 만든 미탐 회귀
- **증상**: `puts("http://a.b"); strcpy(buf, s);` 에서 `strcpy` 를 놓쳤다.
  원본의 부분 문자열 방식은 이 경우를 탐지했으므로, O-5 수정이 만든
  **회귀**다.
- **원인**: 정규식으로 `//...` 주석을 지우면서 문자열 리터럴을 고려하지
  않았다. 문자열 안의 `//` 부터 줄 끝까지 지워지면서 실제 호출도 함께
  사라졌다.
- **해결**: 상태 기계(코드/문자열/문자/한줄주석/블록주석)로 한 번에 스캔해
  주석과 리터럴을 함께 공백으로 치환한다.
- **검증**: `test_risky_ignores_string_literal`, `test_risky_literal_only_not_flagged`
- **교훈**: 보안 도구에서는 미탐이 오탐보다 위험하다. 오탐을 줄이려는
  수정은 미탐 케이스까지 테스트해야 한다. 이 버그는 처음에 docstring 과
  decisions.md 에 "오탐 문제"로 잘못 적혀 있었다. 문서도 코드처럼 검증해야
  한다.

### R-2. 상태 기계의 경계 조건
| 입력 | 문제 | 해결 |
|---|---|---|
| `puts("abc);\nstrcpy(a, b);` | 닫히지 않은 따옴표가 뒤쪽 코드 전체를 삼킴 | C 리터럴은 줄을 넘지 않으므로 줄바꿈에서 code 상태로 복귀 |
| `int x = 1'000; strcpy(a,b);` | C23 자릿수 구분자를 문자 리터럴 시작으로 오인 | 앞 글자가 영숫자면 구분자로 처리 |
| `if (c == L'"') strcpy(a, b);` | 위 수정 때문에 `L'…'` 까지 구분자로 처리됨 | 조건을 "앞 글자가 **숫자**"로 좁힘 |

- **검증**: `test_risky_unterminated_quote_recovers`,
  `test_risky_digit_separator_quote`, `test_risky_wide_char_literal`

---

## 6. 기타

| 문제 | 해결 |
|---|---|
| `LOG_LEVEL` 에 잘못된 값이 들어오면 import 시점에 ValueError 로 서버가 뜨지 않음 | 유효하지 않은 값은 INFO 로 폴백 |
| `.dockerignore` 가 없어 `venv/`(85MB, macOS 바이너리)와 `.git` 이 이미지에 포함됨 | `.dockerignore` 추가 |
| `strcpy` 수정법으로 `strncpy` 를 권장했으나 NUL 종료를 보장하지 않고, `strlcpy` 는 glibc 2.38 미만에 없음 | 권장 문구 수정 |
| `is_vulnerable` 이 "위험 함수 사용"보다 과한 표현 | `uses_risky_functions` 추가(기존 키는 호환용으로 유지) |
| 커밋 작성자 이메일 오타(`gmail..com`)로 GitHub 계정에 커밋이 연결되지 않음 | 작성자 정보 수정 |
| MCP 서버 stderr 에 같은 로그가 두 번씩 찍힘. 모듈 로거의 핸들러와, root 로거로 전파된 뒤 MCP 쪽 핸들러가 각각 출력 | `logger.propagate = False` (프로토콜은 stdout 을 쓰므로 기능 영향은 없었음) |

---

## 알려진 한계 (의도적으로 남긴 것)

README 의 "한계" 절에 적은 항목들이다. 수정 비용이나 복잡도에 비해 실익이
작다고 판단했다.

- 정적 링크 바이너리는 libc 의 `__stack_chk_fail` 때문에 카나리가 오탐될
  수 있다(checksec 도 같다). import 심볼이 없어서 `critical_functions` 도
  비어 있을 수 있다.
- 같은 `output_path` 에 대한 동시 실행은 지원하지 않는다. 읽기→수정→쓰기
  구조라 나중에 끝난 쪽이 앞선 결과를 덮어쓴다.
- 파일시스템 접근 범위는 운영 측에서 제한해야 한다.
- `u8'x'` 문자 리터럴은 자릿수 구분자로 오인될 수 있다.

---

## 돌아보며

1. **고치는 과정에서 새 버그가 생긴다.** R-1, B-4, E-3 은 모두 이전 수정이
   만든 문제였다. 재현 케이스를 전부 회귀 테스트로 고정한 뒤에야 같은
   문제가 다시 생기지 않았다.
2. **반복되는 버그는 구조를 의심할 신호다.** mitigation 파서를 네 번 고친
   끝에 찾은 원인은 파서의 정규식이 아니라, 정확한 값을 문자열로 바꿨다가
   다시 파싱하는 구조(M-4)였다.
3. **skip 은 통과가 아니다.** macOS 에서 "테스트 통과"로 보였지만 핵심
   기능은 한 번도 실행되지 않았다(E-1). CI 와 skip 사유 확인이 필요하다.
4. **테스트 주석과 검증 내용이 일치하는지 확인한다.** "내용도 동일"이라고
   적고 줄 수만 비교한 테스트는 B-2 를 잡지 못했다.
5. **문서도 검증 대상이다.** "checksec 과 동일", ".so 는 PT_INTERP 가 없다",
   "오탐 문제였다" 같은 문장이 모두 사실과 달랐다.
