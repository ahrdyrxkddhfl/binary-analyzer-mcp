"""ELF 바이너리 자동 분석 툴.

실제 ELF 파일을 받아 (1) 임포트된 함수 심볼과 (2) 적용된 보호기법
(NX/PIE/Canary/RELRO)을 직접 파싱한다. checksec 이 하는 판정을
pyelftools 로 구현한 것으로, 사람이 심볼 목록을 손으로 넣지 않아도
바이너리 하나로 symbol/mitigation 분석까지 이어갈 수 있게 한다.

pyelftools 를 쓰는 이유: readelf/checksec 같은 외부 실행 파일에
의존하지 않고 순수 파이썬으로 ELF 구조를 읽기 위함. 배포 환경(도커,
Smithery)에 바이너리 유틸이 없어도 동작한다.
"""

import os

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection

from common import make_error, get_logger
from tools.symbol_tool import analyze_symbol_table
from tools.mitigation_tool import score_protections, build_mitigation_result

logger = get_logger(__name__)

# GNU_STACK 세그먼트의 실행 권한 플래그. 이 비트가 켜져 있으면 스택이
# 실행 가능(NX 꺼짐)하다는 뜻이다. ELF 스펙에 정의된 고정 값이므로
# 이름 붙인 상수로 둔다.
_PF_X = 0x1


def _read_imported_symbols(elf: ELFFile) -> list:
    """ELF 가 외부에서 가져다 쓰는(import) 함수 심볼 이름을 뽑는다.

    함수 타입(STT_FUNC)이면서 정의부가 이 바이너리에 없는(SHN_UNDEF)
    심볼만 모은다. 이게 "이 바이너리가 호출하는 외부 함수"에 해당한다.
    이 필터가 없으면 파일명(Scrt1.o), 내부 변수(_DYNAMIC), 로컬 심볼
    까지 섞여 들어와 위험 함수 분류가 오염된다. 버전 접미사
    (printf@GLIBC_2.2.5)는 떼어 순수 이름만 남긴다.

    Args:
        elf: 열린 ELFFile 객체.

    Returns:
        중복 제거된 임포트 함수 이름 리스트.
    """
    names = set()
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            if not name:
                continue
            info = symbol["st_info"]
            # 함수 타입만.
            if info["type"] != "STT_FUNC":
                continue
            # 정의부가 이 바이너리에 없는(외부에서 가져오는) 것만.
            if symbol["st_shndx"] != "SHN_UNDEF":
                continue
            names.add(name.split("@")[0])
    return sorted(names)


def _detect_nx(elf: ELFFile) -> bool:
    """NX(스택 실행 방지) 활성 여부.

    GNU_STACK 세그먼트에 실행 권한 플래그가 없으면 NX 가 켜진 것이다.
    세그먼트가 아예 없으면 checksec/pwntools 는 NX disabled 로
    판정하므로 여기서도 그 관례를 따른다(스택 실행 가능으로 간주).

    Returns:
        NX 가 켜져 있으면 True.
    """
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & _PF_X)
    return False


def _detect_pie(elf: ELFFile) -> bool:
    """PIE(위치 독립 실행) 활성 여부.

    ET_DYN 은 PIE 실행 파일과 공유 라이브러리(.so)가 공유하는 타입
    이라, ET_DYN 만으로 PIE 라 하면 .so 까지 PIE 로 오판한다. 두 신호로
    구분한다: (1) 동적 플래그 DT_FLAGS_1 의 DF_1_PIE 비트, (2) 프로그램
    인터프리터 세그먼트 PT_INTERP 가 있으면서 DT_SONAME 이 없을 때.

    PT_INTERP 만으로는 부족하다. libc.so.6 처럼 직접 실행도 되는 공유
    라이브러리는 PT_INTERP 를 갖기 때문이다. 다만 공유 라이브러리는
    거의 항상 DT_SONAME(라이브러리 이름)을 갖고 PIE 실행 파일은 갖지
    않으므로, PT_INTERP 가 있고 DT_SONAME 이 없을 때만 PIE 로 본다.
    DF_1_PIE 는 비교적 최근 binutils 부터 설정되므로 이 조합을 함께
    쓴다. (checksec.sh 는 전통적으로 DT_DEBUG 유무로 판별한다.)

    Returns:
        PIE 실행 파일이면 True.
    """
    if elf.header["e_type"] != "ET_DYN":
        return False

    _DF_1_PIE = 0x08000000  # DT_FLAGS_1 의 DF_1_PIE 비트(ELF 스펙 고정값).
    has_soname = False
    has_pie_flag = False
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_SONAME":
                    has_soname = True
                if tag.entry.d_tag == "DT_FLAGS_1" and (
                    tag.entry.d_val & _DF_1_PIE
                ):
                    has_pie_flag = True

    if has_pie_flag:
        return True

    # PT_INTERP 가 있으면서 SONAME 이 없으면 PIE 실행 파일.
    # (libc 같은 실행 가능 .so 는 SONAME 이 있어 여기서 걸러진다.)
    if not has_soname:
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                return True

    return False


def _detect_canary(elf: ELFFile) -> bool:
    """스택 카나리 활성 여부.

    스택 보호가 켜지면 컴파일러가 __stack_chk_fail 심볼을 참조한다.
    그 심볼이 있으면 카나리가 적용된 것으로 판단한다.
    """
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if symbol.name and "__stack_chk_fail" in symbol.name:
                return True
    return False


def _detect_relro(elf: ELFFile) -> str:
    """RELRO 수준을 판정한다.

    GNU_RELRO 세그먼트가 없으면 NONE. 있으면서 동적 태그에 BIND_NOW
    가 있으면 FULL, 없으면 PARTIAL 이다.

    Returns:
        "FULL", "PARTIAL", "NONE" 중 하나.
    """
    has_relro = any(
        seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments()
    )
    if not has_relro:
        return "NONE"

    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    return "FULL"
                # DT_FLAGS 에 BIND_NOW 비트가 설정된 경우도 Full 로 본다.
                if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                    return "FULL"
    return "PARTIAL"


def analyze_elf(path: str) -> dict:
    """ELF 파일 하나를 열어 심볼과 보호기법을 함께 분석한다.

    Args:
        path: 분석할 ELF 파일 경로.

    Returns:
        성공 시 보호기법 상태(protections), 위험 심볼 분류
        (symbol_analysis), 보호기법 기반 난이도(mitigation_analysis)를
        묶은 딕셔너리. 파일이 없거나 ELF 가 아니면 표준 에러 객체.
    """
    if not path or not os.path.isfile(path):
        return make_error(
            code="FILE_NOT_FOUND",
            message=f"file not found: {path}",
            hint="Provide a path to an existing ELF file",
        )

    try:
        with open(path, "rb") as f:
            # ELF 매직 넘버 확인 — 엉뚱한 파일에 파서를 태우지 않는다.
            magic = f.read(4)
            if magic != b"\x7fELF":
                return make_error(
                    code="NOT_ELF",
                    message="file is not an ELF binary",
                    hint="Only ELF binaries are supported",
                )
            f.seek(0)
            elf = ELFFile(f)

            # 재배치 가능 오브젝트(.o, ET_REL)는 실행 파일/라이브러리가
            # 아니라 보호기법 개념이 적용되지 않는다. 분석 대상에서
            # 제외한다(배치 스캔에서 skip 으로 집계).
            if elf.header["e_type"] == "ET_REL":
                return make_error(
                    code="UNSUPPORTED_ELF_TYPE",
                    message="relocatable object (.o) is not an executable/library",
                    hint="Provide a linked executable or shared object",
                )

            symbols = _read_imported_symbols(elf)
            nx = _detect_nx(elf)
            pie = _detect_pie(elf)
            canary = _detect_canary(elf)
            relro = _detect_relro(elf)
    except Exception as e:  # pyelftools 가 던지는 파싱 오류 포괄
        logger.exception("analyze_elf failed for %s", path)
        return make_error(
            code="PARSE_ERROR",
            message=f"failed to parse ELF: {e}",
            hint="File may be corrupted or an unsupported ELF variant",
            retryable=False,
        )

    # 보호기법을 mitigation 툴이 이해하는 문자열로 조립한다. 이렇게 해서
    # 사람이 손으로 만들던 protection 문자열을 자동 생성한다.
    protection_parts = [
        f"NX {'enabled' if nx else 'disabled'}",
        f"PIE {'enabled' if pie else 'disabled'}",
        f"Canary {'enabled' if canary else 'disabled'}",
        f"RELRO {relro.lower()}",
    ]
    protection_str = ", ".join(protection_parts)

    symbol_analysis = analyze_symbol_table(symbols)

    # 이미 정확한 불리언/열거값을 알고 있으므로, 문자열로 바꿨다가 다시
    # 파싱하지 않고 순수 함수 score_protections 에 값을 직접 넘긴다.
    # 이렇게 하면 핵심 경로에 텍스트 파서 버그가 끼어들 수 없다.
    scored = score_protections(nx, pie, canary, relro.lower())
    mitigation_analysis = build_mitigation_result(
        scored, protection_str, "buffer overflow"
    )

    safe_name = os.path.basename(path).encode(
        "utf-8", "surrogateescape"
    ).decode("utf-8", "backslashreplace")

    logger.info(
        "analyze_elf: %s | NX=%s PIE=%s Canary=%s RELRO=%s | %d symbols",
        safe_name,
        nx,
        pie,
        canary,
        relro,
        len(symbols),
    )

    return {
        "ok": True,
        "file": safe_name,
        "protections": {
            "nx": nx,
            "pie": pie,
            "canary": canary,
            "relro": relro,
        },
        "protection_string": protection_str,
        "symbol_count": len(symbols),
        "symbol_analysis": symbol_analysis,
        "mitigation_analysis": mitigation_analysis,
    }
