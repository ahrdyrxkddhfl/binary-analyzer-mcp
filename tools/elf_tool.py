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

from config_loader import load_config
from common import make_error, get_logger
from tools.symbol_tool import analyze_symbol_table
from tools.mitigation_tool import get_exploit_mitigation_info

logger = get_logger(__name__)

# GNU_STACK 세그먼트의 실행 권한 플래그. 이 비트가 켜져 있으면 스택이
# 실행 가능(NX 꺼짐)하다는 뜻이다. ELF 스펙에 정의된 고정 값이므로
# 이름 붙인 상수로 둔다.
_PF_X = 0x1


def _read_imported_symbols(elf: ELFFile) -> list:
    """ELF 에서 참조된 함수 심볼 이름을 뽑는다.

    동적 심볼 테이블(.dynsym)과 일반 심볼 테이블(.symtab)을 모두 훑어
    함수 심볼 이름을 모은다. 버전 접미사(printf@GLIBC_2.2.5)는 떼어
    순수 이름만 남긴다.

    Args:
        elf: 열린 ELFFile 객체.

    Returns:
        중복 제거된 함수 심볼 이름 리스트.
    """
    names = set()
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            if not name:
                continue
            # printf@GLIBC_2.2.5 -> printf
            name = name.split("@")[0]
            names.add(name)
    return sorted(names)


def _detect_nx(elf: ELFFile) -> bool:
    """NX(스택 실행 방지) 활성 여부.

    GNU_STACK 세그먼트에 실행 권한 플래그가 없으면 NX 가 켜진 것이다.
    세그먼트 자체가 없으면 커널 기본값을 따르므로 켜진 것으로 본다.
    """
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & _PF_X)
    return True


def _detect_pie(elf: ELFFile) -> bool:
    """PIE(위치 독립 실행) 활성 여부.

    ELF 타입이 ET_DYN 이면서 실행 파일이면 PIE 다. 공유 라이브러리도
    ET_DYN 이지만 여기서는 실행 파일 분석을 전제로 한다.
    """
    return elf.header["e_type"] == "ET_DYN"


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
    mitigation_analysis = get_exploit_mitigation_info(
        protection_str, target_vuln="buffer overflow"
    )

    logger.info(
        "analyze_elf: %s | NX=%s PIE=%s Canary=%s RELRO=%s | %d symbols",
        os.path.basename(path),
        nx,
        pie,
        canary,
        relro,
        len(symbols),
    )

    return {
        "ok": True,
        "file": os.path.basename(path),
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
