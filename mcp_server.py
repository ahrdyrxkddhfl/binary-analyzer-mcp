"""binary-analyzer-mcp 서버 진입점.

바이너리/코드 분석 툴을 MCP(Model Context Protocol) 툴로 노출한다.
LLM 이 이 툴들을 호출해 심볼 분석 → 위험 함수 검사 → 보호기법 기반
난이도 설명 → 실제 ELF 자동 분석/배치 스캔까지 이어갈 수 있다.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# mcp 2.x 에서 FastMCP 가 MCPServer 로 이름이 바뀌었다. 구버전
# (mcp<2)에서도 돌아가도록 폴백 임포트를 둔다.
try:
    from mcp.server.mcpserver import MCPServer
except ImportError:  # pragma: no cover - 구버전 호환용
    from mcp.server.fastmcp import FastMCP as MCPServer

from tools.symbol_tool import analyze_symbol_table
from tools.risky_tool import check_risky_functions
from tools.mitigation_tool import get_exploit_mitigation_info
from tools.elf_tool import analyze_elf as analyze_elf_file
from tools.batch_tool import scan_directory as scan_directory_impl

mcp = MCPServer("binary-analyzer")


@mcp.tool()
def analyze_symbol(symbols: list, platform: str = "linux_x64") -> dict:
    """바이너리 함수 목록에서 위험 함수를 카테고리별로 분류한다.

    Args:
        symbols: 함수 이름 리스트.
        platform: 실행 플랫폼(기록용).

    Returns:
        카테고리별 위험 함수 분류 결과.
    """
    return analyze_symbol_table(symbols, platform)


@mcp.tool()
def check_risky(code_block: str, check_type: str = "buffer_overflow") -> dict:
    """C/pseudo 코드에서 위험 함수 사용 여부를 검사한다.

    Args:
        code_block: 검사할 코드.
        check_type: 검사 유형 라벨.

    Returns:
        취약 여부와 함수별 사유·수정 방법.
    """
    return check_risky_functions(code_block, check_type)


@mcp.tool()
def mitigation(protection: str, target_vuln: str) -> dict:
    """보호기법 조합으로 익스플로잇 난이도와 이론을 설명한다.

    Args:
        protection: 보호기법 설명 문자열.
        target_vuln: 대상 취약점 유형.

    Returns:
        난이도와 보호기법별 이론 설명.
    """
    return get_exploit_mitigation_info(protection, target_vuln)


@mcp.tool()
def analyze_elf(path: str) -> dict:
    """실제 ELF 파일을 열어 심볼과 보호기법을 자동 분석한다.

    Args:
        path: ELF 파일 경로.

    Returns:
        보호기법(NX/PIE/Canary/RELRO), 심볼 분류, 난이도를 묶은 결과.
    """
    return analyze_elf_file(path)


@mcp.tool()
def scan_directory(
    directory: str,
    output_path: str = "scan_results.jsonl",
    pattern: str = "*",
) -> dict:
    """디렉터리 내 ELF 파일을 배치로 분석해 JSONL 로 적재한다(멱등).

    Args:
        directory: 스캔할 디렉터리.
        output_path: 결과 JSONL 경로.
        pattern: 파일 glob 패턴.

    Returns:
        입력/처리/스킵/에러 건수 요약.
    """
    return scan_directory_impl(directory, output_path, pattern)


if __name__ == "__main__":
    mcp.run(transport="stdio")
