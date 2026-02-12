import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

# tool 로직 import
from tools.symbol_tool import analyze_symbol_table
from tools.risky_tool import check_risky_functions
from tools.mitigation_tool import get_exploit_mitigation_info

# MCP 서버 생성
mcp = FastMCP("binary-analyzer")


# -----------------------------
# Tool 1: analyze_symbol_table
# -----------------------------
@mcp.tool()
def analyze_symbol(symbols: list, platform: str = "linux_x64") -> dict:
    """
    # WHY:
    바이너리에서 위험 가능성이 있는 핵심 함수들을 우선 분석 대상으로 분류

    # INPUT:
    symbols: 함수 이름 리스트
    platform: 실행 플랫폼

    # OUTPUT:
    위험 함수 분류 결과
    """
    return analyze_symbol_table(symbols, platform)


# -----------------------------
# Tool 2: check_risky_functions
# -----------------------------
@mcp.tool()
def check_risky(code_block: str, check_type: str = "buffer_overflow") -> dict:
    """
    # WHY:
    취약한 함수 사용 여부를 검사하여 실제 익스플로잇 가능성 판단

    # INPUT:
    code_block: C 코드 또는 어셈블리 코드
    check_type: 검사 유형

    # OUTPUT:
    취약 여부와 원인
    """
    return check_risky_functions(code_block, check_type)


# -----------------------------
# Tool 3: get_exploit_mitigation_info
# -----------------------------
@mcp.tool()
def mitigation(protection: str, target_vuln: str) -> dict:
    """
    # WHY:
    적용된 보호기법에 따라 공격 난이도와 필요한 기법을 설명

    # INPUT:
    protection: 적용된 보호기법 문자열
    target_vuln: 대상 취약점 유형

    # OUTPUT:
    공격 난이도 및 이론 설명
    """
    return get_exploit_mitigation_info(protection, target_vuln)


# 서버 실행
if __name__ == "__main__":
    mcp.run(transport='stdio')
