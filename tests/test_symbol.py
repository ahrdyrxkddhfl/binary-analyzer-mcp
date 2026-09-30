"""symbol_tool 테스트."""

import json
import os

from tools.symbol_tool import analyze_symbol_table

# 테스트 데이터는 이 파일 기준 경로로 읽는다(실행 위치 무관).
_HERE = os.path.dirname(os.path.abspath(__file__))


def test_symbol_success():
    """정상 입력: 위험 심볼이 카테고리별로 잡히고 우선순위가 High."""
    with open(os.path.join(_HERE, "test_symbol.json")) as f:
        data = json.load(f)

    result = analyze_symbol_table(**data)

    assert result["ok"] is True
    assert "critical_functions" in result
    assert isinstance(result["critical_functions"], list)


def test_symbol_multi_category():
    """여러 카테고리가 모두 보존되는지(기존 버그: 마지막만 남음)."""
    result = analyze_symbol_table(["socket", "system", "strcpy"])

    cats = result["categories"]
    assert "network" in cats
    assert "execution" in cats
    assert "memory" in cats


def test_symbol_invalid_input():
    """None 입력에 예외 대신 표준 에러 객체를 돌려준다."""
    result = analyze_symbol_table(symbols=None, platform="linux_x64")

    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_INPUT"
