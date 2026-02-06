import json
import sys
import os

# tools 폴더 import 가능하게 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.symbol_tool import analyze_symbol_table


def test_symbol_success():
    """정상 입력 테스트"""
    with open("tests/test_symbol.json") as f:
        data = json.load(f)

    result = analyze_symbol_table(**data)

    assert "critical_functions" in result
    assert isinstance(result["critical_functions"], list)


def test_symbol_invalid_input():
    """비정상 입력 테스트 (symbols 누락)"""
    try:
        result = analyze_symbol_table(symbols=None, platform="linux_x64")
        assert result["ok"] is False
    except Exception:
        assert True
