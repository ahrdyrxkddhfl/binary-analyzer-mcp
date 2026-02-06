import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.risky_tool import check_risky_functions


def test_risky_success():
    """정상 입력 테스트"""
    with open("tests/test_risky.json") as f:
        data = json.load(f)

    result = check_risky_functions(**data)

    assert "is_vulnerable" in result


def test_risky_invalid_input():
    """비정상 입력 테스트 (code_block 누락)"""
    result = check_risky_functions(code_block="", check_type="buffer_overflow")

    assert result["ok"] is False
