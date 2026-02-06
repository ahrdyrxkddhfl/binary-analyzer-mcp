import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from tools.mitigation_tool import get_exploit_mitigation_info


def test_mitigation_success():
    """정상 입력 테스트"""
    with open("tests/test_mitigation.json") as f:
        data = json.load(f)

    result = get_exploit_mitigation_info(**data)

    assert "difficulty" in result


def test_mitigation_invalid_input():
    """비정상 입력 테스트 (protection 누락)"""
    result = get_exploit_mitigation_info(protection="", target_vuln="BOF")

    assert result["ok"] is False
