"""mitigation_tool 테스트."""

import json
import os

from tools.mitigation_tool import get_exploit_mitigation_info

_HERE = os.path.dirname(os.path.abspath(__file__))


def test_mitigation_success():
    """모든 보호기법이 켜지면 High."""
    with open(os.path.join(_HERE, "test_mitigation.json")) as f:
        data = json.load(f)

    result = get_exploit_mitigation_info(**data)

    assert result["ok"] is True
    assert result["difficulty"] == "High"


def test_mitigation_disabled_is_low():
    """보호기법이 다 꺼졌으면 Low (기존 버그: 문자열 매칭으로 Medium)."""
    result = get_exploit_mitigation_info(
        "NX disabled, No PIE, No canary, No RELRO", "buffer overflow"
    )

    assert result["difficulty"] == "Low"
    assert result["enabled_protections"] == []


def test_mitigation_nx_only_is_medium():
    """NX 만 켜졌으면 Medium."""
    result = get_exploit_mitigation_info(
        "NX enabled, No PIE, No canary", "buffer overflow"
    )

    assert result["difficulty"] == "Medium"
    assert "nx" in result["enabled_protections"]


def test_mitigation_invalid_input():
    """protection 누락 시 표준 에러 객체."""
    result = get_exploit_mitigation_info(protection="", target_vuln="BOF")

    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_INPUT"
