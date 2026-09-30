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


def test_mitigation_checksec_all_disabled():
    """checksec 형식으로 전부 꺼진 문자열은 Low (회귀 방지)."""
    text = "Stack: No canary found, NX: NX disabled, PIE: No PIE, RELRO: No RELRO"
    result = get_exploit_mitigation_info(text, "buffer overflow")

    assert result["enabled_protections"] == []
    assert result["difficulty"] == "Low"


def test_mitigation_negation_forms():
    """다양한 부정 표기를 모두 꺼짐으로 판정한다."""
    for text in ["NX: disabled", "NX=off", "NX not enabled", "non-PIE"]:
        result = get_exploit_mitigation_info(text, "bof")
        assert result["enabled_protections"] == [], text


def test_mitigation_no_substring_false_match():
    """'position independent' 안의 'dep' 를 nx 로 오판하지 않는다."""
    result = get_exploit_mitigation_info("PIE: position independent", "bof")

    assert "nx" not in result["enabled_protections"]
    assert "pie" in result["enabled_protections"]


def test_mitigation_partial_relro_not_counted():
    """Partial RELRO 는 점수에 넣지 않는다(.got.plt 여전히 쓰기 가능)."""
    full = get_exploit_mitigation_info("Full RELRO", "bof")
    partial = get_exploit_mitigation_info("Partial RELRO", "bof")

    assert "relro:full" in full["enabled_protections"]
    assert "relro:partial" in partial["enabled_protections"]
    assert full["score"] > partial["score"]


def test_mitigation_relro_none_not_partial():
    """'RELRO none' 은 partial 이 아니라 아예 없는 것으로 본다(회귀)."""
    result = get_exploit_mitigation_info(
        "NX enabled, PIE enabled, No canary, RELRO none", "bof"
    )
    relro = [x for x in result["enabled_protections"] if "relro" in x]
    assert relro == []


def test_mitigation_relro_disabled_forms():
    """RELRO: disabled / RELRO off 도 none 으로 판정."""
    for text in ["RELRO: disabled", "RELRO off"]:
        result = get_exploit_mitigation_info(text, "bof")
        relro = [x for x in result["enabled_protections"] if "relro" in x]
        assert relro == [], text


def test_mitigation_full_scoped_to_relro():
    """다른 항목의 'full' 이 RELRO 로 새지 않는다."""
    result = get_exploit_mitigation_info("Canary: full, RELRO: partial", "bof")
    relro = [x for x in result["enabled_protections"] if "relro" in x]
    assert relro == ["relro:partial"]


def test_mitigation_newline_separator():
    """줄바꿈으로 구분된 여러 줄에서 다음 줄 상태가 새지 않는다."""
    result = get_exploit_mitigation_info("NX enabled\nPIE: No PIE", "bof")
    assert "nx" in result["enabled_protections"]
    assert "pie" not in result["enabled_protections"]


def test_mitigation_no_separator_relro():
    """구분자 없는 입력에서도 RELRO 와 NX 상태가 뒤섞이지 않는다."""
    result = get_exploit_mitigation_info(
        "NX disabled PIE enabled Full RELRO", "bof"
    )
    enabled = result["enabled_protections"]
    assert "nx" not in enabled
    assert "pie" in enabled
    assert "relro:full" in enabled


def test_score_protections_pure_function():
    """score_protections 는 문자열 파싱 없이 구조화된 값으로 계산한다."""
    from tools.mitigation_tool import score_protections
    high = score_protections(nx=True, pie=True, canary=True, relro="full")
    assert high["difficulty"] == "High"
    assert "relro:full" in high["enabled_protections"]

    low = score_protections(nx=False, pie=False, canary=False, relro="none")
    assert low["difficulty"] == "Low"
    assert low["enabled_protections"] == []

    # partial RELRO 는 점수 0.
    partial = score_protections(nx=False, pie=False, canary=False, relro="partial")
    assert partial["score"] == 0


def test_text_parser_matches_pure_function():
    """텍스트 파서 결과가 순수 함수 결과와 일치한다(왕복 무손실)."""
    from tools.mitigation_tool import score_protections
    parsed = get_exploit_mitigation_info(
        "NX enabled, PIE enabled, No canary, Full RELRO", "bof"
    )
    direct = score_protections(nx=True, pie=True, canary=False, relro="full")
    assert parsed["enabled_protections"] == direct["enabled_protections"]
    assert parsed["difficulty"] == direct["difficulty"]
