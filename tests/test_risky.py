"""risky_tool 테스트."""

import json
import os

from tools.risky_tool import check_risky_functions

_HERE = os.path.dirname(os.path.abspath(__file__))


def test_risky_success():
    """정상 입력: strcpy 를 잡고 사유·수정법을 함께 반환한다."""
    with open(os.path.join(_HERE, "test_risky.json")) as f:
        data = json.load(f)

    result = check_risky_functions(**data)

    assert result["ok"] is True
    assert result["is_vulnerable"] is True
    assert result["findings"][0]["reason"]
    assert result["findings"][0]["suggested_fix"]


def test_risky_ignores_comments():
    """주석 속 함수명은 오탐하지 않는다."""
    code = "// strcpy 쓰지 말 것\nstrncpy(a, b, n);"
    result = check_risky_functions(code, "buffer_overflow")

    assert result["is_vulnerable"] is False


def test_risky_no_false_match_on_prefix():
    """mystrcpy 같은 유사 이름을 strcpy 로 오탐하지 않는다."""
    result = check_risky_functions("mystrcpy(a, b);", "buffer_overflow")

    assert result["is_vulnerable"] is False


def test_risky_invalid_input():
    """빈 입력에 표준 에러 객체를 돌려준다."""
    result = check_risky_functions(code_block="", check_type="buffer_overflow")

    assert result["ok"] is False
    assert result["error"]["code"] == "INVALID_INPUT"


def test_risky_ignores_string_literal():
    """문자열 리터럴 안의 함수명은 오탐하지 않되, 실제 호출은 잡는다."""
    code = 'puts("http://a.b"); strcpy(buf, s);'
    result = check_risky_functions(code, "buffer_overflow")

    # strcpy 실제 호출은 잡아야 한다.
    assert "strcpy" in result["found_functions"]


def test_risky_literal_only_not_flagged():
    """리터럴에만 등장하고 실제 호출은 없으면 위험 아님."""
    code = 'printf("use gets carefully");'
    result = check_risky_functions(code, "buffer_overflow")

    assert result["uses_risky_functions"] is False


def test_risky_unterminated_quote_recovers():
    """닫히지 않은 따옴표 다음 줄의 실제 호출을 놓치지 않는다(회귀)."""
    code = 'puts("abc);\nstrcpy(a, b);'
    result = check_risky_functions(code, "buffer_overflow")
    assert "strcpy" in result["found_functions"]


def test_risky_digit_separator_quote():
    """C23 자릿수 구분자('의 홑따옴표) 이후 호출도 잡는다."""
    code = "int x = 1'000; strcpy(a, b);"
    result = check_risky_functions(code, "buffer_overflow")
    assert "strcpy" in result["found_functions"]
