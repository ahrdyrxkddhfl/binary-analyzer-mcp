"""위험 함수 사용 탐지 툴.

C 코드 또는 pseudo-code 블록에서 버퍼 오버플로우 등 취약점을 유발할
수 있는 함수 사용을 찾는다. 탐지 대상과 각 함수의 사유·수정 방법은
config.yaml 의 dangerous_functions 에서 읽는다.
"""

import re

from config_loader import load_config
from common import make_error, get_logger

logger = get_logger(__name__)

# 함수 호출을 식별하기 위한 정규식 조각. 함수명 뒤에 여는 괄호가 오고,
# 앞에는 식별자 문자가 없어야 한다(strcpy 가 mystrcpy 에 오탐되는 것 방지).
_CALL_PATTERN = r"(?<![A-Za-z0-9_])%s\s*\("


def _strip_comments_and_strings(code: str) -> str:
    """C 스타일 주석과 문자열/문자 리터럴을 공백으로 치환한다.

    주석뿐 아니라 문자열 리터럴도 지운다. 앞서 정규식으로 주석만
    지웠을 때의 실제 회귀는 미탐이었다. 예를 들어 puts("http://a.b")
    의 "//" 를 한줄주석 시작으로 오인해 그 줄 뒤쪽(실제 strcpy 호출
    포함)을 통째로 주석 처리해 버려, 위험 호출을 놓쳤다. 리터럴을
    먼저 인식해 통째로 공백 처리하면 리터럴 안의 "//" 나 함수명이
    파싱에 영향을 주지 않아 이 미탐이 사라진다.

    처리 순서가 중요하다. 주석 기호가 문자열 안에 있거나("// not a
    comment") 문자열 기호가 주석 안에 있을 수 있으므로, 한 번의 스캔
    으로 상태(일반/문자열/문자/한줄주석/블록주석)를 따라가며 지운다.
    문자열/문자 리터럴이 닫는 따옴표 없이 줄이 끝나면(잘린 코드) 그
    줄에서 리터럴을 끝내, 여는 따옴표 하나가 뒤 코드를 삼키지 않게 한다.

    Args:
        code: 원본 코드 문자열.

    Returns:
        주석과 리터럴이 공백으로 치환된 코드 문자열.
    """
    out = []
    i = 0
    n = len(code)
    state = "code"  # code | line_comment | block_comment | string | char
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
            elif c == "/" and nxt == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
            elif c == '"':
                state = "string"
                out.append(" ")
                i += 1
            elif c == "'":
                # C23 자릿수 구분자(1'000)의 홑따옴표는 문자 리터럴이
                # 아니다. 바로 앞 글자가 영숫자면 구분자로 보고 리터럴로
                # 진입하지 않는다(그대로 두어도 함수 호출 탐지에 무해).
                prev = code[i - 1] if i > 0 else ""
                if prev.isalnum():
                    out.append(c)
                    i += 1
                else:
                    state = "char"
                    out.append(" ")
                    i += 1
            else:
                out.append(c)
                i += 1
        elif state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif state in ("string", "char"):
            quote = '"' if state == "string" else "'"
            if c == "\n":
                # C 문자열/문자 리터럴은 한 줄을 넘어갈 수 없다. 닫는
                # 따옴표 없이 줄이 끝나면(붙여넣다 잘린 코드 등) 리터럴이
                # 아니라고 보고 code 상태로 복귀한다. 이렇게 하지 않으면
                # 여는 따옴표 하나가 그 뒤 코드 전체를 리터럴로 삼켜
                # 실제 위험 호출을 놓친다(미탐).
                state = "code"
                out.append("\n")
                i += 1
            elif c == "\\":
                # 이스케이프 문자는 다음 한 글자와 함께 건너뛴다.
                out.append("  ")
                i += 2
            elif c == quote:
                state = "code"
                out.append(" ")
                i += 1
            else:
                out.append(" ")
                i += 1
    return "".join(out)


def check_risky_functions(code_block: str, check_type: str = "buffer_overflow") -> dict:
    """코드 블록에서 위험 함수 호출을 찾는다.

    Args:
        code_block: 검사할 C 코드 또는 pseudo-code.
        check_type: 검사 유형 라벨. 결과에 기록되며, 호출자가 어떤
            관점으로 검사했는지 구분하는 용도다.

    Returns:
        성공 시 취약 여부(is_vulnerable)와 걸린 함수별 사유·수정
        방법(findings)을 담은 딕셔너리. 입력이 없으면 표준 에러 객체.
    """
    # EDGE CASE: 입력 누락
    if not code_block:
        return make_error(
            code="INVALID_INPUT",
            message="code_block is required",
            hint="Provide a valid code snippet",
        )

    config = load_config()
    dangerous = config["dangerous_functions"]

    # 주석과 문자열 리터럴을 걷어내고 실제 호출만 검사한다.
    cleaned = _strip_comments_and_strings(code_block)

    findings = []
    for name, info in dangerous.items():
        if re.search(_CALL_PATTERN % re.escape(name), cleaned):
            # config 에 적어 둔 사유·수정법을 그대로 실어 보낸다
            # (기존에는 문서에만 있고 실제로 반환하지 않았다).
            findings.append(
                {
                    "function": name,
                    "reason": info["reason"],
                    "suggested_fix": info["fix"],
                    "severity": info.get("severity", "unknown"),
                }
            )

    logger.info(
        "check_risky (%s): %d risky call(s) found",
        check_type,
        len(findings),
    )

    uses_risky = len(findings) > 0
    return {
        "ok": True,
        # "위험 함수 사용 여부"가 정확한 의미. is_vulnerable 은 실제
        # 취약점 존재를 단정하는 과한 표현이라 uses_risky_functions 로
        # 바꾸되, 기존 호출자를 위해 별칭도 남긴다.
        "uses_risky_functions": uses_risky,
        "is_vulnerable": uses_risky,
        "check_type": check_type,
        "found_functions": [f["function"] for f in findings],
        "findings": findings,
    }
