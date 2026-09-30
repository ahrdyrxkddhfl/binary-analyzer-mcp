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


def _strip_comments(code: str) -> str:
    """C 스타일 주석(// ..., /* ... */)을 제거한다.

    주석 안에 적힌 함수명을 실제 호출로 오탐하지 않기 위함이다
    (예: "// strcpy 쓰지 말 것").

    Args:
        code: 원본 코드 문자열.

    Returns:
        주석이 공백으로 치환된 코드 문자열.
    """
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)
    code = re.sub(r"//[^\n]*", " ", code)
    return code


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

    # 주석을 걷어내고 실제 호출만 검사한다.
    cleaned = _strip_comments(code_block)

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

    return {
        "ok": True,
        "is_vulnerable": len(findings) > 0,
        "check_type": check_type,
        "found_functions": [f["function"] for f in findings],
        "findings": findings,
    }
