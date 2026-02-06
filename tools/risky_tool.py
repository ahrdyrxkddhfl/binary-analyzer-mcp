# WHY:
# 코드 블록 내에서 버퍼 오버플로우 등
# 취약점 유발 가능 함수 사용 여부 탐지

# INPUT:
# code_block: C 코드 또는 pseudo code
# check_type: 검사 유형 (현재는 buffer_overflow 중심)

# OUTPUT:
# is_vulnerable: 취약 여부
# reason: 취약 이유
# suggested_fix: 수정 방법


DANGEROUS_FUNCTIONS = {
    "strcpy": "입력 길이 제한이 없어 버퍼 오버플로우 발생 가능",
    "gets": "길이 제한 없는 입력으로 오버플로우 발생",
    "scanf": "형식 지정자 없이 사용 시 오버플로우 가능"
}


def check_risky_functions(code_block: str, check_type: str):
    # EDGE CASE: 입력 누락
    if not code_block:
        return {
            "ok": False,
            "error": {
                "code": "INVALID_INPUT",
                "message": "code_block is required",
                "hint": "Provide a valid code snippet",
                "retryable": False
            }
        }

    risky_functions = ["strcpy", "gets", "scanf", "sprintf"]

    found = [f for f in risky_functions if f in code_block]

    return {
        "ok": True,
        "is_vulnerable": len(found) > 0,
        "found_functions": found,
        "check_type": check_type
    }
