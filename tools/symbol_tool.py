# WHY:
# 바이너리에서 추출된 함수 목록 중
# 악성 행위나 취약점과 관련된 중요 함수를 식별

# INPUT:
# symbols: 함수 이름 리스트
# platform: 플랫폼 정보 (현재는 참고용)

# OUTPUT:
# critical_functions: 분석 우선 대상 함수 목록
# category: 기능 카테고리
# analysis_priority: 우선순위


CRITICAL_FUNCTIONS = {
    "network": ["socket", "connect", "accept", "recv", "send"],
    "execution": ["system", "execve", "popen"],
    "file": ["open", "read", "write"],
    "memory": ["strcpy", "gets", "scanf", "memcpy"]
}


def analyze_symbol_table(symbols, platform="linux_x64"):
    found = []
    category = "Unknown"

    for cat, funcs in CRITICAL_FUNCTIONS.items():
        for f in funcs:
            if f in symbols:
                found.append(f)
                category = cat.capitalize()

    priority = "High" if found else "Low"

    return {
        "critical_functions": found,
        "category": category,
        "analysis_priority": priority
    }
