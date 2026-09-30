"""보호기법 기반 익스플로잇 난이도 설명 툴.

바이너리에 적용된 보호기법 조합을 받아 공격 난이도를 추정하고,
각 보호기법이 공격에 어떤 제약을 주는지 이론적으로 설명한다.
가중치와 난이도 구간은 config.yaml 에서 읽는다.
"""

import re

from config_loader import load_config
from common import make_error, get_logger

logger = get_logger(__name__)

# 보호기법 이름 → config 키. 문자열에서 이 별칭들을 찾아 어떤
# 보호기법을 말하는지 식별한다.
_ALIASES = {
    "nx": ["nx", "dep", "no-execute"],
    "canary": ["canary", "stack canary", "stack_chk", "ssp"],
    "pie": ["pie", "aslr", "position independent"],
    "relro": ["relro"],
}

# 각 보호기법이 공격에 주는 제약 설명. 난이도 근거를 사람이 읽을 수
# 있게 덧붙이는 용도.
_THEORY = {
    "nx": "데이터 영역 실행이 막혀 셸코드를 직접 올려 실행할 수 없다. ROP/ret2libc 등 코드 재사용 공격이 필요하다.",
    "canary": "스택 카나리가 있어 스택 버퍼 오버플로우로 저장된 복귀 주소를 덮으려면 카나리 값을 먼저 알아내야 한다.",
    "pie": "실행 파일이 위치 독립이라 주소가 실행마다 바뀐다. 주소 유출(info leak)로 베이스를 먼저 구해야 한다.",
    "relro": "GOT가 읽기 전용이라 GOT 덮어쓰기로 흐름을 가로채는 공격이 막힌다(Full RELRO 기준).",
}


def _is_enabled(protection_text: str, aliases: list) -> bool:
    """보호기법 문자열에서 특정 기법이 '켜져' 있는지 판정한다.

    기존 버그의 핵심 수정 지점이다. 단순히 "NX" 가 문자열에 들어
    있는지만 보면 "NX disabled" 도 켜진 것으로 오판한다. 여기서는
    별칭이 등장한 위치 주변에 부정어(disabled, no, off, none)가 있는지
    확인해 실제 활성 여부를 가린다.

    Args:
        protection_text: 소문자로 바꾼 보호기법 설명 문자열.
        aliases: 해당 보호기법을 가리키는 별칭 목록.

    Returns:
        해당 보호기법이 활성으로 판단되면 True.
    """
    for alias in aliases:
        for m in re.finditer(re.escape(alias), protection_text):
            # 별칭 "바로 앞" 표현만 본다. 넓은 윈도우로 보면 뒤따르는
            # 다른 항목의 부정어(예: "NX enabled, no PIE")까지 삼켜
            # 오판한다. 앞쪽 부정 접두(no/not/without)와 뒤쪽 상태어
            # (disabled/off)만 각각 확인한다.
            before = protection_text[max(0, m.start() - 8):m.start()]
            after = protection_text[m.end():m.end() + 10]
            if re.search(r"(no|not|without)[\s_-]*$", before):
                continue
            if re.search(r"^\s*(disabled|disable|off|none)", after):
                continue
            return True
    return False


def get_exploit_mitigation_info(protection: str, target_vuln: str) -> dict:
    """보호기법 조합으로 익스플로잇 난이도를 추정한다.

    Args:
        protection: 적용된 보호기법 설명 문자열
            (예: "NX enabled, PIE enabled, No canary").
        target_vuln: 대상 취약점 유형(예: "buffer overflow").

    Returns:
        성공 시 난이도(difficulty), 켜진 보호기법 목록(enabled),
        각 기법의 이론 설명(theory)을 담은 딕셔너리. 입력이 없으면
        표준 에러 객체.
    """
    if not protection or not target_vuln:
        return make_error(
            code="INVALID_INPUT",
            message="protection and target_vuln are required",
            hint="Provide both fields",
        )

    config = load_config()
    weights = config["mitigation_weights"]
    thresholds = config["difficulty_thresholds"]

    text = protection.lower()

    enabled = []
    score = 0
    theory = {}
    for key, aliases in _ALIASES.items():
        if _is_enabled(text, aliases):
            enabled.append(key)
            score += weights.get(key, 0)
            theory[key] = _THEORY[key]

    # config 의 구간으로 점수를 난이도로 환산한다.
    if score >= thresholds["high_min"]:
        difficulty = "High"
    elif score >= thresholds["medium_min"]:
        difficulty = "Medium"
    else:
        difficulty = "Low"

    logger.info(
        "mitigation: score=%d enabled=%s -> %s",
        score,
        enabled,
        difficulty,
    )

    return {
        "ok": True,
        "protection": protection,
        "target_vulnerability": target_vuln,
        "enabled_protections": enabled,
        "score": score,
        "difficulty": difficulty,
        "theory": theory,
        "analysis": (
            f"Exploit difficulty estimated as {difficulty} "
            f"(score {score}) based on enabled protections: "
            f"{', '.join(enabled) if enabled else 'none'}."
        ),
    }
