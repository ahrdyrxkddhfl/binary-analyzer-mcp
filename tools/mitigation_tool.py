"""보호기법 기반 익스플로잇 난이도 설명 툴.

바이너리에 적용된 보호기법 조합을 받아 공격 난이도를 추정하고,
각 보호기법이 공격에 어떤 제약을 주는지 이론적으로 설명한다.
가중치와 난이도 구간은 config.yaml 에서 읽는다.

입력 문자열은 사람이 쓴 표기, checksec/pwntools 출력 등 형식이
제각각이므로, 각 보호기법마다 (1) 그 기법을 가리키는 별칭 토큰과
(2) "꺼짐"을 뜻하는 부정 패턴을 명시적으로 두고, 별칭이 등장했고
부정 표현이 없을 때만 "켜짐"으로 본다. RELRO 는 full/partial 을
구분한다.
"""

import re

from config_loader import load_config
from common import make_error, get_logger

logger = get_logger(__name__)

# 각 보호기법을 가리키는 별칭. 단어 경계로 감싸 매칭하므로
# "independent" 안의 "dep" 같은 부분 문자열 오탐이 없다.
# 여러 단어 별칭(position independent)은 공백을 포함해 그대로 찾는다.
_ALIASES = {
    "nx": [r"nx", r"dep", r"no[\s_-]?execute", r"nx[\s_-]?bit"],
    "canary": [r"canary", r"stack[\s_-]?canary", r"stack_chk", r"ssp", r"stack[\s_-]?protector"],
    "pie": [r"pie", r"pic", r"position[\s_-]?independent"],
    "relro": [r"relro"],
}

# 각 보호기법의 "꺼짐"을 뜻하는 표현. 별칭 근처(구분자 :/= 포함)에
# 이 패턴이 있으면 비활성으로 본다. checksec 의 "No canary found",
# "NX disabled", "No PIE", pwntools 의 "NX:      No" 등을 포괄한다.
_DISABLED = re.compile(
    r"(disabled|disable|\bno\b|\bnone\b|\boff\b|not[\s_-]+enabled|"
    r"\bnon[\s_-]?|\bnot\b|\bfalse\b)"
)

# RELRO 수준은 _relro_level 에서 별칭 주변 구간을 잘라 판정한다.

# 각 보호기법이 공격에 주는 제약 설명. 난이도 근거를 사람이 읽을 수
# 있게 덧붙이는 용도.
_THEORY = {
    "nx": "데이터 영역 실행이 막혀 셸코드를 직접 올려 실행할 수 없다. ROP/ret2libc 등 코드 재사용 공격이 필요하다.",
    "canary": "스택 카나리가 있어 스택 버퍼 오버플로우로 저장된 복귀 주소를 덮으려면 카나리 값을 먼저 알아내야 한다.",
    "pie": "실행 파일이 위치 독립이라 주소가 실행마다 바뀐다. 주소 유출(info leak)로 베이스를 먼저 구해야 한다.",
    "relro_full": "GOT 전체가 읽기 전용이라 GOT 덮어쓰기 공격이 막힌다(Full RELRO).",
    "relro_partial": "Partial RELRO 는 .got 만 보호하고 .got.plt 는 여전히 쓰기 가능해, GOT 덮어쓰기를 완전히 막지는 못한다.",
}


def _find_alias(text: str, alias_patterns: list):
    """별칭이 등장한 위치들을 (start, end) 로 돌려준다.

    Args:
        text: 소문자로 바꾼 보호기법 설명 문자열.
        alias_patterns: 해당 보호기법 별칭 정규식 목록.

    Returns:
        매칭 구간 (start, end) 리스트. 없으면 빈 리스트.
    """
    spans = []
    for pat in alias_patterns:
        # 별칭을 단어 경계로 감싸 부분 문자열 오탐을 막는다.
        for m in re.finditer(r"(?<![a-z])" + pat + r"(?![a-z])", text):
            spans.append((m.start(), m.end()))
    return spans


def _is_enabled(text: str, key: str) -> bool:
    """보호기법이 활성인지 판정한다.

    별칭이 문자열에 있고, 그 별칭 근처(뒤쪽 구분자·상태어 또는 바로 앞
    부정 접두)에 "꺼짐" 표현이 없을 때만 True. checksec 처럼 별칭이
    "카테고리 라벨"로 한 번, "상태"로 또 한 번 나오는 경우("NX: NX
    disabled")도, disabled 가 근처에 있으면 꺼짐으로 잡는다.

    Args:
        text: 소문자로 바꾼 보호기법 설명 문자열.
        key: 보호기법 키(nx/canary/pie/relro).

    Returns:
        활성으로 판단되면 True.
    """
    spans = _find_alias(text, _ALIASES[key])
    if not spans:
        return False

    for start, end in spans:
        # 별칭 앞 6자 + 뒤 16자(구분자와 상태어를 담기 충분한 창).
        before = text[max(0, start - 6):start]
        after = text[end:end + 16]
        # 바로 앞이 부정 접두(no/non/not)면 꺼짐.
        if re.search(r"(no|non|not|without)[\s_:=-]*$", before):
            continue
        # 뒤쪽에 disabled/off/no 등이 오면 꺼짐. 단 다른 보호기법의
        # 상태를 삼키지 않도록 구분자(콤마·세미콜론·파이프·줄바꿈) 이전
        # 까지만 본다. 줄바꿈을 넣지 않으면 다음 줄의 "No" 가 이 줄의
        # 상태로 잘못 붙는다.
        after_segment = re.split(r"[,;|\n]", after)[0]
        if _DISABLED.search(after_segment):
            continue
        return True
    return False


def _relro_level(text: str) -> str:
    """RELRO 수준을 판정한다.

    relro 별칭이 등장한 위치 주변 구간(그 구분자 안)에서만 full/partial/
    none 을 찾는다. 문자열 전체에서 full/partial 을 찾으면 "Canary: full,
    RELRO: partial" 같은 입력에서 다른 항목의 full 을 RELRO 로 잘못
    가져온다. 별칭 앞뒤의 부정어(no/off/disabled/none)도 이 구간에서
    확인해 "RELRO none", "RELRO: disabled" 를 none 으로 판정한다.

    Args:
        text: 소문자로 바꾼 보호기법 설명 문자열.

    Returns:
        "full", "partial", "none" 중 하나.
    """
    spans = _find_alias(text, _ALIASES["relro"])
    if not spans:
        return "none"

    start, end = spans[0]
    # relro 별칭이 속한 구간만 잘라낸다(앞뒤 구분자 사이).
    # 앞쪽 구분자 이후부터.
    seg_start = max(
        (text.rfind(sep, 0, start) for sep in [",", ";", "|", "\n"]),
        default=-1,
    )
    seg_start = seg_start + 1 if seg_start >= 0 else 0
    # 뒤쪽 구분자 이전까지.
    seg_end_candidates = [
        text.find(sep, end) for sep in [",", ";", "|", "\n"]
    ]
    seg_end_candidates = [p for p in seg_end_candidates if p >= 0]
    seg_end = min(seg_end_candidates) if seg_end_candidates else len(text)
    segment = text[seg_start:seg_end]

    # 이 구간 안에 부정어가 있으면 none.
    if re.search(r"\b(no|non|not|disabled|disable|off|none)\b", segment):
        return "none"
    if re.search(r"\bfull\b", segment):
        return "full"
    if re.search(r"\bpartial\b", segment):
        return "partial"
    # relro 는 있다고 했으나 수준 표기가 없으면 보수적으로 partial.
    return "partial"


def get_exploit_mitigation_info(protection: str, target_vuln: str) -> dict:
    """보호기법 조합으로 익스플로잇 난이도를 추정한다.

    Args:
        protection: 적용된 보호기법 설명 문자열
            (예: "NX enabled, PIE enabled, No canary, Full RELRO").
            checksec/pwntools 출력 형식도 받는다.
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

    # NX / PIE / Canary 는 켜짐 여부만 본다.
    for key in ("nx", "pie", "canary"):
        if _is_enabled(text, key):
            enabled.append(key)
            score += weights.get(key, 0)
            theory[key] = _THEORY[key]

    # RELRO 는 수준별로 가중치를 다르게 준다. Partial 은 .got.plt 가
    # 여전히 쓰기 가능해 온전한 보호로 보기 어려우므로, config 에서
    # relro_partial 가중치를 0 으로 두었다(Full 만 점수를 준다).
    relro = _relro_level(text)
    if relro == "full":
        enabled.append("relro:full")
        score += weights.get("relro_full", weights.get("relro", 1))
        theory["relro"] = _THEORY["relro_full"]
    elif relro == "partial":
        enabled.append("relro:partial")
        score += weights.get("relro_partial", 0)
        theory["relro"] = _THEORY["relro_partial"]

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
