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
    # relro 별칭이 속한 구간을 잡는다. 먼저 구분자(,;|줄바꿈) 사이로
    # 자르고, 그 위에 별칭 바로 앞뒤 좁은 창을 한 번 더 씌운다. 구분자가
    # 전혀 없는 입력("NX disabled PIE enabled Full RELRO")에서는 구간이
    # 문자열 전체가 되어, 다른 항목의 부정어(NX 의 disabled)나 값(다른
    # full)을 RELRO 것으로 잘못 가져오기 때문이다.
    sep_start = max(
        (text.rfind(sep, 0, start) for sep in [",", ";", "|", "\n"]),
        default=-1,
    )
    sep_start = sep_start + 1 if sep_start >= 0 else 0
    sep_end_candidates = [
        text.find(sep, end) for sep in [",", ";", "|", "\n"]
    ]
    sep_end_candidates = [p for p in sep_end_candidates if p >= 0]
    sep_end = min(sep_end_candidates) if sep_end_candidates else len(text)

    # 별칭 앞 8자 / 뒤 16자 창과 구분자 구간의 교집합을 쓴다.
    win_start = max(sep_start, start - 8)
    win_end = min(sep_end, end + 16)
    segment = text[win_start:win_end]

    # 이 구간 안에 부정어가 있으면 none.
    if re.search(r"\b(no|non|not|disabled|disable|off|none)\b", segment):
        return "none"
    if re.search(r"\bfull\b", segment):
        return "full"
    if re.search(r"\bpartial\b", segment):
        return "partial"
    # relro 는 있다고 했으나 수준 표기가 없으면 보수적으로 partial.
    return "partial"


def score_protections(nx: bool, pie: bool, canary: bool, relro: str) -> dict:
    """구조화된 보호기법 값으로 익스플로잇 난이도를 계산한다(순수 함수).

    문자열 파싱을 거치지 않고 불리언/열거값을 직접 받는다. elf_tool 처럼
    이미 정확한 값을 아는 호출자는 이 함수를 바로 쓰고, 사람이나 LLM 이
    문자열을 넣는 경우에만 get_exploit_mitigation_info 의 텍스트 파서를
    거친다. 핵심 경로에서 파서 버그가 끼어들 수 없게 하기 위한 분리다.

    Args:
        nx: NX(스택 실행 방지) 활성 여부.
        pie: PIE(위치 독립 실행) 활성 여부.
        canary: 스택 카나리 활성 여부.
        relro: "full" / "partial" / "none" (대소문자 무시).

    Returns:
        enabled_protections, score, difficulty, theory 를 담은 딕셔너리.
    """
    config = load_config()
    weights = config["mitigation_weights"]
    thresholds = config["difficulty_thresholds"]

    enabled = []
    score = 0
    theory = {}

    if nx:
        enabled.append("nx")
        score += weights.get("nx", 0)
        theory["nx"] = _THEORY["nx"]
    if pie:
        enabled.append("pie")
        score += weights.get("pie", 0)
        theory["pie"] = _THEORY["pie"]
    if canary:
        enabled.append("canary")
        score += weights.get("canary", 0)
        theory["canary"] = _THEORY["canary"]

    relro_norm = (relro or "none").lower()
    if relro_norm == "full":
        enabled.append("relro:full")
        score += weights.get("relro_full", weights.get("relro", 1))
        theory["relro"] = _THEORY["relro_full"]
    elif relro_norm == "partial":
        enabled.append("relro:partial")
        score += weights.get("relro_partial", 0)
        theory["relro"] = _THEORY["relro_partial"]

    if score >= thresholds["high_min"]:
        difficulty = "High"
    elif score >= thresholds["medium_min"]:
        difficulty = "Medium"
    else:
        difficulty = "Low"

    return {
        "enabled_protections": enabled,
        "score": score,
        "difficulty": difficulty,
        "theory": theory,
    }


def build_mitigation_result(
    scored: dict, protection: str, target_vuln: str
) -> dict:
    """score_protections 결과를 툴 응답 형태로 감싼다.

    elf_tool 과 get_exploit_mitigation_info 가 같은 응답 dict 를 각자
    조립하면 한쪽만 바뀔 때 어긋난다. 조립을 이 헬퍼 한 곳으로 모아
    두 경로의 출력이 항상 같게 한다.

    Args:
        scored: score_protections 가 돌려준 딕셔너리.
        protection: 응답에 기록할 보호기법 설명 문자열.
        target_vuln: 대상 취약점 유형.

    Returns:
        ok/protection/난이도/이론/analysis 를 담은 응답 딕셔너리.
    """
    enabled = scored["enabled_protections"]
    return {
        "ok": True,
        "protection": protection,
        "target_vulnerability": target_vuln,
        "enabled_protections": enabled,
        "score": scored["score"],
        "difficulty": scored["difficulty"],
        "theory": scored["theory"],
        "analysis": (
            f"Exploit difficulty estimated as {scored['difficulty']} "
            f"(score {scored['score']}) based on enabled protections: "
            f"{', '.join(enabled) if enabled else 'none'}."
        ),
    }


def get_exploit_mitigation_info(protection: str, target_vuln: str) -> dict:
    """보호기법 조합으로 익스플로잇 난이도를 추정한다.

    이 함수는 사람/LLM 이 넣은 자유 형식 문자열을 해석하는 진입점이다.
    문자열에서 각 보호기법의 활성 여부를 파싱한 뒤, 실제 점수 계산은
    구조화된 값을 받는 score_protections 에 위임한다. 정확한 값을 이미
    아는 호출자(elf_tool)는 이 파서를 거치지 말고 score_protections 를
    직접 써야 한다.

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

    text = protection.lower()

    # 문자열 → 구조화된 값(불리언/열거)으로 파싱.
    nx = _is_enabled(text, "nx")
    pie = _is_enabled(text, "pie")
    canary = _is_enabled(text, "canary")
    relro = _relro_level(text)

    # 실제 점수 계산은 순수 함수에 위임.
    scored = score_protections(nx, pie, canary, relro)

    logger.info(
        "mitigation: score=%d enabled=%s -> %s",
        scored["score"],
        scored["enabled_protections"],
        scored["difficulty"],
    )

    return build_mitigation_result(scored, protection, target_vuln)
