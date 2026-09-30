"""심볼(함수 목록) 분석 툴.

바이너리에서 추출된 함수 이름 목록을 받아, 악성 행위나 취약점과
관련된 함수를 카테고리별로 분류하고 분석 우선순위를 매긴다.
분류 기준(카테고리, 우선순위 카테고리)은 config.yaml 에서 읽는다.
"""

from config_loader import load_config
from common import make_error, get_logger

logger = get_logger(__name__)


def analyze_symbol_table(symbols, platform: str = "linux_x64") -> dict:
    """함수 목록을 기능 카테고리별로 분류한다.

    Args:
        symbols: 함수 이름 문자열 리스트. socket, strcpy 처럼 순수한
            심볼 이름을 기대한다.
        platform: 실행 플랫폼(현재는 결과에 기록만 하고 분류에는
            사용하지 않는다).

    Returns:
        성공 시 카테고리별 함수 목록(categories), 걸린 전체 위험
        함수(critical_functions), 우선순위(analysis_priority)를 담은
        딕셔너리. 입력이 잘못되면 표준 에러 객체.
    """
    # EDGE CASE: 입력 누락 — 다른 툴과 같은 에러 형식으로 돌려준다
    # (기존에는 여기서 TypeError 로 죽었다).
    if symbols is None or not isinstance(symbols, list):
        return make_error(
            code="INVALID_INPUT",
            message="symbols must be a non-null list of function names",
            hint="Provide a list like ['strcpy', 'system']",
        )

    config = load_config()
    category_map = config["symbol_categories"]
    high_priority = set(config["high_priority_categories"])

    # 심볼을 set 으로 바꿔 조회를 O(1) 로 만든다. 문자열이 아닌 원소
    # (중첩 리스트 등)가 섞이면 set() 이 TypeError 를 내므로, 해시
    # 가능한 문자열만 남긴다.
    symbol_set = {s for s in symbols if isinstance(s, str)}

    categories = {}
    critical_functions = []
    for category, funcs in category_map.items():
        hits = [f for f in funcs if f in symbol_set]
        if hits:
            # 기존 버그: category 를 단일 변수에 덮어써 마지막 매칭만
            # 남았다. 카테고리별로 나눠 담아 여러 카테고리를 보존한다.
            categories[category] = hits
            critical_functions.extend(hits)

    # 우선순위 카테고리에 걸린 게 있으면 High.
    priority = "High" if high_priority & set(categories) else "Low"

    logger.info(
        "analyze_symbol: %d symbols in, %d critical across %d categories",
        len(symbols),
        len(critical_functions),
        len(categories),
    )

    return {
        "ok": True,
        "platform": platform,
        "categories": categories,
        "critical_functions": critical_functions,
        "analysis_priority": priority,
    }
