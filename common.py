"""툴 공통 유틸: 표준 에러 응답과 로깅 설정.

세 툴이 제각각 에러 형식을 만들면 클라이언트(LLM) 쪽에서 분기가
복잡해진다. 여기서 에러 객체 모양을 한 곳에 고정해 모든 툴이 같은
구조를 반환하게 한다.
"""

import logging
import os


def make_error(code: str, message: str, hint: str, retryable: bool = False) -> dict:
    """표준 에러 응답을 만든다.

    Args:
        code: 기계가 분기할 수 있는 에러 코드(예: "INVALID_INPUT").
        message: 사람이 읽는 에러 설명.
        hint: 어떻게 고치면 되는지 안내.
        retryable: 같은 입력으로 재시도할 여지가 있는지 여부.

    Returns:
        ok=False 와 error 상세를 담은 딕셔너리.
    """
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
            "hint": hint,
            "retryable": retryable,
        },
    }


def get_logger(name: str) -> logging.Logger:
    """단계별 처리 건수·소요 시간·에러를 남기기 위한 로거.

    print 대신 logging 을 쓰면 레벨 조절과 출력 위치 변경이 쉽다.
    로그 레벨은 환경변수 LOG_LEVEL 로 조절한다(기본 INFO).

    Args:
        name: 로거 이름. 보통 모듈의 __name__ 을 넘긴다.

    Returns:
        설정이 끝난 Logger 인스턴스.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        # 핸들러가 없을 때만 붙여 중복 로그를 막는다.
        handler = logging.StreamHandler()
        fmt = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    # 잘못된 레벨 값이 들어와도 서버가 죽지 않도록 유효한 값만 허용하고,
    # 그 외에는 INFO 로 폴백한다.
    _VALID = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if level not in _VALID:
        level = "INFO"
    logger.setLevel(level)
    return logger
