"""설정 파일(config.yaml) 로더.

사람이 조정하는 값(위험 함수 목록, 카테고리, 난이도 가중치)을 코드에서
분리하기 위한 단일 진입점이다. 모든 툴이 이 모듈을 통해 같은 설정을 읽어,
비교나 재실행 시 룰이 어긋나지 않도록 한다.
"""

import os

import yaml

# config.yaml 은 이 파일과 같은 디렉터리에 있다고 가정한다. 이름 붙인
# 경로 상수 — 실행 위치(cwd)가 달라도 항상 같은 파일을 읽게 하기 위함.
_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")

# 파싱 결과 캐시. 설정은 실행 중 바뀌지 않으므로 한 번만 읽는다.
_cache = None


def load_config(path: str = _CONFIG_PATH) -> dict:
    """config.yaml 을 읽어 dict 로 돌려준다.

    Args:
        path: 설정 파일 경로. 기본값은 모듈과 같은 폴더의 config.yaml.
            테스트에서 다른 설정을 주입하고 싶을 때만 바꾼다.

    Returns:
        파싱된 설정 딕셔너리.

    Raises:
        FileNotFoundError: 설정 파일이 없을 때.
        yaml.YAMLError: 설정 파일 형식이 잘못됐을 때.
    """
    global _cache
    if _cache is not None and path == _CONFIG_PATH:
        return _cache

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    if path == _CONFIG_PATH:
        _cache = config
    return config
