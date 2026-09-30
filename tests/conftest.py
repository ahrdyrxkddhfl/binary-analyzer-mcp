"""pytest 공통 설정.

프로젝트 루트를 import 경로에 추가해, tests 폴더에서 실행하든
루트에서 실행하든 tools/config_loader 를 임포트할 수 있게 한다.
"""

import os
import sys

# 루트 = 이 파일의 상위 디렉터리.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
