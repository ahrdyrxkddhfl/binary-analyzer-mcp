"""로컬 Ollama LLM 호출 클라이언트(선택 기능).

보호기법 설명 등에 자연어 보강이 필요할 때 로컬 Ollama 서버를 호출한다.
기본 분석 툴은 이 모듈 없이도 동작하며, 로컬에 Ollama 가 떠 있을 때만
쓰는 부가 기능이다. 서버 배포 환경에는 Ollama 가 없을 수 있으므로
핵심 경로에서 임포트하지 않는다.
"""

import requests

# Ollama 로컬 API 엔드포인트. 고정된 로컬 주소이므로 상수로 둔다.
_OLLAMA_URL = "http://localhost:11434/api/generate"

# 응답 대기 최대 시간(초). LLM 생성이 길어질 수 있어 넉넉히 둔다.
_TIMEOUT = 60


def ask_llm(prompt: str, model: str = "llama3") -> str:
    """로컬 Ollama LLM 에 프롬프트를 보내고 응답 텍스트를 받는다.

    Args:
        prompt: LLM 에 보낼 질문 문자열.
        model: 사용할 Ollama 모델 이름.

    Returns:
        LLM 응답 문자열. 호출 실패 시 "LLM 호출 실패: ..." 메시지.
    """
    payload = {"model": model, "prompt": prompt, "stream": False}
    try:
        res = requests.post(_OLLAMA_URL, json=payload, timeout=_TIMEOUT)
        res.raise_for_status()
        data = res.json()
        return data.get("response", "").strip()
    except Exception as e:
        return f"LLM 호출 실패: {str(e)}"
