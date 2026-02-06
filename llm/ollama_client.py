import requests


def ask_llm(prompt: str, model: str = "llama3") -> str:
    """
    Ollama 로컬 LLM 호출
    INPUT: prompt (질문 문자열)
    OUTPUT: LLM 응답 문자열
    """

    url = "http://localhost:11434/api/generate"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }

    try:
        res = requests.post(url, json=payload, timeout=60)
        res.raise_for_status()
        data = res.json()
        return data.get("response", "").strip()

    except Exception as e:
        return f"LLM 호출 실패: {str(e)}"
