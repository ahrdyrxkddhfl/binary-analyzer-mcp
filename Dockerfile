# Smithery 배포 및 로컬 재현용 이미지.
FROM python:3.12-slim

WORKDIR /app

# 의존성 먼저 설치해 레이어 캐시를 활용한다.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# stdio MCP 서버 실행.
CMD ["python", "-u", "mcp_server.py"]
