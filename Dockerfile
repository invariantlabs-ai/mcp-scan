FROM python:3.11-slim

# 작업 디렉토리 설정
WORKDIR /root/Project

# 필요한 파일 복사
COPY . .

# uv 설치 및 의존성 설치
RUN pip install --no-cache-dir uv && \
    uv venv && \
    . .venv/bin/activate && \
    uv pip install -e .

# 기본 명령어 설정
ENV PYTHONPATH=/root/Project
ENTRYPOINT ["uv", "run", "-m", "src.mcp_scan.cli"]
CMD ["scan", "--help"] 