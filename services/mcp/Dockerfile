FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml .
RUN pip install --no-cache-dir "mcp[cli]>=1.0" "httpx>=0.27"
COPY server.py .

CMD ["python", "server.py"]
