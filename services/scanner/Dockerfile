FROM instrumentisto/nmap:latest

RUN apk add --no-cache python3 py3-pip
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn pydantic
COPY scanner.py .

CMD ["python3", "-m", "uvicorn", "scanner:app", "--host", "0.0.0.0", "--port", "8002"]
