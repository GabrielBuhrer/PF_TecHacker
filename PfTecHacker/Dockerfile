FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends nikto ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY src/ /app/src/
COPY src/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN mkdir -p /app/reports /app/logs
ENTRYPOINT ["python3", "/app/src/scanner.py"]
CMD ["-h"]