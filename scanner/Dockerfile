FROM python:3.11-slim
WORKDIR /app/backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.docker.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY backend/ /app/backend/
COPY scanner/worker.py /app/scanner/worker.py

CMD ["python", "/app/scanner/worker.py"]
