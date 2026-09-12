FROM mcr.microsoft.com/playwright/python:v1.62.0-jammy
WORKDIR /app/backend

COPY backend/requirements.docker.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt

COPY backend/ /app/backend/
COPY browser-worker/worker.py /app/browser-worker/worker.py

CMD ["python", "/app/browser-worker/worker.py"]
