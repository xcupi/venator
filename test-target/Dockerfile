FROM python:3.11-slim
WORKDIR /srv
RUN pip install --no-cache-dir flask==3.0.3
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
