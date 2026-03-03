FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY honeysentinel ./honeysentinel
COPY config.example.yaml /app/config.yaml
RUN mkdir -p /app/data
EXPOSE 8000 12222 12323 12525 16379 19000 18080 33890
CMD ["python", "-m", "honeysentinel", "/app/config.yaml"]
