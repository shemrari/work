FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
RUN chown -R 10001:10001 /app
USER 10001:10001

EXPOSE 8090
CMD ["python", "server.py"]
