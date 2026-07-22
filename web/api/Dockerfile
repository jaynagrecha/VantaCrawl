FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl unzip ca-certificates \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Repo root context expected (docker-compose build context = repo root)
COPY requirements.txt /app/requirements.txt
COPY web/api/requirements.txt /app/web-api-requirements.txt
COPY web/requirements-render.txt /app/web-requirements-render.txt
RUN pip install --no-cache-dir -r /app/requirements.txt -r /app/web-api-requirements.txt \
    && pip install --no-cache-dir -r /app/web-requirements-render.txt

COPY . /app
WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/web/api
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver
ENV APP_ENV=production

EXPOSE 8000
CMD ["uvicorn", "vantacrawl_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "web/api"]
