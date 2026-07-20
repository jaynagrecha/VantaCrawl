# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV CHROME_BIN=/usr/bin/chromium
ENV PYTHONUNBUFFERED=1

# GUI needs display; default CLI
ENTRYPOINT ["python", "app.py"]
CMD ["--cli", "--help"]
