FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY . /app

EXPOSE 3049 1145

CMD ["python", "app.py", "--only-detect", "--no-llm", "--db-config", "config/db_config.docker.json", "--api-host", "0.0.0.0", "--api-port", "3049", "--dashboard-host", "0.0.0.0", "--dashboard-port", "1145"]
