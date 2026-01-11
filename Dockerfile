FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY dbt/ ./dbt/
COPY main.py .

ENV PYTHONPATH=/app

ENTRYPOINT ["python", "main.py"]




