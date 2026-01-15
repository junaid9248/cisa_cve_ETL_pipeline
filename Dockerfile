# This is the dockerfile for the cloud run job image
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy directories and requirements files from the vm machine first
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY cloudentrypoint.sh .
RUN chmod +x cloudentrypoint.sh

COPY main.py .
COPY src/ ./src/
COPY dbt/ ./dbt/

ENTRYPOINT [ "./cloudentrypoint.sh" ]