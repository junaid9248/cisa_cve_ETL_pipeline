# Pinned to your exact chosen version
FROM apache/airflow:2.9.3-python3.11

# Switch to root to perform system installs
USER root
RUN apt-get update && apt-get install -y git && apt-get clean

# Switch back to the airflow user immediately after
USER airflow

WORKDIR /app

# Upgrade pip and install requirements as the 'airflow' user
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy your code
COPY src/ ./src/
COPY dbt/ ./dbt/
COPY main.py .

ENV PYTHONPATH=/app