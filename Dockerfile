# Pinned to your exact chosen version
FROM apache/airflow:2.9.3-python3.11

# Switch to root to perform system installs
USER root
RUN apt-get update && apt-get install -y git && apt-get clean

COPY . /opt/airflow/repo

# Change ownership to airflow user from root for future access
RUN chown -R airflow:root /opt/airflow/repo

# Switch back to the airflow user after
USER airflow
WORKDIR /opt/airflow/repo

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


