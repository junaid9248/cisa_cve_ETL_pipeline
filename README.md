# __CISA CVE Vulnrichment ELT Data pipeline__

## __Overview__
This project implements a high-performance ELT (Extract, Load, Transform) pipeline designed using Google Cloud Services, Apache Airflow and Data Build Tool (dbt) to process and analyze 120,000+ Common Vulnerabilities and Exposures (CVE) records data enriched by CISA's Authorized Data Publisher (ADP) Vulnrichment program (https://github.com/cisagov/vulnrichment/). 

The pipeline automates the journey from raw, nested JSON vulnerability records to a structured, query-ready Data Warehouse, enabling security researchers to perform complex risk analysis at scale.

## __Project Architecture__

### _Technology Stack_
- __Data Engineering Tools__
    - ***Apache Airflow (v2.9.3)***: Workflow orchestration and scheduling
    - ***Python (v3.11)***:  Core programming language for data processing
    - ***Docker (Compose)***: Containerization and service management
    - ***Data build tool (dbt)***: Framework for transforming data for warehousing using SQL
    - ***PostgreSQL***: Metadata database for Airflow state management
    

- __Google Cloud Platform (GCP)__
    - ***Google Cloud Storage***: Data lake for raw CVE JSON files
    - ***BigQuery***: Data warehouse for bronze/final analytics table
    - ***Compute Engine***: VM hosting the Airflow orchestration containers
    - ***Cloud Run***: Serverless execution of ETL tasks
    - ***Artifact Registry***: Docker container image storage for cloud run containers
    - ***Google Secret Manager***: Securely stored secrets used as env variables during cloud run job
    - ***GCP Service Account***: Identity configured with suitable roles to run GCP services

### _System Components_
The pipeline operates on a GCP Compute Engine VM (e2-medium) with 2 vCPUs, 4GB RAM running Ubuntu 22.04, and consists of three primary layers:
- __Orchestration Layer__: Apache Airflow 2.9.3 with scheduler and webserver for workflow management
- __Data Storage__: PostgreSQL database for Airflow metadata
- __Runtime__: Python 3.11 with Docker Compose for containerization

### _Data Flow_
- __Stage 1: Extract raw cve JSONS, compile into new-line delimited json files and store in GCS data lake__
    - Parallelly extract raw JSONs using ThreadPoolExecutor threads for cve records from CISA Vulnrichment github repository via REST API and append to ndjson file for each year
    - Insert ndsjon files into Google Cloud Storage (GCS) buckets in cloud mode operation or store as csv on local machine in local mode operation

- __Stage 2: Load ndjson file contents to BigQuery data warehouse bronze table__
    - Retrives ndjson files from data lake and loads to bronze table
    - Uses a load job configuration wiht custom schema for bronze table and load_table_from_uri() method

- __Stage 3: Transform bronze table to final table using dbt__
    - Uses Bigquery SQL to transform bronze table into a refined final table available to use in BigQuery

![CISA CVE Vulnrichment ELT Data pipeline architecture](elt_pipline.png)


## __Getting Started__
### STEP 1: Setting up Google Cloud Project
### STEP 2: Setting up virtual machine using Google Compute Engine
### STEP 3: 









