# __CISA CVE Vulnrichment ETL Data pipeline__

## __Overview__
This project implements a high-performance ELT (Extract, Load, Transform) pipeline designed to process and analyze 120,000+ Common Vulnerabilities and Exposures (CVE) records data enriched by CISA's Authorized Data Publisher (ADP) Vulnrichment program (https://github.com/cisagov/vulnrichment/). 

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

![CISA CVE Vulnrichment ETL Data pipeline architecture](etl_pipeline.png) 


## __Getting Started__
### Prerequisites
Install and configure neccesary services:
1. Python 3.11 environment
2. Google Cloud Platform account with enabled services (GCS, BigQuery, Compute Engine)
3. GCP service account credentials with appropriate IAM permissions
4. Docker and Docker Compose
5. Pip package manager

### Installation Steps
1. Clone repository from master branch
```sh
    git clone https://github.com/junaid9248/cisa_cve_ETL_pipeline dev
```
2. Configure GCP project (cloud storage, compute engine, bigquery, service account)
You can use the provided tutorials and others to set up your GCP project with required services:
- [Google Cloud Full Course for Beginners](https://www.youtube.com/watch?v=lvZk_sc8u5I)
- [Set Up Google Cloud Project & Service Account](https://www.youtube.com/watch?v=_FmsEkF72M0&t=71s)

3. Install python dependencies using pip manager
```sh
    cd cisa_cve_elt_pipeline
    pip install -r requirements.txt
```

4. Create a .env file in root directory
```sh
    touch .env
```

6. Fill the .env with your secrets
- Create a source.txt file with the following environment variables and set your values:
```python
#source.txt
IS_LOCAL  =  #boolean for cloud or local mode operation
GCLOUD_PROJECTNAME = #String value of project name on GCP
GH_TOKEN = # String value of GitHub developer token for increased bandwidth
GCLOUD_BUCKETNAME = # String value of bucket name in Cloud Storage
GOOGLE_APPLICATION_CREDENTIALS = # String value for path to GCP service account credentials 
MY_EMAIL = # String value for apache webserver email
AIRFLOW__WEBSERVER__SECRET_KEY = # String value for common apache airflow webserver and scheduler secret key
```
- Fill existing .env file from source.txt
```sh
    cat source.txt > .env
```








