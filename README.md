# __CISA CVE Vulnrichment ETL Data pipeline__

## __Overview__
This project implements a production-grade ETL (Extract, Transform, Load) pipeline using Apache Airflow to process Common Vulnerabilities and Exposures (CVE) data enriched by CISA's Authorized Data Publisher (ADP) Vulnrichment program (https://github.com/cisagov/vulnrichment/). 

The pipeline handles 120,000+ raw JSON vulnerability records, transforms them into structured formats, and stores them in a data lake for storage and data warehouse architecture.

## __Project Architecture__

### _Technology Stack_
- __Data Engineering Tools__
    - ***Apache Airflow (v2.9.3)***: Workflow orchestration and scheduling
    - ***PostgreSQL***: Metadata database for Airflow state management
    - ***Docker (Compose)***: Containerization and service management
    - ***Python (v3.11)***:  Core programming language for data processing

- __Google Cloud Platform (GCP)__
    - ***Google Cloud Storage***: Data lake for raw CVE JSON files
    - ***BigQuery***: Data warehouse for structured vulnerability records
    - ***Compute Engine***: VM hosting the Airflow orchestration platform

### _System Components_
The pipeline operates on a GCP Compute Engine VM (e2-medium) with 2 vCPUs, 4GB RAM running Ubuntu 22.04, and consists of three primary layers:
- __Orchestration Layer__: Apache Airflow 2.9.3 with scheduler and webserver for workflow management
- __Data Storage__: PostgreSQL database for Airflow metadata
- __Runtime__: Python 3.11 with Docker Compose for containerization

### _Data Flow_
- __Stage 1: Extract raw cve JSONS into GCS data lake__
    - Extracts raw jsons for cve records from CISA Vulnrichment github repository via REST API
    - Parallelly extract raw JSONs using ThreadPoolExecutor threads in a two-stage process
    - Insert raw JSONs into Google Cloud Storage (GCS) buckets  

- __Stage 2: Transform raw data and load to BigQuery data warehouse__
    - Retrives raw JSONs from data lake and transforms into into flattened, structured records
    - Employs Transfer Manager with 10-15 workers to create preliminary staging table
    - Merges staging table with final table and loads into BigQuery data warehouse
    - Enables SQL-based analytics and reporting on vulnerability metrics

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
    git clone https://github.com/junaid9248/cisa_cve_elt_pipeline master
```

2. Install python dependencies using pip manager
```sh
    cd cisa_cve_elt_pipeline
    pip install -r requirements.txt
```

3. Create a .env file in root directory
```sh
    touch .env
```

5. Fill the .env with your secrets
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








