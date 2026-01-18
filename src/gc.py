from google.cloud import bigquery, storage
from google.oauth2 import service_account
from google.api_core.exceptions import NotFound

import os
import pandas as pd
from typing import Dict, List, Optional

import logging
logging.basicConfig(level = logging.INFO)

from src.config import IS_LOCAL, GCLOUD_PROJECTNAME, GCLOUD_BUCKETNAME, GOOGLE_APPLICATION_CREDENTIALS_PATH

year_table_schema = [
    bigquery.SchemaField(name = 'cve_id', field_type = 'STRING', mode='REQUIRED', description='Unique CVE identifier'),
    bigquery.SchemaField("published_date", "TIMESTAMP", description="Date first published"),
    bigquery.SchemaField("updated_date", "TIMESTAMP", description="Latest date updated"),
    bigquery.SchemaField('cisa_kev','BOOLEAN',mode='REQUIRED', description='If appeared in CISA KEV catalog'),
    bigquery.SchemaField('cisa_kev_date', 'DATE', mode='NULLABLE',description='Date appeared in CISA KEV catalog'),

    bigquery.SchemaField('cvss_version', 'FLOAT', description='CVSS version recorded'),
    bigquery.SchemaField('base_score', 'FLOAT', description='Base CVSS score for CVE entry'),

    bigquery.SchemaField('base_severity', 'STRING', description='Severity classiication for CVE entry'),

    bigquery.SchemaField('attack_vector', 'STRING', description='Attack vector for attacks'),

    bigquery.SchemaField('attack_complexity', 'STRING', description='Complexity of attack'),
    bigquery.SchemaField('privileges_required', 'STRING', description='Level of privillege required'),
    bigquery.SchemaField('user_interaction', 'STRING', description='Level of user interaction needed'),
    bigquery.SchemaField('scope', 'STRING'),

    bigquery.SchemaField('confidentiality_impact', 'STRING', description='If confidentiality of system affected'),
    bigquery.SchemaField('integrity_impact', 'STRING', description='If integrity of system affected'),
    bigquery.SchemaField('availability_impact', 'STRING', description='If availability of system affected'),

    bigquery.SchemaField('ssvc_timestamp', 'TIMESTAMP', description='Date SSVC score was added'),
    bigquery.SchemaField('ssvc_exploitation', 'STRING', description='Whether exploitable'),
    bigquery.SchemaField('ssvc_automatable', 'BOOLEAN', description='Whether automatable'),
    bigquery.SchemaField('ssvc_technical_impact', 'STRING', description='SSVC impact level'),
    bigquery.SchemaField('ssvc_decision', 'STRING', description='SSVC decision for metrics'),

    bigquery.SchemaField('impacted_vendor', 'STRING', description='List of vendors impacted'),
    bigquery.SchemaField('impacted_products', 'STRING', mode='REPEATED', description='List of products impacted'),
    bigquery.SchemaField('vulnerable_versions', 'STRING', mode='REPEATED', description='List of product versions impacted'),

    bigquery.SchemaField('cwe_number', 'STRING', description='CWE description number'),
    bigquery.SchemaField('cwe_description', 'STRING', description='Description of CWE')
]

raws_table_schema = [
    bigquery.SchemaField(name = 'cveId', field_type = 'STRING', mode='REQUIRED', description='Unique CVE identifier'),
    bigquery.SchemaField(name = 'year', field_type = 'INT64', mode='NULLABLE', description='Year of CVE entry'),
    bigquery.SchemaField(name= 'filename_string', field_type='STRING', mode='NULLABLE', description='String URI ro retrive raw json from GCS bucket'),
    bigquery.SchemaField(name='extracted_cve_record',field_type='JSON', mode= 'REQUIRED', description='String of raw cve json file')
]

class GoogleClient():

    def __init__(self, isLocal: Optional[bool] = IS_LOCAL):

        self.projectID = GCLOUD_PROJECTNAME
        self.isLocal = isLocal

        # Let us use locally stored json credentials file only when running from local host machine
        if self.isLocal:
            logging.info(f'Initialzing a Google Client from local machine for testing...')
            self.credentials = service_account.Credentials.from_service_account_file(filename=GOOGLE_APPLICATION_CREDENTIALS_PATH)
            self.bigquery_client = bigquery.Client(credentials=self.credentials, project=self.projectID)
            self.storage_client = storage.Client(credentials=self.credentials, project= self.projectID)
        else:
            # When running through a cloud run job, the service account credentials tied to the run job can be used
            #These will be the application defualt credentials ie: ADC
            self.storage_client = storage.Client(project= self.projectID)
            self.bigquery_client = bigquery.Client(project=self.projectID)
        
        self.bucket_name = GCLOUD_BUCKETNAME

        # Retrieving the bucket through it's name 
        self.bucket= self.storage_client.bucket(self.bucket_name) 

    def upload_blob(self, blobname: str ='', local_filepath: Optional[str] = ''):
        try:
            blob = self.bucket.blob(blob_name = blobname)
        
            if local_filepath:
                blob.upload_from_filename(filename=local_filepath)
                logging.info(f'Successfully uploaded file from {local_filepath} to {self.bucket_name}')
        except Exception as e:
            logging.error(f'Failed to upload {blobname} to {self.bucket_name}: {e}')

    def csv_to_bucket(self, year_data, year: str = ''):
        try:

            df = pd.DataFrame(year_data)
            blob_name = f'cve_csvs/cve_data_{year}.csv'

            #Creating a blob with file path for CSVs
            blob = self.bucket.blob(blob_name = blob_name)

            blob.upload_from_string(
                df.to_csv(index = False),
                content_type= 'csv/text'
            )

            logging.info(f'Succesfully upload csv for {year} to GCS bucket {self.bucket_name}')
        
        except Exception as e:
            logging.warning(f'Failed to upload {year} csv to GCS bucket {self.bucket_name}: {e}')
    
    # A method to check if the final table exists, crete if it does not
    def check_final_table_exists(self):
        final_dataset_id = f'{self.projectID}.dataset_final'

        try:
            #Create a bigquery dataset object
            dataset = bigquery.Dataset(final_dataset_id)
            dataset.location = 'US'
            dataset = self.bigquery_client.create_dataset(dataset=dataset, exists_ok=True ,timeout=30)
            logging.info(f'Successfully created or verified existence of dataset_final dataset: {final_dataset_id}')
        except Exception as e:
            logging.info(f'Failed to create dataset_final: {e}')

            
    def create_fill_raws_table(self, source_uri: str= '', year: str = '', isFirstRun : bool = True):
        dataset_id = f'{self.projectID}.sources_bronze'

        # Only check for dataset existence status for the very first run!
        if isFirstRun is True:
            try:
                #Create a bigquery dataset object
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = 'US'
                dataset = self.bigquery_client.create_dataset(dataset=dataset, exists_ok=True ,timeout=30)
                dataset_exists = True
            except Exception as e:
                logging.info(f'Failed to create dataset: {e}')
                dataset_exists= False
        else:
            dataset_exists = True
            
        if dataset_exists:
            table_id = 'cve_raws_table'
            table_ref = f'{dataset_id}.{table_id}'

            if isFirstRun is True:
                try:
                    table = self.bigquery_client.get_table(table_ref)
                    logging.info(f'The table {table_ref} alreeady exists!Truncating it before first entry...')

                    truncate_query = f'''
                    TRUNCATE TABLE {table_ref}'''
                    query_job = self.bigquery_client.query(truncate_query)
                    query_job.result()
                    logging.info(f'Truncated {table_ref} successfully!')
                except NotFound:
                    logging.info(f'Table {table_ref} does not exists! Atttempting to create it now...')
                    new_table = bigquery.Table(table_ref, schema=raws_table_schema)
                    table = self.bigquery_client.create_table(table=new_table, exists_ok=True)
                    logging.info(f'Successfully created table: {table.table_id} in dataset folder {table.dataset_id}')
                
            load_job_config = bigquery.LoadJobConfig(
                schema = raws_table_schema,
                source_format = bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                write_disposition= bigquery.WriteDisposition.WRITE_APPEND
            )

            load_job = self.bigquery_client.load_table_from_uri(
                source_uris= source_uri,
                job_config= load_job_config,
                destination= table_ref,
                location='US'
            )

            load_job.result(timeout=3600)
            logging.info(f'Load job succesful for year {year} on {table_ref}')

        #checking or creating the final dataset where DBT will build the table.
        self.check_final_table_exists()

