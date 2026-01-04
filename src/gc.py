from google.cloud import bigquery, exceptions
from google.cloud.storage import transfer_manager, Client
from google.oauth2 import service_account

import os
import io
import json
import logging
import pandas as pd
from typing import Dict, List, Optional, Any


from src.config import GCLOUD_PROJECTNAME

logging.basicConfig(level = logging.INFO)

GCLOUD_PROJECTNAME = os.environ.get('GCLOUD_PROJECTNAME')
GOOGLE_APPLICATION_CREDENTIALS = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
GCLOUD_BUCKETNAME = os.environ.get('GCLOUD_BUCKETNAME')

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
                    bigquery.SchemaField('cwe_description', 'STRING', description='Description of CWE')]

raws_table_schema = [
    bigquery.SchemaField(name = 'cveId', field_type = 'STRING', mode='REQUIRED', description='Unique CVE identifier'),
    bigquery.SchemaField(name = 'year', field_type = 'INT64', mode='REQUIRED', description='Year of CVE entry'),
    bigquery.SchemaField(name= 'filename_string', field_type='STRING', mode='REQUIRED', description='String URI ro retrive raw json from GCS bucket'),
    bigquery.SchemaField(name='raw_json',field_type='STRING', mode= 'REQUIRED', description='String of raw cve json file')
]

class GoogleClient():

    def __init__(self, bucket_name: str = GCLOUD_BUCKETNAME, credentials_path: Optional[str] = GOOGLE_APPLICATION_CREDENTIALS):

        self.projectID = GCLOUD_PROJECTNAME
        self.credentials = service_account.Credentials.from_service_account_file(credentials_path)

        #Defining the google storage client and bigquery client with credentials and project id 
        self.storage_client = Client(credentials=self.credentials, project= self.projectID)
        self.bigquery_client = bigquery.Client(credentials=self.credentials, project=self.projectID)
        
        self.bucket_name = bucket_name

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
    

    def create_fill_raws_table(self, source_uri: str= '', isTruncated: bool = True, year: str = ''):
        dataset_id = f'{self.projectID}.cve_all'
        dataset_exists = False

        try:               
            #Create a bigquery dataset object
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = 'US'

            dataset = self.bigquery_client.create_dataset(dataset=dataset, exists_ok=True ,timeout=30)
            if dataset:
                logging.info(f'Successfully created: {dataset.dataset_id} in {self.bigquery_client.project}')
                dataset_exists = True
        except Exception as e:
            logging.warning(f'Error creating dataset: {e}')

        if dataset_exists:
            table_id = 'cve_raws_table'
            table_ref = f'{dataset_id}.{table_id}'

        
            table = self.bigquery_client.get_table(table_ref)
            try:
                if table:
                    
                    if isTruncated is False:
                        logging.info(f'Table already exists. Truncating it before first entry...')

                        truncate_query = f'''
                        TRUNCATE TABLE {table_ref}'''
                        query_job = self.bigquery_client.query(truncate_query)
                        query_job.result()
                        logging.info(f'Truncated {table_ref} successfully!')
                else:
                    logging.info(f'Table {table_ref} does not exists! Atttempting to create it now...')
                    new_table = bigquery.Table(table_ref, schema=raws_table_schema)
                    self.bigquery_client.create_table(table=new_table, exists_ok=True)
                    updated_table = self.bigquery_client.update_table(table, fields=['schema'])
            
                    logging.info(f'Successfully created table: {updated_table.table_id} in dataset folder {updated_table.dataset_id}')
            except Exception as e:
                logging.info(f'Failed to resolved table {table_ref}: {e}')

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

        load_job.result()
        logging.info(f'Load job succesful for year {year} on {table_ref}')



    def combined_staging_table_bigquery(self, gcs_uri: str = '', year: Optional[str] = 'combined_staging', did_truncate: bool = False):

        dataset_id = f'{self.projectID}.cve_all'
        dataset_exists = False

        try:               
            #Create a bigquery dataset object
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = 'US'

            dataset = self.bigquery_client.create_dataset(dataset=dataset, exists_ok=True ,timeout=30)
            if dataset:
                logging.info(f'Successfully created: {dataset.dataset_id} in {self.bigquery_client.project}')
            dataset_exists = True
        except Exception as e:
            logging.warning(f'Error creating dataset: {e}')
            dataset_exists = False
    
        # If dataset exists proceeding with table creation or update
        if dataset_exists:
            table_id = f'cve_combined_staging_table'
            table_ref = f'{dataset_id}.{table_id}'
            try:
                table = self.bigquery_client.get_table(table_ref)
                if table:
                    logging.info(f'The table {table.table_id} already exists in {table.dataset_id}!')

                    if did_truncate == False:
                        logging.info("Truncated staging table before first insertion: %s", table_ref)
                        # Truncating the table before inserting new data for cleaner data
                        truncate_sql = f"TRUNCATE TABLE `{table_ref}`"
                        self.bigquery_client.query(truncate_sql).result()
                    
            except Exception:
                logging.error(f'Staging table {table_ref} does not exist. Attempting to create it...')
                # Defining the new table object
                new_table = bigquery.Table(table_ref, schema= year_table_schema)
                table = self.bigquery_client.create_table(table= new_table, exists_ok=True)

                updated_table = self.bigquery_client.update_table(table, fields=['schema'])

                logging.info(f'Successfully created table: {updated_table.table_id} in dataset folder {updated_table.dataset_id}')
            
            # Inserting data into the staging table
            upload_from_uri = gcs_uri

            # Configuring the load job with the source format as the newline delimited json
            job_config =bigquery.LoadJobConfig(
                source_format = bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
                schema = year_table_schema,
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND
            )

            # Starting the load job which loads all files from created bytes file into the table
            # load_table_from_file() returns a LoadJob class
            load_job = self.bigquery_client.load_table_from_uri(
                source_uris = upload_from_uri,
                destination=table_ref,
                job_config= job_config
            ) 

            load_job.result()
            logging.info(f'Load job finished. Successfully loaded to {table_ref}table.')


    def combined_final_table_bigquery(self, query: str = '', year: Optional[str] = 'combined_final'):

        final_table_id = f"cisa-cve-data-pipeline.cve_all.cve_combined_final_table"
       
        try:
            # Try to get final table if it exists
            self.bigquery_client.get_table(final_table_id)
        except Exception:
            logging.error(f'Final table {final_table_id} does not exist. Attempting to create it...')
            new_table = bigquery.Table(final_table_id, schema= year_table_schema)
            self.bigquery_client.create_table(table= new_table, exists_ok=True)

        # Run merge query to update final table
        try: 
            query_job = self.bigquery_client.query(query)
            results = query_job.result()
            logging.info(f'Successfully updated final table: {final_table_id}: {results}')
        except Exception as e:
            logging.warning(f'Failed to update final table: {e}')

                




       