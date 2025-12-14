from google.cloud import storage, bigquery, exceptions as gc_exceptions

from google.oauth2 import service_account

import json
import logging
import pandas as pd
from typing import Dict, List, Optional, Any
from src.config import GCLOUD_API_KEY, GCLOUD_BUCKETNAME, GCLOUD_APP_CREDENTIALS, GCLOUD_PROJECTNAME

logging.basicConfig(level = logging.INFO)

class googleClient():

    def __init__(self, bucket_name: str = GCLOUD_BUCKETNAME):

        self.projectID = GCLOUD_PROJECTNAME
        self.credentials = service_account.Credentials.from_service_account_file(GCLOUD_APP_CREDENTIALS)

        #Defining the google storage client and bigquery client with credentials and project id 
        self.storage_client = storage.Client(credentials=self.credentials, project= self.projectID)
        self.bigquery_client = bigquery.Client(credentials=self.credentials, project=self.projectID)
        
        self.bucket_name = bucket_name

        # Retrieving the bucket through it's name 
        self.bucket= self.storage_client.bucket(self.bucket_name) 

    def upload_blob(self, raw_json, filename):
        try:
            blob = self.bucket.blob(blob_name = filename)

            blob.upload_from_string(json.dumps(raw_json))
            logging.info(f'Uploaded {filename} to {self.bucket_name}')
        except Exception as e:
            logging.error(f'Failed to upload {filename} to {self.bucket_name}: {e}')

    def csv_to_bucket(self, year_data, year: str = ''):

        try:

            df = pd.DataFrame(year_data)
            blob_name = f'cve_csv/cve_data_{year}.csv'

            #Creating a blob with file path for CSVs
            blob = self.bucket.blob(blob_name = blob_name)

            blob.upload_from_string(
                df.to_csv(index = False),
                content_type= 'csv/text'
            )

            logging.info(f'Succesfully upload csv for {year} to GCS bucket {self.bucket_name}')
        
        except Exception as e:
            logging.warning(f'Failed to upload {year} csv to GCS bucket {self.bucket_name}: {e}')


    def checkdatasetexists(self, dataset_id):
        #Checcking if a dataset exists and creating if not
            try: 
                self.bigquery_client.get_dataset(dataset_id)
                return True
            except gc_exceptions.NotFound:
                logging.warning('Dataset not found, creating a new dataset')
                return False
            
    def checktableexists(self, table_id):
        try: 
            self.bigquery_client.get_table(table_id)
            return True
        except gc_exceptions.NotFound:
            logging.info(f'Table was not found. Creating new table: {table_id}')
            return False

            
    def csv_bigquery(self, isLocal, files :List= [], year:str = '1999'):

        # Check if it is automated mode 
        if not isLocal:
            
            dataset_id = 'cisa-cve-data-pipeline.cve_all_new'
            dataset_exists = False

            try:               
                #Create a bigquery dataset object
                dataset = bigquery.Dataset(dataset_id)
                dataset.location = 'US'

                dataset = self.bigquery_client.create_dataset(dataset=dataset, exists_ok=True ,timeout=30)
                logging.info(f'Successfully created: {dataset.dataset_id} in {self.bigquery_client.project}')
                dataset_exists = True
            except Exception as e:
                logging.warning(f'Error creating dataset: {e}')
                dataset_exists = False
        

            
            # If dataset exists proceeding with table creation or update
            if dataset_exists:
                #Check for the desired year table to see if it is in this dataset
                table_id = f'cve_{year}_table'
                table_ref = f'{dataset_id}.{table_id}'

                year_table_schema = [
                            bigquery.SchemaField('cve_id', 'STRING', mode='REQUIRED', description='Unique CVE identifier'),
                            bigquery.SchemaField("published_date", "STRING", description="Date first published"),
                            bigquery.SchemaField("updated_date", "STRING", description="Latest date updated"),
                            bigquery.SchemaField('cisa_kev','STRING', description='If appeared in CISA KEV catalog'),
                            bigquery.SchemaField('cisa_kev_date', 'STRING', description='Date appeared in CISA KEV catalog'),

                            bigquery.SchemaField('cvss_version', 'STRING', description='CVSS version recorded'),

                            bigquery.SchemaField('base_score', 'STRING', description='Base CVSS score for CVE entry'),

                            bigquery.SchemaField('base_severity', 'STRING', description='Severity classiication for CVE entry'),

                            bigquery.SchemaField('attack_vector', 'STRING', description='Attack vector for attacks'),

                            bigquery.SchemaField('attack_complexity', 'STRING', description='Complexity of attack'),
                            bigquery.SchemaField('privileges_required', 'STRING', description='Level of privillege required'),
                            bigquery.SchemaField('user_interaction', 'STRING', description='Level of user interaction needed'),
                            bigquery.SchemaField('scope', 'STRING'),

                            bigquery.SchemaField('confidentiality_impact', 'STRING', description='If confidentiality of system affected'),
                            bigquery.SchemaField('integrity_impact', 'STRING', description='If integrity of system affected'),
                            bigquery.SchemaField('availability_impact', 'STRING', description='If availability of system affected'),

                            bigquery.SchemaField('ssvc_timestamp', 'STRING', description='Date SSVC score was added'),
                            bigquery.SchemaField('ssvc_exploitation', 'STRING', description='Whether exploitable'),
                            bigquery.SchemaField('ssvc_automatable', 'STRING', description='Whether automatable'),
                            bigquery.SchemaField('ssvc_technical_impact', 'STRING', description='SSVC impact level'),
                            bigquery.SchemaField('ssvc_decision', 'STRING', description='SSVC decision for metrics'),

                            bigquery.SchemaField('impacted_vendor', 'STRING', description='List of vendors impacted'),
                            bigquery.SchemaField('impacted_products', 'STRING', mode='REPEATED', description='List of products impacted'),
                            bigquery.SchemaField('vulnerable_versions', 'STRING', mode='REPEATED', description='List of product versions impacted'),

                            bigquery.SchemaField('cwe_number', 'STRING', description='CWE description number'),
                            bigquery.SchemaField('cwe_description', 'STRING', description='Description of CWE')]
                
                # Defining the new table object
                new_table = bigquery.Table(table_ref, schema= year_table_schema)

                try: 
                    #Inserting new table into the dataset
                    table = self.bigquery_client.create_table(table= new_table, exists_ok=True)

                    updated_table = self.bigquery_client.update_table(table, fields=['schema'])

                    logging.info(f'Successfully created table: {updated_table.table_id} in dataset folder {updated_table.dataset_id}')

                    rows_to_insert = files                    
                    fill_errors = self.bigquery_client.insert_rows_json(
                        table = new_table,
                        json_rows= rows_to_insert
                    )

                    if fill_errors:
                        logging.ERROR(f'Error while filling rows for table {table_ref}')

                        # Return obj is a list of errors. Each element has propert
                        for error in fill_errors:
                            logging.warning(f'Error inserting at {error['index']}: error:{error['errors']}')
                    else:
                        logging.info(f'Successfully inserted rows for table: {table_ref}')

                except Exception as e:
                    logging.warning(f'failed to create table: {e}')

                    