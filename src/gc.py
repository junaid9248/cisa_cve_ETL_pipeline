from google.cloud import storage, bigquery, exceptions
from google.cloud.storage import transfer_manager
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
class GoogleClient():

    def __init__(self, bucket_name: str = GCLOUD_BUCKETNAME, credentials_path: Optional[str] = GOOGLE_APPLICATION_CREDENTIALS):

        self.projectID = GCLOUD_PROJECTNAME
        self.credentials = service_account.Credentials.from_service_account_file(credentials_path)

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

    def upload_many_blobs(self, upload_list: List = [], max_workers=50):
        """
        Upload many blobs concurrently using Transfer Manager
        
        upload_list: List of dicts with 'filename_string' and 'raw_json' keys
        """
        if not upload_list:
            logging.warning("No files to upload")
            return {'success': 0, 'failed': 0}
        
        try:
            upload_pairs = []
            
            for data in upload_list:
                
                json_data = json.dumps(data['raw_json']).encode('UTF-8')
                f = io.BytesIO(json_data)
                
                f.seek(0)
                
                blob = self.bucket.blob(blob_name=data['filename_string'])
                upload_pairs.append((f, blob))
            
            logging.info(f"Starting batch upload of {len(upload_pairs)} concurrently")
            
        
            results = transfer_manager.upload_many(
                worker_type=transfer_manager.THREAD,
                max_workers=max_workers,
                file_blob_pairs=upload_pairs
            )
            
            # Check results
            success_count = 0
            failed_count = 0
            
            for i, result in enumerate(results):
                blob_name = upload_list[i]['filename_string']
                
                if isinstance(result, Exception):
                    failed_count += 1
                    logging.error(f"Failed to upload {blob_name}: {result}")
                else:
                    success_count += 1
            
            logging.info(f"✅ Upload complete: {success_count} succeeded, {failed_count} failed")
            
            return {
                'success': success_count,
                'failed': failed_count,
                'total': len(upload_list)
            }
            
        except Exception as e:
            logging.error(f"❌ Batch upload failed with exception: {e}")
            return {
                'success': 0,
                'failed': len(upload_list),
                'total': len(upload_list),
                'error': str(e)
            }



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
    

    def combined_staging_table_bigquery(self, files :List= [], year: Optional[str] = 'combined_staging'):

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
            except Exception:
                logging.error(f'Staging table {table_ref} does not exist. Attempting to create it...')
                # Defining the new table object
                new_table = bigquery.Table(table_ref, schema= year_table_schema)
                table = self.bigquery_client.create_table(table= new_table, exists_ok=True)

                updated_table = self.bigquery_client.update_table(table, fields=['schema'])

                logging.info(f'Successfully created table: {updated_table.table_id} in dataset folder {updated_table.dataset_id}')
            
            # Truncating the table before inserting new data for cleaner data
            truncate_sql = f"TRUNCATE TABLE `{table_ref}`"
            self.bigquery_client.query(truncate_sql).result()
            logging.info("Truncated staging table before insert: %s", table_ref)

            # Inserting data into the staging table
            rows_to_insert = files                    
            fill_errors = self.bigquery_client.insert_rows_json(
                table = table_ref,
                json_rows= rows_to_insert
            )

            if fill_errors:
                logging.ERROR(f'Error while filling rows for table {table_ref}')

                # Return obj is a list of errors. Each element has propert
                for error in fill_errors:
                    logging.warning(f'Error inserting: {error}')
            else:
                logging.info(f'Successfully inserted rows for table: {table_ref}')

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

                




       