import logging
import json 
import argparse
from typing import Dict, List

from google.cloud.storage import transfer_manager

from .gc import GoogleClient
from src.extract import cveExtractor
from .parser import extract_cvedata
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)

def create_combined_staging_table(combined_processed_records: Dict = {}):
    if not combined_processed_records:
        logging.error(f'There are no files to process!')
    else:
        try:
            gc = GoogleClient()
            logging.info(f'Creating combined staging table...')
            # This table will be merged with the final table in BigQuery
            gc.combined_staging_table_bigquery(files=combined_processed_records)
        except Exception as e:
            logging.info(f'Failed to create a combined table: {e}')
        
def extract_cvedata_from_filepath(filepath: str=''):
    try:
        logging.info(f'Extracting cve json from file at {filepath}')

        with open(file=filepath, mode='r') as file:
            cve_json = json.load(file)
        
        #logging.info(f'Extracted cve_json from {filepath}: {cve_json}')

        record = extract_cvedata(cve_data_json= cve_json)
        return record
    except Exception as e:
        logging.error(f'Error opening file {filepath}: {e}')

def transform_tocsv_load_to_gcs_bq(year: str = '1999') -> List[Dict]:
    logging.info(f'Transforming raw json to processed python objects for year: {year}')

    gc = GoogleClient()
    storage_client = gc.storage_client
    bucket_id = gc.bucket_name

    # fetching the bucket we need
    bucket = storage_client.bucket(bucket_name=bucket_id)
    # Returns an iterator object 

    # fetching raw jsons using blob names
    blob_prefix = f'{year}/'
    # List of all blobs for the year
    year_cve_raws_blobs = bucket.list_blobs(prefix=blob_prefix)
    # Creating a list of just the names of blobs and typecasting to string in case it is not 
    jsons_list =[str(blob.name) for blob in year_cve_raws_blobs if blob.name.endswith('.json')]
    #logging.info(f'This is list of all blobs that will be downloaded from {year} blob: {jsons_list}')
    
    try:
        #using transfer manager to download all blobs to a temp folder
        results = transfer_manager.download_many_to_path(
            bucket = bucket,
            destination_directory=f'/tmp/cve_blob_downloaded/',
            blob_names= jsons_list,
            worker_type=transfer_manager.THREAD
        )
    except Exception as e:
        logging.error(f'Failed to download from bucket to temp directory for year {year}: {e}')

    # List that holds set of (blob_name, blob_filepath)
    downloaded_records = []

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logging.error(f'Failed to process record : {e}')
        else:
            downloaded_records.append((jsons_list[i], f'/tmp/cve_blob_downloaded/{jsons_list[i]}'))


    processed_records =[]

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures_records = {
            executor.submit(extract_cvedata_from_filepath, filepath=file_path):
            file_path for (blob_name, file_path) in downloaded_records
        }
    
        for future in as_completed(futures_records):
            try:
                record = future.result()
                if record:
                    processed_records.append(record)
            except Exception as e:
                logging.error(f'Error appending record')


    # Clean up temp files
    import shutil
    shutil.rmtree(f'/tmp/cve_blob_downloaded/', ignore_errors=True)

    return processed_records


def run():
    # Creating a argument parser using the argparse library
    argparser = argparse.ArgumentParser(description= 'Transform raw CVE json text files to structured BigQuery tables')

    # Adding years list argument for custom 
    argparser.add_argument('years', 
                           nargs='?',
                           type=str,
                           default=None, 
                           help='Comma separated years list, can be custom list for test purposes or entire list of years using get_years() function from extractor')

    args = argparser.parse_args()

    if args.years:
        # testing
        years = args.years.split(',')
    else:
        # Automated
        extractor = cveExtractor()
        years = extractor.get_years()

    combined_proccessed_records = []

    for year in years:
        year = year.strip()

        try:
            processed_records= transform_tocsv_load_to_gcs_bq(year)
            #logging.info(f'These are the processed records for {year}: {processed_records}')


            combined_proccessed_records.extend(processed_records)
        except Exception as e:
            logging.error(f'Failed to process for year {year}: {e}')
    
    if combined_proccessed_records:
        #print(f'This is part of the combined processed records that will be used to create the staging table: {combined_proccessed_records[:10]}')
        create_combined_staging_table(combined_processed_records=combined_proccessed_records)
    else:
        logging.warning(f'Error creating combined table!')


if __name__ == '__main__':
    run()

    


            

