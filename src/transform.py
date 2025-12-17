import logging
import json 
import argparse
import pandas as pd
from typing import Dict, List, Optional

from .gc import GoogleClient
from src.extract import cveExtractor
from .parser import extract_cvedata

logging.basicConfig(level=logging.INFO)

def create_combined_table(combined_processed_records: Dict = {}):
    if not combined_processed_records:
        logging.error(f'There are no files to process!')
    else:
        try:
            gc = GoogleClient()
            logging.info(f'Creating combined table...')
            gc.csv_bigquery(files=combined_processed_records)
        except Exception as e:
            logging.info(f'Failed to create a combined table: {e}')
        

def transform_tocsv_load_to_gcs_bq(year: str = '1999') -> List[Dict]:
    logging.info(f'Transforming raw json to csv for year: {year}')

    gc = GoogleClient()
    storage_client = gc.storage_client

    bucket_id = gc.bucket_name
    # fetching the bucket we need
    bucket = storage_client.bucket(bucket_id)

    # fetching raw jsons using blob names
    blob_prefix = f'{year}/'
    blobs = bucket.list_blobs(prefix=blob_prefix)

    #logging.info(f'These are the blobs retrived from {bucket_id}: {list(blobs)}')
    processed_records = []

    for blob in blobs:
        if not blob.name.endswith('.json'):
            continue

        # we will first download the raw text
        try:
            content = blob.download_as_text()
            # Creating a valid python object from the raw json string
            cve_data_json = json.loads(content)

            #Passing this into the cve json extractor from parser.py
            record = extract_cvedata(cve_data_json = cve_data_json)

            if record:
                processed_records.append(record)

        except Exception as e:
            logging.error(f'Failed to download blob contents and create a record!: {e}') 

    return processed_records


def run():
    # Creating a argument parser using the argparse library
    argparser = argparse.ArgumentParser(description= 'Transform raw CVE json text files to structured BigQuery tables')

    # adding years flag arugument to the argument parser
    #argparser.add_argument('--years', action='store_true', help='Pass years thru comma separated input. If not, get years from cve-raws-bucket bucket')

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
            record = transform_tocsv_load_to_gcs_bq(year)
            combined_proccessed_records.extend(record)
        except Exception as e:
            logging.error(f'Failed to process for year {year}: {e}')
    
    if combined_proccessed_records:
        create_combined_table(combined_processed_records=combined_proccessed_records)
    else:
        logging.warning(f'Error creating combined table!')


if __name__ == '__main__':
    run()

    


            

