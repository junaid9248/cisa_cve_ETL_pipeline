import logging
import json 
import argparse
from typing import Dict, List, Optional

from google.cloud.storage import transfer_manager

from .gc import GoogleClient
from src.extract import cveExtractor
from .parser import extract_cvedata
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import os
import shutil
import json
logging.basicConfig(level=logging.INFO)

def create_combined_staging_table(gcs_uri:str = '', year: str= 'combined_staging', did_truncate: bool = False):
    try:
        gc = GoogleClient()
        logging.info(f'Creating combined staging table...')
        # This table will be merged with the final table in BigQuery
        gc.combined_staging_table_bigquery(gcs_uri=gcs_uri, year=year, did_truncate = did_truncate)
    except Exception as e:
        logging.info(f'Failed to initialize a staging table for year {year}: {e}')
        
def extract_cvedata_from_filepath(filepath: str='', year: str ='2022'):
    #logging.info(f'This is the filepath:{filepath}')
    try:
        logging.info(f'Extracting cve json from file at {filepath}')

        with open(file=filepath, mode='r') as file:
            cve_json = json.load(file)
        
        #logging.info(f'Extracted cve_json from {filepath}: {cve_json}')

        #Getting list of dicts for each cve entry from json 
        record = extract_cvedata(cve_data_json= cve_json)
        raw_json_str= json.dumps(cve_json)

        record_details = {
            'cve_id': record['cveID'],
            'gcs_path': 

        }
        return record
    except Exception as e:
        logging.error(f'Error opening file {filepath}: {e}')

def iter_downloaded(tm_results, jsons_list, tmp_root_dir):
    for i, result in enumerate(tm_results):
        if isinstance(result, Exception):
            logging.error(f'Failed to download {jsons_list[i]}: {result}')
            continue
        blob_name = jsons_list[i]
        file_path = f'{tmp_root_dir}{blob_name}'
        yield blob_name, file_path

# Batching the blobs for larger years
def create_blob_bacthes(blobs, max_batch_size: Optional[int] = 1000):
    current_batch = []

    for blob in blobs:
        name = str(blob.name)
        if name.endswith('.json'):
            current_batch.append(name)
        
        if len(current_batch) <= max_batch_size:
            yield current_batch
            current_batch = []
    
    if current_batch:
        yield current_batch

def transform_tocsv_load_to_gcs_bq(year: str = '1999') -> str:
   
    logging.info(f'Transforming raw json to processed NDJSON for year: {year}')

    gc = GoogleClient()
    storage_client = gc.storage_client
    bucket_id = gc.bucket_name
    bucket = storage_client.bucket(bucket_name=bucket_id)

    blob_prefix = f'{year}/'
    year_cve_raws_blobs = bucket.list_blobs(prefix=blob_prefix)


    '''
    # Getting cve ID of all the raw cves for the year passed
    jsons_list = [str(blob.name) for blob in year_cve_raws_blobs if blob.name.endswith('.json')]

    if not jsons_list:
        logging.warning(f'No JSON blobs found for year {year}')
        return ''
    '''

    #Create a temp dir where downloaded blobs will be stored
    tmp_root_dir = f'/tmp/cve_blob_downloaded/'
    os.makedirs(tmp_root_dir, exist_ok=True)
    
    #Creating a temp dir where created ndjsons will be stored before being posted to gcs bucket
    local_ndjson_path = f'/tmp/cve_processed_{year}.ndjson'
    if os.path.exists(local_ndjson_path):
        os.remove(local_ndjson_path)

    # Using transfer manager to download all jsons to a temp file at tmp_root_dir
    try:
        logging.info(f'Starting raw json downloads from GCS now for {year}')

        for batch_index, blob_batch in enumerate(blobs_batch = create_blob_bacthes(blobs=year_cve_raws_blobs)):
            logging.info(f'Total files being processed in batch: {len(blob_batch)}')

            try: 
                tm_results = transfer_manager.download_many_to_path(
                    bucket=bucket,
                    destination_directory=tmp_root_dir,
                    blob_names=blob_batch,
                    worker_type=transfer_manager.THREAD,
                    max_workers=15,
                )
            except Exception as e:
                logging.error(f'Failed to download blobs for batch {batch_index}: {e}')
                continue
            
            def 
            for i, result in iter(tm_results):
                if isinstance(result, Exception):
                    logging.error(f'Failed to download:{blob_batch[i]}')
                    continue

                blob_name = blob_batch[i]
                    file_path = f'{tmp_root_dir}{blob_name}'
                    yield blob_name, file_path
                


    except Exception as e:
        logging.error(f'Failed to download blobs for year {year}: {e}')
        shutil.rmtree(tmp_root_dir, ignore_errors=True)
        return ''
    
    max_workers = 50
    factor = 5
    max_in_mem = max_workers * factor

    processed_count = 0
    failed_count = 0

    # Writing to the local temp ndjson file
    with open(local_ndjson_path, mode='w', encoding='utf-8') as output_file:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            pending = set()
            path_by_future = {}

            files_iter = iter_downloaded(tm_results, jsons_list, tmp_root_dir)

            while len(pending) < max_in_mem:
                try:
                    blob_name, file_path = next(files_iter)
                except StopIteration:
                    break
                fut = executor.submit(extract_cvedata_from_filepath, filepath=file_path)
                pending.add(fut)
                path_by_future[fut] = file_path

            while pending:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    try:
                        record = fut.result()
                        if record:
                            output_file.write(json.dumps(record))
                            output_file.write('\n')
                            processed_count += 1
                    except Exception as e:
                        failed_count += 1
                        logging.error(f'Error parsing {path_by_future.get(fut)}: {e}')
                    finally:
                        path_by_future.pop(fut, None)

                    try:
                        blob_name, file_path = next(files_iter)
                        new_fut = executor.submit(extract_cvedata_from_filepath, filepath=file_path)
                        pending.add(new_fut)
                        path_by_future[new_fut] = file_path
                    except StopIteration:
                        pass

    logging.info(
        f'Year {year} complete: wrote {processed_count} records to {local_ndjson_path}, '
        f'failed={failed_count}'
    )

    # 3) 
    gcs_object = f'processed_ndjson/{year}/cve_processed_{year}.ndjson'
    blob = bucket.blob(gcs_object)
    blob.upload_from_filename(local_ndjson_path)

    gcs_uri = f'gs://{bucket_id}/{gcs_object}'
    logging.info(f'Uploaded processed NDJSON to {gcs_uri}')

    # 4) Cleanup raw downloads (keep NDJSON local or delete it too—your choice)
    shutil.rmtree(tmp_root_dir, ignore_errors=True)
    shutil.rmtree(local_ndjson_path,ignore_errors=True)
    # optionally: os.remove(local_ndjson_path)

    return gcs_uri



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

    # Truncate flag to truncate before first run
    did_truncate = False

    for year in years:
        year = year.strip()
        try:
            # getting the uri for ndjson file for the given year
            gcs_uri = transform_tocsv_load_to_gcs_bq(year)
          
        except Exception as e:
            logging.error(f'Failed to process for year {year}: {e}')

        if gcs_uri:
            #print(f'This is part of the combined processed records that will be used to create the staging table: {combined_proccessed_records[:10]}')
            create_combined_staging_table(year = year, gcs_uri=gcs_uri,did_truncate = did_truncate)
            #Setting to true after initial successful run as it has truncated table once
            did_truncate = True
        else:    
            logging.warning(f'Unable to fetch uri for year {year}')
            continue

        


if __name__ == '__main__':
    run()

    


            

