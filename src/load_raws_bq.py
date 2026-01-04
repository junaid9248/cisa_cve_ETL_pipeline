from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv
import logging
import os
import argparse
from src.gc import GoogleClient
from src.extract2 import cveExtractor

logging.basicConfig(level=logging.INFO)
#If not available locally will not execute
load_dotenv(override=True)

def load_ndjsons_to_bq(year: str = '', isTruncated: bool = False):
    googleclient = GoogleClient()
    bucket_id = googleclient.bucket_name

    gcs_ndjsonblob_uri = f"gs://{bucket_id}/NDjson_files/{year}/*.ndjson"
    googleclient.create_fill_raws_table(source_uri=gcs_ndjsonblob_uri, isTruncated= isTruncated, year = year)
    '''
    #create a bucket object with or bucker id
    bucket = googleclient.storage_client.bucket(bucket_name=bucket_id)
    #Fetch all blobs for the year
    blob_prefix = f'NDjson_files/{year}'
    yearly_ndjson_blobs = bucket.list_blobs(prefix=blob_prefix)

    for blob in yearly_ndjson_blobs:
        if not blob.name.endswith(".ndjson"):
            continue
        gcs_ndjsonblob_uri = f'gs://{bucket_id}/{blob.name}'
        googleclient.create_fill_raws_table(source_uri=gcs_ndjsonblob_uri, isTruncated= isTruncated)
        '''

def run():
    # Creating a argument parser using the argparse library
    argparser = argparse.ArgumentParser(description= 'Transform raw CVE ND json text files into a raw bronze table')

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

    isTruncated = False
    for year in years:
        load_ndjsons_to_bq(year=year, isTruncated = isTruncated)
        isTruncated = True


if __name__ == '__main__':
    run()