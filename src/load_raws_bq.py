from typing import Dict, List, Optional
from src.gc import GoogleClient
from time import sleep
#googleclient = GoogleClient()
import logging
logging.basicConfig(level=logging.INFO)

#If not available locally will not execute
from dotenv import load_dotenv
load_dotenv(override=True)

class ndjson_loader():

    def __init__(self, isLocal: bool = False):
        self.isLocal = isLocal
        self.google_client = GoogleClient(isLocal= self.isLocal)
        self.isFirstRun = True

    def load_ndjsons_to_bq(self, years: List = []):
        bucket_id = self.google_client.bucket_name
        for year in years:
            sleep(3)
            gcs_ndjsonblob_uri = f"gs://{bucket_id}/NDjson_files/{year}/*.ndjson"
            self.google_client.create_fill_raws_table(source_uri=gcs_ndjsonblob_uri, isFirstRun= self.isFirstRun, year = year)
            self.isFirstRun = False