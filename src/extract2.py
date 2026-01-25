import requests
from requests.adapters import HTTPAdapter
import json
import csv
import os
import time

from datetime import datetime
import io
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from urllib3.util.retry import Retry
from src.config import IS_LOCAL

from src.gc import GoogleClient

from src.parser import extract_cvedata

from src.config import GCLOUD_PROJECTNAME, GCLOUD_BUCKETNAME
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#If not available locally will not execute
from dotenv import load_dotenv
load_dotenv(override=True)
             
class cveExtractor():
    def __init__(self, islocal: bool = IS_LOCAL, branch: str = 'develop', token: Optional[str] = None):
        
        self.islocal= islocal

        self.branch = branch
        self.base_url = "https://api.github.com"
        self.raw_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"

        self.headers = {
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.max_workers = 25

        retry_strategy = Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1
        )

        adapter = HTTPAdapter(
            max_retries= retry_strategy,
            pool_connections = self.max_workers,
            pool_maxsize= self.max_workers * 2
        )

        self.session = requests.Session()
        self.session.mount("https://", adapter)
        #self.session.headers.update(self.headers)

        
        GH_TOKEN = os.environ.get('GH_TOKEN')
        self.token = GH_TOKEN or token
        #logging.info(f'This is the set GH token: {self.token}')
        
        if self.token:
            # Add token to self.headers then update the header to current sessoion by usung update method
            self.session.headers.update({
                'Authorization': f'token {self.token}'})
            logging.info('GitHub token for authentication was found and used to establish session')
        else:
            logging.warning(" No GitHub token found")

        #Instantiating a gc class if cloud mode
        if self.islocal == False:
            self.google_client = GoogleClient(isLocal=self.islocal)
            logging.info(f'Instantiated a google client for remote upload')
        else:
            logging.info(f'Local mode so no google client instance is created')
            self.google_client = None     

    def _handle_rate_limit(self, response):
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            current_time = int(time.time())
            wait_time = reset_time - current_time + 5 # Add 5 seconds buffer
            
            if wait_time > 0:
                logging.warning(f" Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True
        return False
    
    def test_connection(self):
        try:
            response = self.session.get(f'{self.base_url}/repos/{self.repo_owner}/{self.repo_name}', headers=self.headers)
            response.raise_for_status()
        except Exception as e:
            logging.error(f'Error establishing connection with {self.repo_name} repository: {e}')

        if response.status_code == 200:
            logging.info(f'Successfully estabished connection with {self.repo_name} repository during test phase!')
            # Check rate limits
            rate_limit_remaining = response.headers.get('x-ratelimit-remaining')
            rate_limit_reset = response.headers.get('x-ratelimit-reset')

            if rate_limit_remaining:
                print(f"API Rate limit remaining: {rate_limit_remaining}")
                if int(rate_limit_remaining) < 60:
                    logging.warning("Low rate limit remaining gh token not set")
            
            return True

        else:
            logging.error(f"Failed to get file : {response.status_code}")
            return False

    # Method to get all INFORMATION on CVE file entries for each year directory 
    # year_data = {'year' : '1999', subdirs:{'1xxx' : [{'name: 'CVE-01-01-199', 'download_url': url},], '2xxx': [{},{}]}}
    def get_cve_files_for_year(self, year: str) -> Dict:

        # This is the main data structure to hold year data       
        year_data = {'year': year, 'subdirs': {}}  
        
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}"
        params = {'ref': self.branch}
        
        try:
            response = self.session.get(url, params=params)  
            logging.info(f" Response status for year {year}: {response.status_code}")
            
            if self._handle_rate_limit(response):
                response = self.session.get(url, params=params)

            if response.status_code == 200:
                year_response_data = response.json()
                logging.info(f" Found {len(year_response_data)} subdirectories in {year} year directory")
                
                for item in year_response_data:
                    logging.info(f"   - {item['name']}")

                # Process directories only
                subdirs = [item for item in year_response_data if item['type'] == 'dir']

                for i, item in enumerate(subdirs):
                    subdir_name = item['name']
                    logging.info(f"    - [{i+1}/{len(subdirs)}] Processing {subdir_name}...")
                    
                    # Initialize subdirectory
                    year_data['subdirs'][subdir_name] = []
                    
                    subdir_url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents/{year}/{subdir_name}"
                    logging.info(f"Requesting: {subdir_url}")

                    subdir_response = self.session.get(subdir_url, params=params)
                    #logging.info(f"Subdir response code: {subdir_response.status_code}")

                    if self._handle_rate_limit(subdir_response):
                        subdir_response = self.session.get(subdir_url, params=params)

                    if subdir_response.status_code == 200:
                        files = subdir_response.json()
                        logging.info(f"Found {len(files)} items in {subdir_name}")
                        
                        file_count = 0
                        for file_item in files:
                            if (file_item['type'] == 'file' and 
                                file_item['name'].startswith('CVE-') and
                                file_item['name'].endswith('.json')):
                                
                                year_data['subdirs'][subdir_name].append({
                                    'name': file_item['name'],
                                    'download_url': file_item['download_url'],
                                })
                                file_count += 1
                        
                        logging.info(f"Added {file_count} CVE files from {subdir_name}")
                    else:
                        logging.error(f"Failed to get {subdir_name}: {subdir_response.status_code}")
                        if subdir_response.status_code != 200:
                            logging.error(f"Error details: {subdir_response.text[:200]}")
            else:
                logging.error(f"Failed to get year {year}: {response.status_code}")
                logging.error(f"Error details: {response.text[:200]}")

        except requests.RequestException as e:
            logging.error(f"Network error: {e}")

        total_files = sum(len(files) for files in year_data['subdirs'].values())
        logging.info(f"Summary: {total_files} total CVE files across {len(year_data['subdirs'])} subdirectories for {year} year added")

        return year_data
    
    def extract_single_cve_file(self, file: Dict = {}, year: str = ''):
        file_name = file['name']
        file_download_url = file['download_url']

        year_session = requests.Session()
        if self.token:
            year_session.headers.update({
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {self.token}'
        })

        try:
            response = year_session.get(file_download_url, timeout=60)

            if self._handle_rate_limit(response=response):
                response = year_session.get(file_download_url)

            if response.status_code == 200:
                #logging.info(f'Successfully downloaded file: {file_name}')
                # Converts response to a python dictionary
                cve_dict = response.json()

                if cve_dict:
                    cveId = cve_dict.get('cveMetadata', {}).get('cveId', 'none')
                    filename_string = f'{year}/{cveId}.json'

                    # Only run extractor IF local testing
                    if self.islocal is True:
                        # Returns another python dictionary that has extracted key value pairs for a single cve entry 
                        cve_record = extract_cvedata(cve_dict)

                        record_details = {
                        'cveId': cveId,
                        'year': year,
                        'extracted_cve_record': cve_record,
                        'filename_string': filename_string,}

                        return record_details

                    else:
                        bronze_table_row = {
                        'cveId': cveId,
                        'year': int(year),
                        # Must be a string that will appended to the ndjson file for reading later
                        'filename_string': filename_string,
                        'extracted_cve_record': extract_cvedata(cve_dict),
                        }
                        return bronze_table_row 
                                
        except Exception as e:
            logging.error(f'Failed to fetch file {file_name} from {file_download_url}: {e}')
        
    def files_generator(self, year_data: Dict):
            for subdir_files in year_data['subdirs'].values():
                for file in subdir_files:
                    yield file

    def extract_store_cve_data(self, year_data: Dict = {}, maxworkers: int = 25):
        year = year_data['year']
        
        
        total_files_in_year = sum(len(f) for f in year_data['subdirs'].values())
        logging.info(f'Starting processing for {total_files_in_year} in {year}')

        ndjson_path_for_year = f'/tmp/bronze_cve_{year}.ndjson'
        if os.path.exists(ndjson_path_for_year):
            os.remove(ndjson_path_for_year)

        maxworkers = self.max_workers
        amp_factor = 5
        max_in_memory = maxworkers * amp_factor

        files_iter = self.files_generator(year_data=year_data)

        output_file = None
        if self.islocal is False:
            output_file = open(file=ndjson_path_for_year, mode='w', encoding='UTF-8')
        else:
            extracted_rows = []

        try:
            with ThreadPoolExecutor(max_workers=maxworkers) as executor:
                pending = set()
                names_pending_by_future = {}

                # Initial add to the pending
                for _ in range(max_in_memory):
                    try:
                        current_file = next(files_iter)
                        file_name = current_file['name']
                        future = executor.submit(self.extract_single_cve_file, current_file, year)
                        if future:
                            logging.info(f'Successfully downloaded file: {file_name}')
                            pending.add(future)
                            names_pending_by_future[future] = file_name
                    except StopIteration:
                        break

                while pending:
                    # create a set of done futures and pending futures
                    done, pending = wait(fs=pending, timeout=30, return_when=FIRST_COMPLETED)
                    try:  
                        for future in done:
                            result = future.result()    
                            fname = names_pending_by_future.pop(future, "Unknown")
                            
                            if result is None:
                                continue

                            if self.islocal is False:
                                output_file.write(json.dumps(result) + '\n')
                            else:
                                extracted_rows.append(result.get('extracted_cve_record'))
                            
                            del result 
                    except Exception as e:
                        logging.error(f'Error processing {fname} in {year}: {e}')
                        continue  
                    
                    # After the result of that future has been proccessed
                    # ie: 1. Got a valid result and either written to ndjson file or added to extracted rows to write locally alter
                    # 2. Skipped as a error
                    # We add the next future to pending untill it keeps 
                    try:
                        next_file = next(files_iter)
                        next_future = executor.submit(self.extract_single_cve_file, next_file, year)
                        pending.add(next_future)
                        names_pending_by_future[next_future] = next_file['name']
                    except StopIteration:
                        pass

        finally:
            if output_file:

                try:
                    output_file.close()
                    logging.info(f'Successfully wrote ndjson file for year {year}')
    
                except Exception as e:
                    logging.warning(f'Something went wrong closing the file {ndjson_path_for_year}: {e}')
        
        if self.islocal is False:
            try:
                # Upload to the gcs bucket ndjson folder and then delete temp file
                blob_name = f'NDjson_files/{year}/ndjson_{year}_file.ndjson'
                self.google_client.upload_blob(blobname=blob_name, local_filepath=ndjson_path_for_year)

                os.remove(ndjson_path_for_year) 
            except Exception as e:
                    logging.warning(f'Something went wrong uploading {blob_name} to {GCLOUD_BUCKETNAME} : {e}')
        else:
            logging.info(f'Creating local dataset for year {year}')
            self.year_to_csv(year= year, year_processed_files=extracted_rows)

    def year_to_csv(self, year_processed_files: List, year):
        try:
            local_dataset_folder_path = os.path.join(os.getcwd(), 'dataset_local')

            os.makedirs(local_dataset_folder_path, exist_ok=True)

            csv_file_path = os.path.join(local_dataset_folder_path, f'cve_data_{year}.csv')

            for file in year_processed_files:
                
                if isinstance(file.get('impacted_products'), list):
                    file['impacted_products'] = ','.join(file['impacted_products'])
                
                if isinstance(file.get('vulnerable_versions'), list):
                    file['vulnerable_versions'] = ','.join(file['vulnerable_versions'])
                
                if file.get('cvss_version') == 4.0:
                    if isinstance(file.get('confidentiality_impact'), list):
                        file['confidentiality_impact'] = str(file['confidentiality_impact'])
                    if isinstance(file.get('integrity_impact'), list):
                        file['integrity_impact'] = str(file['integrity_impact'])
                    if isinstance(file.get('availability_impact'), list):
                        file['availability_impact'] = str(file['availability_impact'])
                
            with open(csv_file_path, mode ='w', newline='', encoding='UTF-8') as csvfile:

                if year_processed_files:
                    fieldnames = list(year_processed_files[0].keys())
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                    writer.writeheader()
                    writer.writerows(year_processed_files)
            
            logging.info(f'Successfully created csv file for {year}')
        except Exception as e:
            logging.warning(f'There was an issue creating csv file for {year}: {e}')    
    

    #DEGUGGING METHOD to extract data for a specific CVE file in the year data
    def extract_data_for_cve_record(self, year_data: Dict, file_name: str):
        all_subdirs = year_data.get('subdirs', {})
        print(f'These are all subdirs: {all_subdirs.keys()}')

        download_url = ''
        for subdir in all_subdirs:
            for file in all_subdirs[subdir]:
                if file['name'] == file_name:
                    download_url = file['download_url']
        
        logging.info(f"Downloading CVE record from: {download_url}")

        try:
            response = self.session.get(download_url)
        
            if self._handle_rate_limit(response):
                response = self.session.get(download_url)

            if response.status_code == 200:
                cve_data = response.json()

                extracted_data = extract_cvedata(cve_data)
                if extracted_data:
                    logging.info(f"Successfully downloaded {file_name}")
                    
                return extracted_data

        except json.JSONDecodeError as e:
                logging.error(f"JSON parsing error for {file_name}: {e}")


    # Psuedo main function called from main.py
    def run(self, years: List[str] = [], cve_debug_id: Optional[str] = ''):

        success = self.test_connection()

        # If succesful test connection is established
        if success:
            if cve_debug_id:
                year = cve_debug_id.split('-')[1]
                year_data_file = self.get_cve_files_for_year(year)
                extracted_data = self.extract_data_for_cve_record(year_data = year_data_file, file_name = cve_debug_id)
                print(extracted_data)

            if years: 
                for year in years:
                    # Since for both local and cloud mode we still get the years
                    # years will be either all the available years (get_years())
                    # or can be the custom list of years for testing
                    year_data_file = self.get_cve_files_for_year(year)
                    self.extract_store_cve_data(year_data= year_data_file)







        

        

