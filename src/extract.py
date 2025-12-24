import requests
import json
import csv
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

from src.config import GH_TOKEN

from src.gc import GoogleClient

from src.parser import extract_cvedata


logging.basicConfig(level=logging.INFO)

#If not available locally will not execute
load_dotenv(override=True)

class cveExtractor():
    def __init__(self, islocal: Optional[bool] = True, branch: str = 'develop', token: Optional[str] = None):

        self.branch = branch
        self.base_url = "https://api.github.com"
        self.raw_url = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
        self.repo_owner = "cisagov"
        self.repo_name = "vulnrichment"

        self.islocal = islocal

        #Instantiating a gc class if remote execution
        if self.islocal == False:
            self.google_client = GoogleClient()
            logging.info(f'Instantiated a google client for remote upload')
        else:
            self.google_client = None

        self.headers = {
            'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
            'Accept': 'application/vnd.github.v3+json'
        }

        self.cve_list = []

        #Establish a new session
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.token = GH_TOKEN or token
        #logging.info(f'This is the set GH token: {self.token}')
        
        if self.token:
            logging.info('GitHub token for authentication was found and used to establish session')
        else:
            logging.warning(" ⚠️ No GitHub token found. Using unauthenticated requests, which may have lower rate limits. ⚠️")

        

    def _handle_rate_limit(self, response):
        if response.status_code == 403 and 'rate limit' in response.text.lower():
            reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
            current_time = int(time.time())
            wait_time = reset_time - current_time + 5 # Add 5 seconds buffer
            
            if wait_time > 0:
                logging.warning(f"⏳ Rate limit exceeded. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                return True
        return False
    
    def test_connection(self):
        try:
            response = self.session.get(f'{self.base_url}/repos/{self.repo_owner}/{self.repo_name}')
            response.raise_for_status()
        except:
            logging.error(f'Error establishing connection with {self.repo_name} repository')

        if response.status_code == 200:
            logging.info(f'Successfully estabished connection with {self.repo_name} repository')
            # Check rate limits
            rate_limit_remaining = response.headers.get('x-ratelimit-remaining')
            rate_limit_reset = response.headers.get('x-ratelimit-reset')

            if rate_limit_remaining:
                print(f"✓ API Rate limit remaining: {rate_limit_remaining}")
                if int(rate_limit_remaining) < 60:
                    logging.warning("⚠️  Warning: Low rate limit remaining. Consider using a GitHub token.")
            
            return True

        else:
            logging.error(f"❌ Failed to get file : {response.status_code}")
            return False
        
    def get_years(self) -> List[str]:
        url = f"{self.base_url}/repos/{self.repo_owner}/{self.repo_name}/contents"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                years = []

                for item in data:
                    if item['type'] == 'dir' and item['name'] not in ['.github', 'assets']:
                        years.append(item['name'])
                logging.info(f"Number of available years: {len(years)}")
                return years
            else:
                logging.error(f"Error fetching years: {response.status_code}")
                return []
        except requests.RequestException as e:
            logging.error(f"Error fetching years: {e}")
            return []

    # Method to get all information on CVE file entries for each year directory 
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
                
                # Show what we actually got
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
                    logging.info(f"Subdir response code: {subdir_response.status_code}")

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
                        
                        logging.info(f"       ✅ Added {file_count} CVE files from {subdir_name}")
                    else:
                        logging.error(f"       ❌ Failed to get {subdir_name}: {subdir_response.status_code}")
                        if subdir_response.status_code != 200:
                            logging.error(f"       📝 Error details: {subdir_response.text[:200]}")
            else:
                logging.error(f"❌ Failed to get year {year}: {response.status_code}")
                logging.error(f"📝 Error details: {response.text[:200]}")

        except requests.RequestException as e:
            logging.error(f"❌ Network error: {e}")

        total_files = sum(len(files) for files in year_data['subdirs'].values())
        logging.info(f"✅ Summary: {total_files} total CVE files across {len(year_data['subdirs'])} subdirectories for {year} year added")

        return year_data


    def extract_store_cve_data(self, year_data: Dict):

        logging.info(f"🔍 Starting to process year data for {year_data['year']}...")

        # We will use this list to batch uploads and csv entries

        try:
            year_processed_files = []
            # Iterate thru each subdirectory
            for subdir in year_data['subdirs']:

                logging.info(f"    - Processing subdirectory: {subdir}")

                #Instantiating a subdir list as well
                subdir_processed_files = []

                # Iterate over each file in chosen subdirectory
                for file in year_data['subdirs'][subdir]:

                    file_name = file['name']
                    download_url = file['download_url']
                    
                    try: 
                        response = self.session.get(download_url)
                    
                        if self._handle_rate_limit(response):
                            response = self.session.get(download_url)

                        if response.status_code == 200:
                            logging.info(f"✅ Successfully downloaded {file_name}")

                            try: 
                                # This is the raw JSON file
                                cve_data = response.json()

                                # If raw CVE json exists
                                if cve_data:
                                    # appending extracted data from response
                                    #record = self.extract_cve_data(cve_data)

                                    # THIS IS THE MOST IMPORTANT
                                    # WE ARE USING THE FUNCTION FROM PARSER.PY
                                    record = extract_cvedata(cve_data)
                                    #logging.info(f'This is record: {record}')
                                    subdir_processed_files.append(record)
                                    #logging.info(f'This is subdir right now: {subdir_processed_files}')
                                    
                                    # BLOB UPLOAD in cloud mode
                                    if not self.islocal:
                                        try:
                                            # Immediately uploading to bucket if not local execution
                                            cveId = cve_data.get('cveMetadata', {}).get('cveId', 'none') 
                                            # Add extension if missing from cveId
                                            if not cveId.endswith('.json'):
                                                cveId += '.json'
                                                
                                            filename_string = f'{year_data["year"]}/{cveId}'
                                            self.google_client.upload_blob(raw_json=cve_data, filename=filename_string)
                                        except Exception as e:
                                            logging.warning(f'Failed to upload {filename_string} to GCS bucket: {e}')

                            except json.JSONDecodeError as e:
                                logging.error(f"❌ JSON parsing error for {file_name}: {e}")
                    
                    except Exception as e:
                        logging.error(f"❌ Error downloading {file_name}: {e}")
                        import traceback
            
                        traceback.print_exc()

                if subdir_processed_files:
                    #logging.info(f'Appending files from {subdir} to {year_data['year']} processing list')
                    #logging.info(f'This is the subdir: {subdir_processed_files}')

                    # Flattening the year_processed array by using extend  
                    year_processed_files.extend(subdir_processed_files)

        except Exception as e:
            logging.error(f"❌ Unexpected error in extract_store_cve_data: {e}")
            import traceback
            traceback.print_exc()

        
        if year_processed_files:
            #logging.info(f'This is the year_processed_files list: {year_processed_files}')
            # Local path: Create a csv file in the local dataset for internal storage
            if self.islocal:
                self.year_to_csv(year_processed_files, year=year_data['year'])
            else:
                # Since we have separated the transform logic we will trigger it in the dag 
                # Which will be scheduled to run after this extract script has been run for all the years
                pass
     
        return None
    
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
                logging.info(f"✅ Successfully downloaded {file_name}")
                cve_data = response.json()

                extracted_data = self.extract_cve_data(cve_data)
                

                return extracted_data

        except json.JSONDecodeError as e:
                logging.error(f"❌ JSON parsing error for {file_name}: {e}")

    

    # Psuedo main function called from main.py
    def run(self, years: List[str] = []):

        
        success= self.test_connection()

        # If succesful test connection is established
        if success:
            for year in years:
                # Since for both local and cloud mode we still get the years
                # years will be either all the available years (get_years())
                # or can be the custom list of years for testing
                year_data = self.get_cve_files_for_year(year)
                self.extract_store_cve_data(year_data)







        

        

