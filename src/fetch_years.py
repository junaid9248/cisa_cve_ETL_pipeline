import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from typing import List
from src.config import GH_TOKEN

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def fetch_all_years() -> List[str]:
    base_raws_url = "https://api.github.com"
    repo_owner = "cisagov"
    repo_name = "vulnrichment"

    retry_strategy = Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1
        )
    adapter = HTTPAdapter(
            max_retries= retry_strategy,
        )

    session = requests.Session()
    session.mount('https://', adapter=adapter)

    token = GH_TOKEN

    if token:
            # Add token to self.headers then update the header to current sessoion by usung update method
            session.headers.update({
                'User-Agent': 'CISA-Vulnrichment-Extractor/1.0',
                'Accept': 'application/vnd.github.v3+json',
                'Authorization': f'token {token}'})
            logging.info('GitHub token for authentication was found and used to establish session')
    else:
        logging.warning(" No GitHub token found rate limits might be applied! ")

    #get all years
    fetch_url = f"{base_raws_url}/repos/{repo_owner}/{repo_name}/contents"
    try:
        response = session.get(fetch_url)
        if response.status_code == 200:
            data = response.json()
            years = []

            for item in data:
                if item['type'] == 'dir' and item['name'] not in ['.github', 'assets']:
                    years.append(item['name'])
            logging.info(f"Number of available years: {len(years)}")
            return  years
      
    except requests.RequestException as e:
        logging.error(f"Error fetching years: {e}")
        return []


if __name__ == '__main__':
    fetch_all_years()
    