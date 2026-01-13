
import subprocess
from typing import List
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys

def run_dbt_command(dbt_command: List = []):
    try:
        result = subprocess.run(args=dbt_command,
                                capture_output= True, 
                                text= True, 
                                check=True)
            
        logging.info(f'dbt transform output: {result}')
    except subprocess.CalledProcessError as e:
        logging.error(f"dbt transformation failed!")
        logging.error(f"Error output:\n{e.stderr}")
        sys.exit(1)



