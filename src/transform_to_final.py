
import subprocess
from typing import List
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys

def run_dbt_command(dbt_command: List = []):
    try:
        #dbt_command = f'dbt build --project-dir dbt --profiles-dir dbt --select sources'.split()
        result = subprocess.run(args=dbt_command,
                                text= True, 
                                check=True)
            
        logging.info(f'dbt transform output: {result}')
    except subprocess.CalledProcessError as e:
        logging.error(f"dbt transformation failed!")
        logging.error(f'Command failed with return code:{e.returncode}')
        logging.error(f"Error output: {e.output}")
        logging.error(f'Stdout and stderror:{e.stdout} | {e.stderr}')
        sys.exit(1)



