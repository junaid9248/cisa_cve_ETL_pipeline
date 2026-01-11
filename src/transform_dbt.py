
import subprocess

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys

def run_dbt_transform_command(dbt_command: str = ''):
    dbt_command = ['dbt' ,'build' ,'--project-dir' ,'dbt' ,'--project-profile' ,'dbt' ,'--select ','sources']

    try:
        result = subprocess.run(args=dbt_command,
                                cwd= 'dbt',
                                capture_output= True, 
                                text= True, 
                                check=True)
            
        logging.info(f'dbt transform output: {result}')
    except subprocess.CalledProcessError as e:
        logging.error(f"dbt transformation failed!")
        logging.error(f"Error output:\n{e.stderr}")
        sys.exit(1)



