import os

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# load_dotenv() reads a .env file and injects those key-value pairs into os.environ to mimic prod behaviour
# Only if an env file is available then does this work or it gets skipped
from dotenv import load_dotenv
load_dotenv(override=True)

def fetch_env_variable(var_name, default_var_value:None):
    try:
        value = os.environ.get(key=var_name, default=default_var_value)
        return value

    except Exception as e:
        logging.warning(f'The value for {var_name} was not set: {e}')


# If 'K_SERVICE' exists, run in Cloud Run
IS_CLOUD = os.environ.get('K_SERVICE') is not None
IS_LOCAL = not IS_CLOUD

# Fetch the other variables 
GCLOUD_PROJECTNAME = fetch_env_variable('GCLOUD_PROJECTNAME', default_var_value= None)
GCLOUD_BUCKETNAME = fetch_env_variable('GCLOUD_BUCKETNAME', default_var_value=None)
GOOGLE_APPLICATION_CREDENTIALS_PATH = fetch_env_variable('GOOGLE_APPLICATION_CREDENTIALS_PATH', default_var_value= None)
GH_TOKEN = fetch_env_variable('GH_TOKEN', default_var_value=None)

MY_EMAIL = fetch_env_variable('MY_EMAIL', None)
AIRFLOW__WEBSERVER__SECRET_KEY = fetch_env_variable('AIRFLOW__WEBSERVER__SECRET_KEY', None)











