import os
from dotenv import load_dotenv
from src.cloudsecrets import get_env_variable_from_secrets

from typing import Optional

load_dotenv()

IS_LOCAL = os.environ.get('IS_LOCAL', 'true').lower() == 'true'
GCLOUD_PROJECTNAME = os.environ.get('GCLOUD_PROJECTNAME')


# Either set the env variables from the .env file 
# or use the secrets manager to fetch the secrets
def fetch_env_or_secret(env_var: Optional[str] = None):
    if IS_LOCAL:
        return_env = os.environ.get(env_var)
        return return_env
    else:
        return_secret_env = get_env_variable_from_secrets(env_var)
        return return_secret_env

# Fetching env variables
GH_TOKEN = fetch_env_or_secret('GH_TOKEN')
GCLOUD_BUCKETNAME = fetch_env_or_secret('GCLOUD_BUCKETNAME')
GOOGLE_APPLICATION_CREDENTIALS = fetch_env_or_secret('GOOGLE_APPLICATION_CREDENTIALS')
MY_EMAIL = fetch_env_or_secret('EMAIL_ID')
AIRFLOW__WEBSERVER__SECRET_KEY = fetch_env_or_secret('AIRFLOW__WEBSERVER__SECRET_KEY')











