import os
from dotenv import load_dotenv

load_dotenv()

IS_LOCAL = os.getenv('IS_LOCAL', 'True').lower() == 'true'
GH_TOKEN = os.getenv('GH_TOKEN')
GCLOUD_API_KEY = os.getenv('GCLOUD_API_KEY')
GCLOUD_BUCKETNAME = os.getenv('GCLOUD_BUCKETNAME')
GCLOUD_APP_CREDENTIALS = os.getenv('GCLOUD_APP_CREDENTIALS')
GCLOUD_PROJECTNAME = os.getenv('GCLOUD_PROJECTNAME')
MY_EMAIL = os.getenv('EMAIL_ID')