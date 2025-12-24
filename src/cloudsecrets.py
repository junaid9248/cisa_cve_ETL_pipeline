from google.cloud import secretmanager
from typing import Optional
from functools import lru_cache

@lru_cache(maxsize=None)
def get_secret_manager_client() -> secretmanager.SecretManagerServiceClient:
    return secretmanager.SecretManagerServiceClient()

@lru_cache(maxsize=None)
def get_env_variable_from_secrets(secret_id: str = 'None', version: Optional[str] = 'latest') -> str:

    gc_secretmanager = secretmanager.SecretManagerServiceClient()
    name = f'projects/cisa-cve-data-pipeline/secrets/{secret_id}/versions/{version}'

    try: 
        response = gc_secretmanager.access_secret_version(request={'name': name})
        return response.payload.data.decode('UTF-8')
    
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None
