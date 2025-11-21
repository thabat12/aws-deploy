import boto3
from functools import lru_cache

# modify this for various settings in local dev environment
class Constants:
    PROFILE = 'default'
    REGION_NAME = 'us-east-2'
    TAB = '  '

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'

ANSI_RESET = '\033[0m'

def logging(msg, col: Colors = ''):
    print(f'{col}{msg}{ANSI_RESET}')

session = boto3.Session(
    profile_name=Constants.PROFILE,
    region_name=Constants.REGION_NAME
)


@lru_cache(maxsize=None)
def get_client(service_name: str):
    """
    Get a cached AWS service client.
    
    Uses LRU cache to avoid creating multiple client instances for the same service.
    This improves performance by reusing client connections.
    
    Args:
        service_name: Name of the AWS service (e.g., 'lambda', 'iam', 'sts')
        
    Returns:
        boto3 client: Cached client for the specified service
    """
    return session.client(service_name)