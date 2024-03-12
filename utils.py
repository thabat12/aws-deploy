import boto3

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