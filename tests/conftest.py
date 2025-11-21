"""
Pytest configuration file for aws-deploy tests.

This file contains shared fixtures and configuration for all tests.
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from functools import wraps


@pytest.fixture
def response_metadata_fixture():
    return {
        'RequestId': '0b0f2830-804d-4ecf-b502-a095ecad034a',
        'HTTPStatusCode': 200,
        'HTTPHeaders': {
            'x-amzn-requestid': '0b0f2830-804d-4ecf-b502-a095ecad034a',
            'x-amz-sts-extended-request-id': 'MTp1cy1lYXN0LTI6UzoxNzYzNjc1MTY0NTk5OlI6Vjh0ZzQ0S0I=',
            'content-type': 'text/xml',
            'content-length': '387',
            'date': datetime(2025, 1, 1, 0, 0, 0)
        },
        'RetryAttempts': 0
    }

# Helper wrapper to add ResponseMetadata to return values of boto3 clients.
def with_response_metadata(response_metadata):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if isinstance(result, dict):
                result = result.copy()
                result['ResponseMetadata'] = response_metadata
            return result
        return wrapper
    return decorator

"""
    Mock IAM client for testing.

    Manually mock the IAM client to:
    - Create a role
    - Get a role
    - Put a role policy
    - Get a role policy
"""
@pytest.fixture
def role_fixture(request):
    if hasattr(request, 'param'):
        return request.param
    return {}


@pytest.fixture
def mock_iam_client(role_fixture, response_metadata_fixture, aws_account_fixture):
    mock_iam_client = Mock()
    
    @with_response_metadata(response_metadata_fixture)
    def create_role(*args, **kwargs):
        role_name = kwargs['RoleName']
        assume_role_policy_doc = kwargs.get('AssumeRolePolicyDocument', '{}')
        tags = kwargs.get('Tags', [
            {
                'Key': 'Creator',
                'Value': f'arn:aws:iam::{aws_account_fixture}:user/test-user'
            }
        ])
        
        role_arn = f'arn:aws:iam::{aws_account_fixture}:role/{role_name}'
        
        role_fixture[role_name] = {
            'Role': {
                'Path': '/',
                'RoleName': role_name,
                'RoleId': 'AROA-EXAMPLE-ID',
                'Arn': role_arn,
                'CreateDate': datetime(2025, 1, 1),
                'AssumeRolePolicyDocument': assume_role_policy_doc,
                'MaxSessionDuration': 3600,
                'RoleLastUsed': {},
                'Tags': tags
            },
            'Policies': {}
        }
        
        return role_fixture[role_name].copy()
    
    @with_response_metadata(response_metadata_fixture)
    def get_role(*args, **kwargs):
        role_name = kwargs['RoleName']
        if role_name not in role_fixture:
            error_response = {'Error': {'Code': 'NoSuchEntity'}}
            raise ClientError(error_response, 'GetRole')
        
        return role_fixture[role_name]['Role'].copy()
    
    # TODO: Validate this function return value
    @with_response_metadata(response_metadata_fixture)
    def put_role_policy(*args, **kwargs):
        role_name = kwargs['RoleName']
        policy_name = kwargs['PolicyName']
        policy_document = kwargs['PolicyDocument']
        
        if role_name not in role_fixture:
            error_response = {'Error': {'Code': 'NoSuchEntity'}}
            raise ClientError(error_response, 'PutRolePolicy')
        
        role_fixture[role_name]['Policies'][policy_name] = policy_document
        
        return {}
    
    @with_response_metadata(response_metadata_fixture)
    def get_role_policy(*args, **kwargs):
        role_name = kwargs['RoleName']
        policy_name = kwargs['PolicyName']
        
        if role_name not in role_fixture:
            error_response = {'Error': {'Code': 'NoSuchEntity'}}
            raise ClientError(error_response, 'GetRolePolicy')
        
        if policy_name not in role_fixture[role_name]['Policies']:
            error_response = {'Error': {'Code': 'NoSuchEntity'}}
            raise ClientError(error_response, 'GetRolePolicy')
        
        return {
            'RoleName': role_name,
            'PolicyName': policy_name,
            'PolicyDocument': role_fixture[role_name]['Policies'][policy_name]
        }
    
    mock_iam_client.create_role.side_effect = create_role
    mock_iam_client.get_role.side_effect = get_role
    mock_iam_client.put_role_policy.side_effect = put_role_policy
    mock_iam_client.get_role_policy.side_effect = get_role_policy
    
    return mock_iam_client


"""
    Mock STS client for testing.

    Manually mock the STS client to:
    - Get the caller identity
"""
@pytest.fixture
def aws_account_fixture():
    return '752655331954'


@pytest.fixture
def mock_sts_client(aws_account_fixture, response_metadata_fixture):
    mock_sts_client = Mock()

    @with_response_metadata(response_metadata_fixture)
    def get_caller_identity(*args, **kwargs):
        return {
            'Arn': f'arn:aws:iam::{aws_account_fixture}:user/test-user',
            'UserId': str(aws_account_fixture),
            'Account': str(aws_account_fixture),
        }

    mock_sts_client.get_caller_identity.side_effect = get_caller_identity
    return mock_sts_client

@pytest.fixture
def functions_fixture(request):
    if hasattr(request, 'param'):
        return request.param
    return {}


"""
    Mock Lambda client for testing.

    Manually mock the Lambda client to:
    - Get a function
    - Create a function
"""
# TODO: cross reference this with actual lambda client responses to ensure consistency
@pytest.fixture
def mock_lambda_client(
    functions_fixture,
    aws_account_fixture,
    response_metadata_fixture
):
    mock_lambda_client = Mock()

    @with_response_metadata(response_metadata_fixture)
    def get_function(*args, **kwargs):
        function_name = kwargs['FunctionName']
        if function_name not in functions_fixture:
            error_response = {'Error': {'Code': 'ResourceNotFoundException'}}
            raise ClientError(error_response, 'GetFunction')
        
        return functions_fixture[function_name]
    
    @with_response_metadata(response_metadata_fixture)
    def create_function(*args, **kwargs):
        function_name = kwargs['FunctionName']
        runtime = kwargs.get('Runtime', 'python3.11')
        role = kwargs.get('Role')
        handler = kwargs.get('Handler')
        code = kwargs.get('Code', {})
        zip_data = code.get('ZipFile', b'')
        
        if function_name in functions_fixture:
            error_response = {'Error': {'Code': 'ResourceConflictException'}}
            raise ClientError(error_response, 'CreateFunction')
        
        function_arn = f'arn:aws:lambda:us-east-2:{aws_account_fixture}:function:{function_name}'
        # TODO: in the future, code should also support s3 bucket functionalities
        code_size = len(zip_data) if zip_data else 0
        
        functions_fixture[function_name] = {
            'Configuration': {
                'FunctionName': function_name,
                'FunctionArn': function_arn,
                'Runtime': runtime,
                'Role': role,
                'Handler': handler,
                'CodeSize': code_size,
                'Description': '',
                'Timeout': 3,
                'MemorySize': 128,
                'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
                'CodeSha256': '',
                'Version': '$LATEST',
                'State': 'Active',
                'LastUpdateStatus': 'Successful',
                'PackageType': 'Zip',
                'Architectures': ['x86_64'],
            }
        }
        
        return functions_fixture[function_name]['Configuration'].copy()
    
    mock_lambda_client.get_function.side_effect = get_function
    mock_lambda_client.create_function.side_effect = create_function
    
    return mock_lambda_client

"""
    Mock client for testing.

    Patch the overall get_client function and package all mock clients
    into this single element.
"""
@pytest.fixture
def mock_get_client(
    mock_lambda_client,
    mock_iam_client,
    mock_sts_client
):
    with patch('aws_deploy.functions.get_client') as mock_get_client:
        mock_get_client.side_effect = lambda service: {
            'lambda': mock_lambda_client,
            'iam': mock_iam_client,
            'sts': mock_sts_client,
        }.get(service)
        yield mock_get_client