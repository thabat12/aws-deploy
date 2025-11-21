"""
Tests for aws_deploy.functions module.

This module contains tests for Lambda function deployment and management.
"""
import json
import os
import tempfile
import zipfile
from io import BytesIO
from unittest.mock import call, patch

import pytest
from datetime import datetime
from botocore.exceptions import ClientError
from enum import Enum

from aws_deploy.functions import (
    __get_lambda_function_details,
    __get_lambda_role_from_name,
    __generate_auto_role_name,
    __create_lambda_basic_execution_role,
    _wait_for_role_to_exist,
    __create_deployment_package,
    __create_lambda_function,
    __update_lambda_function,
    deploy_lambda,
    remove_lambda,
)
from aws_deploy.params import LambdaParams


class ErrorCode(Enum):
    RESOURCE_NOT_FOUND = 'ResourceNotFoundException'
    ACCESS_DENIED = 'AccessDeniedException'
    INVALID_PARAMETER = 'InvalidParameterValueException'
    SERVICE_EXCEPTION = 'ServiceException'
    TOO_MANY_REQUESTS = 'TooManyRequestsException'
    NO_SUCH_ENTITY = 'NoSuchEntity'
    EMPTY = ''
    NONE = None


def _create_error_response(error_code, message=None):
    if error_code == ErrorCode.NONE:
        return {}
    if error_code == ErrorCode.EMPTY:
        return {'Error': {}}
    error_dict = {'Code': error_code.value}
    if message is not None:
        error_dict['Message'] = message
    return {'Error': error_dict}


@pytest.fixture
def sample_lambda_params_dict_for_role():
    return {
        'function_name': 'test-function',
    }

# __get_lambda_function_details tests
@pytest.mark.parametrize(
    'functions_fixture',
    [
        {
            'test-function': {
                'Configuration': {
                    'FunctionName': 'test-function',
                    'FunctionArn': 'arn:aws:lambda:us-east-2:123456789012:function:test-function',
                    'Runtime': 'python3.11',
                    'Role': 'arn:aws:iam::123456789012:role/test-lambda-role',
                    'Handler': 'lambda_function.handler',
                    'CodeSize': 1024,
                    'Description': '',
                    'Timeout': 123,
                    'MemorySize': 123,
                    'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
                    'CodeSha256': '',
                    'Version': '$LATEST',
                    'State': 'Active',
                    'LastUpdateStatus': 'Successful',
                    'PackageType': 'Zip',
                    'Architectures': ['x86_64'],
                },
                'Code': {
                    'Location': 'https://lambda.us-east-2.amazonaws.com/functions/test-function/code'
                }
            }
        }
    ],
    indirect=True,
    ids=['test-function']
)
def test_get_lambda_function_details_success(
    mock_get_client, functions_fixture, response_metadata_fixture
):
    result = __get_lambda_function_details('test-function')

    # Instantiate the lambda client
    mock_get_client.assert_called_once_with('lambda')

    # get_function should be called with corrrect function name
    lambda_client = mock_get_client.side_effect('lambda')
    lambda_client.get_function.assert_called_once_with(
        FunctionName='test-function'
    )
    
    # result should be function data with response metadata
    assert 'ResponseMetadata' in result
    assert 'Configuration' in result

    # TODO: potentially expand this if we care about more attributes
    assert result['Configuration'] == functions_fixture['test-function']['Configuration']


@pytest.mark.parametrize(
    "error_response",
    [
        _create_error_response(ErrorCode.RESOURCE_NOT_FOUND, 'Function not found'),
        _create_error_response(ErrorCode.RESOURCE_NOT_FOUND, None),
    ],
    ids=[
        'resource_not_found_with_message',
        'resource_not_found_without_message',
    ]
)
def test_get_lambda_function_details_returns_none(
    mock_get_client, error_response
):
    lambda_client = mock_get_client.side_effect('lambda')
    lambda_client.get_function.side_effect = ClientError(
        error_response, 'GetFunction'
    )

    result = __get_lambda_function_details('non-existent-function')

    # Nothing should return if there is no function found
    assert result is None
    mock_get_client.assert_called_once_with('lambda')
    lambda_client.get_function.assert_called_once_with(
        FunctionName='non-existent-function'
    )

@pytest.mark.parametrize(
    "exception,expected_exception_type",
    [
        (
            ClientError(_create_error_response(ErrorCode.ACCESS_DENIED, 'Access denied'), 'GetFunction'),
            ClientError, # expected exception type
        ),
        (
            ClientError(_create_error_response(ErrorCode.INVALID_PARAMETER, 'Invalid parameter'), 'GetFunction'),
            ClientError, # expected exception type
        ),
        (
            ClientError(_create_error_response(ErrorCode.SERVICE_EXCEPTION, 'Service error'), 'GetFunction'),
            ClientError, # expected exception type
        ),
        (
            ValueError('Some unexpected error'),
            ValueError
        ),
        (
            RuntimeError('Runtime error'),
            RuntimeError
        ),
    ],
    ids=[
        'client_error_access_denied',
        'client_error_invalid_parameter',
        'client_error_service_exception',
        'value_error',
        'runtime_error',
    ]
)
def test_get_lambda_function_details_raises_exception(
    mock_get_client,
    exception,
    expected_exception_type
):
    lambda_client = mock_get_client.side_effect('lambda')
    lambda_client.get_function.side_effect = exception

    with pytest.raises(expected_exception_type) as exc_info:
        __get_lambda_function_details('test-function')

    mock_get_client.assert_called_once_with('lambda')
    lambda_client.get_function.assert_called_once_with(
        FunctionName='test-function'
    )


# __get_lambda_role_from_name tests
@pytest.mark.parametrize(
    'role_fixture',
    [
        {
            'test-role': {
                'Role': {
                    'Path': '/',
                    'RoleName': 'test-role',
                    'RoleId': 'AROA-EXAMPLE-ID',
                    'Arn': 'arn:aws:iam::123456789012:role/test-role',
                    'CreateDate': datetime(2025, 1, 1),
                    'MaxSessionDuration': 3600,
                    'RoleLastUsed': {}
                },
                'Policies': {}
            }
        }
    ],
    indirect=True,
    ids=['test-role']
)
def test_get_lambda_role_from_name_success(
    mock_get_client,
    role_fixture,
    response_metadata_fixture
):
    result = __get_lambda_role_from_name('test-role')
    mock_get_client.assert_called_once_with('iam')
    iam_client = mock_get_client.side_effect('iam')
    iam_client.get_role.assert_called_once_with(
        RoleName='test-role'
    )
    
    assert result is not None
    assert 'ResponseMetadata' in result

    expected_result = role_fixture['test-role']['Role'].copy()
    expected_result['ResponseMetadata'] = response_metadata_fixture
    assert result == expected_result

@pytest.mark.parametrize(
    "exception",
    [
        ClientError(
            _create_error_response(ErrorCode.NO_SUCH_ENTITY, 'Role not found'),
            'GetRole'
        ),
        ClientError(
            _create_error_response(ErrorCode.ACCESS_DENIED, 'Access denied'),
            'GetRole'
        ),
        ValueError('Some unexpected error'),
        TypeError('Type error occurred'),
        RuntimeError('Runtime error'),
    ],
    ids=[
        'client_error_no_such_entity',
        'client_error_access_denied',
        'value_error',
        'type_error',
        'runtime_error',
    ]
)
def test_get_lambda_role_from_name_exception(
    mock_get_client, mock_iam_client, exception
):
    mock_iam_client.get_role.side_effect = exception

    result = __get_lambda_role_from_name('non-existent-role')

    assert result is None
    mock_get_client.assert_called_once_with('iam')
    mock_iam_client.get_role.assert_called_once_with(
        RoleName='non-existent-role'
    )


# __generate_auto_role_name tests
@pytest.mark.parametrize(
    "function_name,expected_role_name",
    [
        ('test-function', 'test-function-lambda-exec-role'),
        ('short', 'short-lambda-exec-role'),
        ('a' * 47, 'a' * 47 + '-lambda-exec-role'),
        ('my-very-long-function-name-that-exceeds-limit', 'my-very-long-function-name-that-exceeds-limit-lambda-exec-role'),
    ],
    ids=[
        'normal_length',
        'short_name',
        'exact_max_length',
        'realistic_long_name',
    ]
)
def test_generate_auto_role_name_success(function_name, expected_role_name):
    result = __generate_auto_role_name(function_name)
    assert result == expected_role_name
    assert len(result) <= 64


# __create_lambda_basic_execution_role tests
def test_create_lambda_basic_execution_role_role_exists(
    mock_get_client,
    aws_account_fixture,
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    lambda_params.role_name = 'test-role'
    
    __create_lambda_basic_execution_role(lambda_params)


    assert call('iam') in mock_get_client.call_args_list
    assert call('sts') in mock_get_client.call_args_list

    iam_client = mock_get_client.side_effect('iam')
    sts_client = mock_get_client.side_effect('sts')

    sts_client.get_caller_identity.assert_called_once()
    iam_client.create_role.assert_called_once_with(
        RoleName='test-function-lambda-exec-role',
        AssumeRolePolicyDocument=json.dumps(lambda_params._default_trust_policy),
        Tags=[
            {
                'Key': 'Creator',
                'Value': f'arn:aws:iam::{aws_account_fixture}:user/test-user'
            }
        ]
    )
    iam_client.put_role_policy.assert_called_once_with(
        RoleName='test-function-lambda-exec-role',
        PolicyName='LambdaBasicExecutionPolicy',
        PolicyDocument=json.dumps(lambda_params._default_lambda_policy)
    )
    assert len(iam_client.get_role.call_args_list) == 2
    for arg, kwarg in iam_client.get_role.call_args_list:
        assert kwarg == {'RoleName': 'test-function-lambda-exec-role'}


@pytest.mark.parametrize(
    'http_status_code,expected_exception',
    [
        (500, Exception),
    ],
    ids=['sts_status_code_500']
)
def test_create_lambda_basic_execution_role_sts_failure(
    mock_get_client, http_status_code, expected_exception
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    
    sts_client = mock_get_client.side_effect('sts')
    sts_client.get_caller_identity.side_effect = lambda *args, **kwargs: {
        'ResponseMetadata': {'HTTPStatusCode': http_status_code}
    }
    
    with pytest.raises(expected_exception, match='Log In to user unsuccessful'):
        __create_lambda_basic_execution_role(lambda_params)


def test_create_lambda_basic_execution_role_waiter_error(
    mock_get_client
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    
    iam_client = mock_get_client.side_effect('iam')
    waiter_error = RuntimeError('Waiter failed')
    iam_client.get_waiter.return_value.wait.side_effect = waiter_error
    
    with pytest.raises(RuntimeError, match='Waiter failed'):
        __create_lambda_basic_execution_role(lambda_params)


# _wait_for_role_to_exist tests
@pytest.mark.parametrize('timeout', [1, 2])
@pytest.mark.parametrize('max_attempts', [3, 5])
@pytest.mark.parametrize('failure_count', [0, 2, 3])
def test_wait_for_role_to_exist(
    mock_get_client,
    timeout,
    max_attempts,
    failure_count
):
    lambda_params = LambdaParams()
    lambda_params._role_arn = 'arn:aws:iam::123456789012:role/test-role'
    
    iam_client = mock_get_client.side_effect('iam')
    
    get_role_calls = [
        ClientError(
            {'Error': {'Code': 'NoSuchEntity'}}, 'GetRole'
        )
        for _ in range(failure_count)
    ]
    if failure_count < max_attempts:
        get_role_calls.append({'Role': {'RoleName': 'test-role'}})
    else:
        remaining_failures = max_attempts - failure_count
        get_role_calls.extend([
            ClientError({'Error': {'Code': 'NoSuchEntity'}}, 'GetRole')
            for _ in range(remaining_failures)
        ])
    
    iam_client.get_role.side_effect = get_role_calls
    
    with patch('aws_deploy.functions.time.sleep'):
        if failure_count < max_attempts:
            _wait_for_role_to_exist(lambda_params, timeout, max_attempts)
            assert iam_client.get_role.call_count == failure_count + 1
        else:
            with pytest.raises(Exception, match='The role does not exist!'):
                _wait_for_role_to_exist(lambda_params, timeout, max_attempts)
            assert iam_client.get_role.call_count == max_attempts


# __create_deployment_package tests
def test_create_deployment_package_recursive_all_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, 'subdir'))
        
        file1 = os.path.join(tmpdir, 'file1.py')
        file2 = os.path.join(tmpdir, 'subdir', 'file2.py')
        
        with open(file1, 'w') as f:
            f.write('content1')
        with open(file2, 'w') as f:
            f.write('content2')
        
        lambda_params = LambdaParams()
        lambda_params.code_folder_filepath = tmpdir
        lambda_params.deployment_package_files = None
        
        result = __create_deployment_package(lambda_params)
        
        with zipfile.ZipFile(BytesIO(result), 'r') as zip_file:
            names = sorted(zip_file.namelist())
            assert 'file1.py' in names
            assert 'subdir/file2.py' in names
            assert zip_file.read('file1.py') == b'content1'
            assert zip_file.read('subdir/file2.py') == b'content2'


def test_create_deployment_package_specific_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        file1 = os.path.join(tmpdir, 'file1.py')
        file2 = os.path.join(tmpdir, 'file2.txt')
        file3 = os.path.join(tmpdir, 'file3.py')
        
        with open(file1, 'w') as f:
            f.write('content1')
        with open(file2, 'w') as f:
            f.write('content2')
        with open(file3, 'w') as f:
            f.write('content3')
        
        lambda_params = LambdaParams()
        lambda_params.code_folder_filepath = tmpdir
        lambda_params.deployment_package_files = ['file1.py', 'file2.txt']
        
        result = __create_deployment_package(lambda_params)
        
        with zipfile.ZipFile(BytesIO(result), 'r') as zip_file:
            names = sorted(zip_file.namelist())
            assert 'file1.py' in names
            assert 'file2.txt' in names
            assert 'file3.py' not in names
            assert zip_file.read('file1.py') == b'content1'
            assert zip_file.read('file2.txt') == b'content2'


@pytest.mark.parametrize(
    'file_spec,expected_error',
    [
        ('../outside_file.py', ValueError),
        ('subdir', ValueError),
        ('nonexistent.py', FileNotFoundError),
    ],
    ids=[
        'file_outside_directory',
        'directory_not_allowed',
        'file_not_found',
    ]
)
def test_create_deployment_package_validation_errors(file_spec, expected_error):
    with tempfile.TemporaryDirectory() as tmpdir:
        subdir = os.path.join(tmpdir, 'subdir')
        os.makedirs(subdir)
        
        file1 = os.path.join(tmpdir, 'file1.py')
        with open(file1, 'w') as f:
            f.write('content1')
        
        lambda_params = LambdaParams()
        lambda_params.code_folder_filepath = tmpdir
        lambda_params.deployment_package_files = [file_spec]
        
        with pytest.raises(expected_error):
            __create_deployment_package(lambda_params)


# __create_lambda_function tests
@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_create_lambda_function_success(mock_wait, mock_get_client):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    result = __create_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    lambda_client.create_function.assert_called_once_with(
        FunctionName='test-function',
        Runtime='python3.11',
        Role=role_arn,
        Handler='handler.lambda_handler',
        Code={'ZipFile': zip_data}
    )
    assert result['FunctionName'] == 'test-function'
    assert 'FunctionArn' in result
    assert result['Runtime'] == 'python3.11'
    assert result['Handler'] == 'handler.lambda_handler'
    assert result['Role'] == role_arn
    mock_wait.assert_not_called()


@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_create_lambda_function_invalid_parameter_wait_succeeds(mock_wait, mock_get_client, functions_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function-retry'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params._role_arn = 'arn:aws:iam::123456789012:role/test-role'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    invalid_param_error = ClientError(
        {'Error': {'Code': 'InvalidParameterValueException'}},
        'CreateFunction'
    )
    
    call_count = {'count': 0}
    original_side_effect = lambda_client.create_function.side_effect
    
    def create_function_side_effect(*args, **kwargs):
        call_count['count'] += 1
        if call_count['count'] == 1:
            raise invalid_param_error
        return original_side_effect(*args, **kwargs)
    
    lambda_client.create_function.side_effect = create_function_side_effect
    mock_wait.return_value = None
    
    result = __create_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    assert lambda_client.create_function.call_count == 2
    mock_wait.assert_called_once_with(lambda_params)
    assert result['FunctionName'] == 'test-function-retry'
    assert result['Runtime'] == 'python3.11'
    assert result['Handler'] == 'handler.lambda_handler'
    assert result['Role'] == role_arn


@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_create_lambda_function_invalid_parameter_wait_fails(mock_wait, mock_get_client):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params._role_arn = 'arn:aws:iam::123456789012:role/test-role'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    invalid_param_error = ClientError(
        {'Error': {'Code': 'InvalidParameterValueException'}},
        'CreateFunction'
    )
    lambda_client.create_function.side_effect = invalid_param_error
    mock_wait.side_effect = Exception('The role does not exist!')
    
    with pytest.raises(Exception, match='The role does not exist!'):
        __create_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    lambda_client.create_function.assert_called_once()
    mock_wait.assert_called_once_with(lambda_params)


@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_create_lambda_function_general_exception(mock_wait, mock_get_client):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    connection_error = ConnectionError('Connection failed')
    lambda_client.create_function.side_effect = connection_error
    
    with pytest.raises(ConnectionError, match='Connection failed'):
        __create_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    lambda_client.create_function.assert_called_once()
    mock_wait.assert_not_called()


# __update_lambda_function tests
@patch('aws_deploy.functions.time.sleep')
def test_update_lambda_function_success(mock_sleep, mock_get_client, functions_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'existing-function'
    lambda_params.handler_method = 'handler.lambda_handler'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'updated_zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    functions_fixture['existing-function'] = {
        'Configuration': {
            'FunctionName': 'existing-function',
            'FunctionArn': 'arn:aws:lambda:us-east-2:123456789012:function:existing-function',
            'Runtime': 'python3.11',
            'Role': 'arn:aws:iam::123456789012:role/old-role',
            'Handler': 'old_handler.lambda_handler',
            'CodeSize': 100,
            'LastUpdateStatus': 'Successful',
            'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
        }
    }
    
    result = __update_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    lambda_client.update_function_configuration.assert_called_once_with(
        FunctionName='existing-function',
        Role=role_arn,
        Handler='handler.lambda_handler'
    )
    
    lambda_client.update_function_code.assert_called_once_with(
        FunctionName='existing-function',
        ZipFile=zip_data
    )
    
    assert result['FunctionName'] == 'existing-function'
    assert result['Role'] == role_arn
    assert result['Handler'] == 'handler.lambda_handler'
    assert result['LastUpdateStatus'] == 'Successful'
    mock_sleep.assert_not_called()


@patch('aws_deploy.functions.time.sleep')
def test_update_lambda_function_waits_for_in_progress(mock_sleep, mock_get_client, functions_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'existing-function'
    lambda_params.handler_method = 'handler.lambda_handler'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'updated_zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    functions_fixture['existing-function'] = {
        'Configuration': {
            'FunctionName': 'existing-function',
            'FunctionArn': 'arn:aws:lambda:us-east-2:123456789012:function:existing-function',
            'Runtime': 'python3.11',
            'Role': 'arn:aws:iam::123456789012:role/old-role',
            'Handler': 'old_handler.lambda_handler',
            'CodeSize': 100,
            'LastUpdateStatus': 'Successful',
            'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
        }
    }
    
    call_count = {'count': 0}
    
    def update_function_configuration_side_effect(*args, **kwargs):
        functions_fixture['existing-function']['Configuration']['Role'] = kwargs.get('Role')
        functions_fixture['existing-function']['Configuration']['Handler'] = kwargs.get('Handler')
        functions_fixture['existing-function']['Configuration']['LastUpdateStatus'] = 'InProgress'
        return functions_fixture['existing-function']['Configuration'].copy()
    
    def get_function_side_effect(*args, **kwargs):
        call_count['count'] += 1
        if call_count['count'] <= 2:
            functions_fixture['existing-function']['Configuration']['LastUpdateStatus'] = 'InProgress'
        else:
            functions_fixture['existing-function']['Configuration']['LastUpdateStatus'] = 'Successful'
        return functions_fixture['existing-function']
    
    lambda_client.update_function_configuration.side_effect = update_function_configuration_side_effect
    lambda_client.get_function.side_effect = get_function_side_effect
    
    result = __update_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    assert lambda_client.update_function_configuration.call_count == 1
    assert lambda_client.get_function.call_count >= 3
    assert lambda_client.update_function_code.call_count == 1
    assert result['LastUpdateStatus'] == 'Successful'
    assert mock_sleep.call_count >= 1


@patch('aws_deploy.functions.time.sleep')
def test_update_lambda_function_exception(mock_sleep, mock_get_client, functions_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'existing-function'
    lambda_params.handler_method = 'handler.lambda_handler'
    
    role_arn = 'arn:aws:iam::123456789012:role/test-role'
    zip_data = b'updated_zip_content'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    functions_fixture['existing-function'] = {
        'Configuration': {
            'FunctionName': 'existing-function',
            'FunctionArn': 'arn:aws:lambda:us-east-2:123456789012:function:existing-function',
            'Runtime': 'python3.11',
            'Role': 'arn:aws:iam::123456789012:role/old-role',
            'Handler': 'old_handler.lambda_handler',
            'CodeSize': 100,
            'LastUpdateStatus': 'Successful',
            'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
        }
    }
    
    update_error = ConnectionError('Failed to update function')
    lambda_client.update_function_configuration.side_effect = update_error
    
    with pytest.raises(ConnectionError, match='Failed to update function'):
        __update_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    lambda_client.update_function_configuration.assert_called_once()
    lambda_client.update_function_code.assert_not_called()


# deploy_lambda tests
@patch('aws_deploy.functions.__create_deployment_package')
@patch('aws_deploy.functions.__create_lambda_basic_execution_role')
@patch('aws_deploy.functions.__get_lambda_role_from_name')
@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_deploy_lambda_creates_new_function(
    mock_wait,
    mock_get_role,
    mock_create_role,
    mock_create_package,
    mock_get_client,
    functions_fixture,
    role_fixture,
    aws_account_fixture
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'new-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params.code_folder_filepath = '/tmp/test'
    lambda_params.deployment_package_files = []
    
    zip_data = b'zip_content'
    role_arn = f'arn:aws:iam::{aws_account_fixture}:role/new-function-lambda-exec-role'
    
    mock_create_package.return_value = zip_data
    mock_create_role.return_value = {
        'Role': {
            'Arn': role_arn
        }
    }
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    result = deploy_lambda(lambda_params)
    
    mock_create_role.assert_called_once()
    mock_create_package.assert_called_once_with(lambda_params)
    lambda_client.create_function.assert_called_once()
    assert result['FunctionName'] == 'new-function'
    mock_wait.assert_not_called()


@patch('aws_deploy.functions.__create_deployment_package')
@patch('aws_deploy.functions.__create_lambda_basic_execution_role')
@patch('aws_deploy.functions.__get_lambda_role_from_name')
@patch('aws_deploy.functions._wait_for_role_to_exist')
@patch('aws_deploy.functions.time.sleep')
def test_deploy_lambda_updates_existing_function(
    mock_sleep,
    mock_wait,
    mock_get_role,
    mock_create_role,
    mock_create_package,
    mock_get_client,
    functions_fixture,
    role_fixture,
    aws_account_fixture
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'existing-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params.code_folder_filepath = '/tmp/test'
    lambda_params.deployment_package_files = []
    
    zip_data = b'zip_content'
    role_arn = f'arn:aws:iam::{aws_account_fixture}:role/existing-function-lambda-exec-role'
    
    functions_fixture['existing-function'] = {
        'Configuration': {
            'FunctionName': 'existing-function',
            'FunctionArn': f'arn:aws:lambda:us-east-2:{aws_account_fixture}:function:existing-function',
            'Runtime': 'python3.11',
            'Role': role_arn,
            'Handler': 'handler.lambda_handler',
            'CodeSize': 100,
            'LastUpdateStatus': 'Successful',
            'LastModified': datetime(2025, 1, 1).isoformat() + '+00:00',
        }
    }
    
    mock_create_package.return_value = zip_data
    mock_create_role.return_value = {
        'Role': {
            'Arn': role_arn
        }
    }
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    result = deploy_lambda(lambda_params)
    
    mock_create_role.assert_called_once()
    mock_create_package.assert_called_once_with(lambda_params)
    lambda_client.update_function_configuration.assert_called_once()
    lambda_client.update_function_code.assert_called_once()
    assert result['FunctionName'] == 'existing-function'
    mock_wait.assert_not_called()


@patch('aws_deploy.functions.__create_deployment_package')
@patch('aws_deploy.functions.__get_lambda_role_from_name')
@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_deploy_lambda_with_existing_role(
    mock_wait,
    mock_get_role,
    mock_create_package,
    mock_get_client,
    functions_fixture,
    role_fixture,
    aws_account_fixture
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'new-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params.role_name = 'existing-role'
    lambda_params.code_folder_filepath = '/tmp/test'
    lambda_params.deployment_package_files = []
    
    zip_data = b'zip_content'
    role_arn = f'arn:aws:iam::{aws_account_fixture}:role/existing-role'
    
    role_fixture['existing-role'] = {
        'Role': {
            'Arn': role_arn
        }
    }
    
    mock_create_package.return_value = zip_data
    mock_get_role.return_value = role_fixture['existing-role']
    
    lambda_client = mock_get_client.side_effect('lambda')
    iam_client = mock_get_client.side_effect('iam')
    
    result = deploy_lambda(lambda_params)
    
    mock_get_role.assert_called_once_with('existing-role')
    mock_create_package.assert_called_once_with(lambda_params)
    lambda_client.create_function.assert_called_once()
    assert result['FunctionName'] == 'new-function'
    mock_wait.assert_not_called()


@patch('aws_deploy.functions.__create_deployment_package')
@patch('aws_deploy.functions.__get_lambda_role_from_name')
@patch('aws_deploy.functions._wait_for_role_to_exist')
def test_deploy_lambda_role_not_found(
    mock_wait,
    mock_get_role,
    mock_create_package,
    mock_get_client
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'new-function'
    lambda_params.runtime = 'python3.11'
    lambda_params.handler_method = 'handler.lambda_handler'
    lambda_params.role_name = 'non-existent-role'
    lambda_params.code_folder_filepath = '/tmp/test'
    lambda_params.deployment_package_files = []
    
    mock_get_role.return_value = None
    
    with pytest.raises(ValueError, match='IAM role "non-existent-role" does not exist'):
        deploy_lambda(lambda_params)
    
    mock_get_role.assert_called_once_with('non-existent-role')
    mock_create_package.assert_not_called()


# remove_lambda tests
@patch('aws_deploy.functions.__handle_lambda_remove_role')
def test_remove_lambda_success_without_auto_role(mock_handle_role, mock_get_client, functions_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    role_arn = 'arn:aws:iam::123456789012:role/custom-role'
    functions_fixture['test-function'] = {
        'Configuration': {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-2:123456789012:function:test-function',
            'Role': role_arn,
        }
    }
    
    remove_lambda(lambda_params)
    
    lambda_client.get_function.assert_called_once_with(FunctionName='test-function')
    lambda_client.delete_function.assert_called_once_with(FunctionName='test-function')
    mock_handle_role.assert_not_called()
    assert 'test-function' not in functions_fixture


@patch('aws_deploy.functions.__handle_lambda_remove_role')
def test_remove_lambda_success_with_auto_role(mock_handle_role, mock_get_client, functions_fixture, aws_account_fixture):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    role_arn = f'arn:aws:iam::{aws_account_fixture}:role/test-function-lambda-exec-role'
    functions_fixture['test-function'] = {
        'Configuration': {
            'FunctionName': 'test-function',
            'FunctionArn': f'arn:aws:lambda:us-east-2:{aws_account_fixture}:function:test-function',
            'Role': role_arn,
        }
    }
    
    remove_lambda(lambda_params)
    
    lambda_client.get_function.assert_called_once_with(FunctionName='test-function')
    mock_handle_role.assert_called_once()
    lambda_client.delete_function.assert_called_once_with(FunctionName='test-function')
    assert 'test-function' not in functions_fixture


def test_remove_lambda_function_not_found(mock_get_client):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'non-existent-function'
    
    lambda_client = mock_get_client.side_effect('lambda')
    
    with pytest.raises(ClientError):
        remove_lambda(lambda_params)
    
    lambda_client.get_function.assert_called_once_with(FunctionName='non-existent-function')
    lambda_client.delete_function.assert_not_called()