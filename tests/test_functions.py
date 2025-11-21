"""
Tests for aws_deploy.functions module.

This module contains tests for Lambda function deployment and management.
"""
import json
from unittest.mock import call

import pytest
from datetime import datetime
from botocore.exceptions import ClientError
from enum import Enum

from aws_deploy.functions import (
    __get_lambda_function_details,
    __get_lambda_role_from_name,
    __generate_auto_role_name,
    __create_lambda_basic_execution_role,
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
    mock_get_client, role_fixture, aws_account_fixture
):
    lambda_params = LambdaParams()
    lambda_params.function_name = 'test-function'
    
    iam_client = mock_get_client.side_effect('iam')
    waiter_error = RuntimeError('Waiter failed')
    iam_client.get_waiter.return_value.wait.side_effect = waiter_error
    
    with pytest.raises(RuntimeError, match='Waiter failed'):
        __create_lambda_basic_execution_role(lambda_params)