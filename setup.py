import zipfile
import json
import io
import os

import boto3
import botocore.exceptions

from aws_deploy.deploy import deploy_lambda, remove_lambda, deploy_cognito_userpool, remove_cognito_user_pool, deploy_api_gateway, remove_api_gateway
from aws_deploy.params import LambdaParams, CognitoParams, RestAPIGatewayParams

from aws_deploy.utils import Constants, logging, session
import aws_deploy.utils as utils

sts_client = session.client('sts')
resp = sts_client.get_caller_identity()

if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
    logging(f'Log in successful', utils.Colors.GREEN)
    logging(f'{Constants.TAB}User: {resp["Arn"].split("/")[1]}', utils.Colors.GREEN)
else:
    logging(f'Bad Request: HTTP status code: {resp["HttpStatusCode"]}', utils.Colors.RED)

lambda_params = LambdaParams()
lambda_params.function_name = 'gateway_example'
lambda_params.code_folder_filepath = './unittests/test_functions'
lambda_params.handler_method='unittests.test_functions.example.lambda_handler'
lambda_params.runtime = 'python3.12'
lambda_params.deployment_package_files = ['example.py']

deploy_lambda(lambda_params)

gateway_params = RestAPIGatewayParams()
gateway_params.api_name = 'test'
gateway_params.add_resource('/a/b/c', 'gateway_example', 'GET')
# gateway_params.implicit_deletion = True

deploy_api_gateway(gateway_params)

remove_lambda(lambda_params)
remove_api_gateway(gateway_params)
