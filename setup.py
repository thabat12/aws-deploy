import zipfile
import json
import io
import os

import boto3
import botocore.exceptions

from aws_deploy.functions import deploy_lambda, remove_lambda
from aws_deploy.gateway import deploy_rest_api, remove_rest_api
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
lambda_params.code_folder_filepath = './tests/test_data'
lambda_params.deployment_package_files = ['gateway_function.py']
lambda_params.handler_method = 'gateway_function.lambda_handler'
deploy_lambda(lambda_params)

gateway_params = RestAPIGatewayParams()
gateway_params.api_name = 'test'
gateway_params.add_resource('/a/b/c', 'gateway_example', 'GET')

deploy_rest_api(gateway_params)
remove_rest_api(gateway_params)

remove_lambda(lambda_params)
