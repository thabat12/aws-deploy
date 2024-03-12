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
lambda_params.function_name = 'newFunction2'
lambda_params.code_folder_filepath = './functions'
lambda_params.handler_method='functions.testing_this.lambda_handler'
# lambda_params.role_name = 'lambda-basic-execution-role'
lambda_params.deployment_package_files = ['testing_this.py']

deploy_lambda(lambda_params)

# step 1: create the lambda function
# pre_signup_arn = deploy_lambda(function_name='preSignUpLambdaTriggerTradingSimCognitoUserpool',
#             runtime='python3.12', handler_method='functions.pre_signup.lambda_handler',
#             role_arn='arn:aws:iam::758259432754:role/lambda-basic-execution-role',
#             code_folder_filepath='./functions', deployment_package_files='pre_signup.py')

# remove_lambda(function_arn='preSignUpLambdaTriggerTradingSimCognitoUserpool')

# gateway_function = deploy_lambda(
#     function_name='gatewayFunction2', runtime='python3.12', handler_method='functions.testing_this.lambda_handler',
#     role_arn='arn:aws:iam::758259432754:role/lambda-basic-execution-role', code_folder_filepath='./functions',
#     deployment_package_files='testing_this.py'
# )

# cognito_params = CognitoParams()
# deploy_cognito_userpool(cognito_params)
# remove_cognito_user_pool(cognito_params)


# now to add a new api gateway resource -- will support: 
#   1. adding endpoints
#   2. implicit deletion of endpoints
#   3. updating endpoints
# gateway_params = RestAPIGatewayParams()
# gateway_params.api_name = 'TradingSimApi'
# gateway_params.add_resource('/resource1', 'gatewayFunction', 'POST')
# gateway_params.add_resource('/resource1', 'gatewayFunction', 'GET')
# gateway_params.add_resource('/a/b')
# gateway_params.add_resource('/a/n/c', 'gatewayFunction', 'POST')
# gateway_params.add_resource('/a/n/c/d', 'gatewayFunction2', 'GET')
# gateway_params.implicit_deletion = True

