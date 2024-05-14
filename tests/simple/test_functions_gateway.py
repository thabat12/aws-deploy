import os
import sys


base_path = os.path.abspath(os.path.join(__file__, '..', '..', '..'))
sys.path.append(base_path)

from aws_deploy.functions import deploy_lambda, remove_lambda
from aws_deploy.gateway import deploy_rest_api, remove_rest_api
from aws_deploy.params import LambdaParams, RestAPIGatewayParams

def test_deploy_function():
    params = LambdaParams()
    params.function_name = 'gateway_function'
    params.code_folder_filepath = os.path.join(base_path, 'tests', 'test_data')
    params.handler_method = 'gateway_function.lambda_handler'
    params.deployment_package_files = ['gateway_function.py']

    deploy_lambda(params)

def test_remove_function():
    params = LambdaParams()
    params.function_name = 'gateway_function'

    remove_lambda(params)

def test_deploy_api():
    gateway_params = RestAPIGatewayParams()
    gateway_params.api_name = 'test'
    gateway_params.add_resource('/a/b/c', 'gateway_example', 'GET')
    gateway_params.implicit_deletion = True
    
    deploy_rest_api(gateway_params)

