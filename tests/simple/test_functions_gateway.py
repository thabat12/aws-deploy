import os
import sys


base_path = os.path.abspath(os.path.join(__file__, '..', '..', '..'))
sys.path.append(base_path)

from aws_deploy.functions import deploy_lambda
from aws_deploy.params import LambdaParams

def test_deploy_function():
    params = LambdaParams()
    params.function_name = 'gateway_function'
    params.code_folder_filepath = os.path.join(base_path, 'tests', 'test_data')
    params.handler_method = 'gateway_function.lambda_handler'
    params.deployment_package_files = ['gateway_function.py']

    assert os.path.isdir(params.code_folder_filepath)


    print('deploying function now...')
    deployment_details = deploy_lambda(params)

