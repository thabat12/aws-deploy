import sys
import os
import json
import unittest

import boto3

# treat aws_deploy as a module
s = os.path.abspath(os.path.join(__file__, '../..'))
sys.path.append(s)

from aws_deploy.deploy import deploy_lambda, remove_lambda
from aws_deploy.params import LambdaParams

# Arrange, Act, Assert model of testing
def sum(a, b):
    return a + b

# must inherit from the unittest.TestCase
class LambdaTests(unittest.TestCase):
    PYTHON38 = 'python3.8'

    # note that tests should start with the "test" keyword
    
    # note that setup is called before every test function!
    def setUp(self, *args):
        # arrange
        self.session = None

    # this is ran after every test function!
    def tearDown(self):
        self.session = None
        self.deployment_details = None

    def test_initialize_lambda(self):
        # act
        lambda_params = LambdaParams()
        lambda_params.function_name = 'unittest_function'
        lambda_params.code_folder_filepath = './test_functions'
        lambda_params.handler_method='functions.testing_this.lambda_handler'
        lambda_params.deployment_package_files = ['testing_this.py']

        expected_params = {
            'FunctionName': lambda_params.function_name,
            'Runtime': LambdaTests.PYTHON38,
            'RoleName': f'{lambda_params.function_name}-lambda-basic-execution-role-auto-created',
        }

        # assigning into deployment details to properly handle teardown
        self.deployment_details = deploy_lambda(lambda_params)

        print(self.deployment_details, type(self.deployment_details))

        self.assertEqual(self.deployment_details['FunctionName'], expected_params['FunctionName'])
        self.assertEqual(self.deployment_details['Runtime'], expected_params['Runtime'])
        self.assertEqual(self.deployment_details['Role'].split('/')[-1].strip(), expected_params['RoleName'])

    def test_remove_lambda(self):
        # reconstruct from deployment_details
        lambda_params = LambdaParams()
        lambda_params.function_name = 'unittest_function'

        remove_lambda(lambda_params)

if __name__ == "__main__":
    unittest.main()