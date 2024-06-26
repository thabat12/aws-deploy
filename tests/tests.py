import sys
import os
import json
import unittest

import boto3

# treat aws_deploy as a module
s = os.path.abspath(os.path.join(__file__, '../..'))
sys.path.append(s)

from aws_deploy.functions import deploy_lambda, remove_lambda
from aws_deploy.dynamodb import deploy_dynamodb, remove_dynamodb
from aws_deploy.params import LambdaParams, DynamoDBParams

# Arrange, Act, Assert model of testing
def sum(a, b):
    return a + b

# must inherit from the unittest.TestCase
class LambdaTests(unittest.TestCase):
    PYTHON38 = 'python3.8'

    # note that tests should start with the "test" keyword
    
    # note that setup is called before every test function!
    def setUp(self):
        # arrange
        self.session = None

    # this is ran after every test function!
    def tearDown(self):
        self.session = None
        self.deployment_details = None

    # @unittest.skip('skipping test initialize lambda')
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

        self.assertEqual(self.deployment_details['FunctionName'], expected_params['FunctionName'])
        self.assertEqual(self.deployment_details['Runtime'], expected_params['Runtime'])
        self.assertEqual(self.deployment_details['Role'].split('/')[-1].strip(), expected_params['RoleName'])

    # @unittest.skip('skip')
    def test_remove_lambda(self):
        # reconstruct from deployment_details
        lambda_params = LambdaParams()
        lambda_params.function_name = 'unittest_function'

        remove_lambda(lambda_params)

class DynamoDBTests(unittest.TestCase):

    def setUp(self):
        self.table_name = None

    def tearDown(self):
        if self.table_name:
            remove_table_params = DynamoDBParams()
            remove_table_params.table_name = self.table_name
            remove_dynamodb(remove_table_params)
            self.table_name = None

    def test_dynamodb_params_validation(self):
        dynamodb_params = DynamoDBParams()
        dynamodb_params.table_name = 'test'
        dynamodb_params.set_partition_key('id', 'S')
        dynamodb_params.set_sort_key('number', 'N')

        self.assertEqual(dynamodb_params.table_name, 'test')
        self.assertEqual(dynamodb_params.attributes, [('id', 'S'), ('number', 'N')])

    def test_create_table_sort_and_partition(self):
        dynamodb_params = DynamoDBParams()
        dynamodb_params.table_name = 'test'
        dynamodb_params.set_partition_key('id', 'S')
        dynamodb_params.set_sort_key('number', 'N')

        deploy_dynamodb(dynamodb_params)
        self.table_name = 'test'

    def test_create_only_primary_key_table(self):
        dynamodb_params = DynamoDBParams()
        dynamodb_params.table_name = 'test1'
        dynamodb_params.set_partition_key('id', 'N')

        deploy_dynamodb(dynamodb_params)
        self.table_name = 'test1'

    def test_create_multiple_lsis_table(self):
        dynamodb_params = DynamoDBParams()
        dynamodb_params.table_name = 'test2'
        dynamodb_params.set_partition_key('id', 'N')
        dynamodb_params.set_sort_key('name', 'S')
        dynamodb_params.add_local_secondary_index('age', 'N')
        dynamodb_params.add_local_secondary_index('height', 'N')

        deploy_dynamodb(dynamodb_params)
        
        self.table_name = 'test2'

if __name__ == "__main__":
    unittest.main()