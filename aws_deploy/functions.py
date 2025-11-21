import os
import io
import json
import time
import zipfile
import botocore

import aws_deploy.utils as utils
from aws_deploy.utils import logging, get_client
from aws_deploy.params import LambdaParams

def __get_lambda_function_details(function_name):
    lambda_client = get_client('lambda')
    
    try:
        resp = lambda_client.get_function(FunctionName=function_name)
        return resp
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ResourceNotFoundException':
            return None
        # Re-raise other client errors
        raise e
    except Exception as e:
        # Re-raise unexpected errors
        raise e

def __get_lambda_role_from_name(role_name):
    iam_client = get_client('iam')

    try:
        resp = iam_client.get_role(RoleName=role_name)
        return resp
    except Exception as e:
        # role doesn't exist, so red flag it
        logging(e, utils.Colors.RED)


def __generate_auto_role_name(function_name: str) -> str:
    suffix = '-lambda-exec-role'
    max_base_length = 64 - len(suffix)
    
    if len(function_name) > max_base_length:
        raise ValueError(
            f'Function name "{function_name}" exceeds maximum length of '
            f'{max_base_length} characters for auto-generated IAM role names. '
            f'Total role name must be <= 64 characters.'
        )
    
    return f'{function_name}{suffix}'


# MARKER: I AM HERE RIGHT NOW
def __create_lambda_basic_execution_role(lambda_params: LambdaParams):
    iam_client = get_client('iam')

    role_name = __generate_auto_role_name(lambda_params.function_name)

    try:
        # return this role as-is if it already exists
        resp = iam_client.get_role(RoleName=role_name)
        logging('role already exists!', utils.Colors.CYAN)
        return resp
    except Exception as e:
        logging('role does not exist!', utils.Colors.CYAN)
        pass # do nothing

    sts_client = get_client('sts')
    resp = sts_client.get_caller_identity()
    user_name = None

    if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
        user_name = resp["Arn"]
    else:
        raise Exception('Log In to user unsuccessful')

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(lambda_params._default_trust_policy),
        Tags=[
            {
                'Key': 'Creator',
                'Value': user_name
            }
        ]
    )

    # deploy & retrieve function arn
    iam_client.put_role_policy(
        RoleName=role_name,
        PolicyName='LambdaBasicExecutionPolicy',
        PolicyDocument=json.dumps(lambda_params._default_lambda_policy)
    )


    try:
        resp = iam_client.get_role(RoleName=role_name)
        iam_client.get_waiter('role_exists').wait(RoleName=role_name)
        return resp
    except Exception as e:
        # this is a host-side issue
        raise e

def __handle_lambda_remove_role(lambda_client, lambda_params: LambdaParams):
    logging('Found auto-generated role, deleting role from IAM...')

    iam_client = get_client('iam')

    # just naively delete the role
    try:
        role_name = lambda_params._role_arn.split('/')[-1].strip()

        # first, delete any policies attached to the role
        resp = iam_client.list_attached_role_policies(RoleName=role_name)

        logging('removing the policies first...', utils.Colors.YELLOW)
        logging(resp, utils.Colors.YELLOW)

        for policy in resp['AttachedPolicies']:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])

        # deletion of inline policies
        resp = iam_client.list_role_policies(RoleName=role_name)
        inline_policy_names = resp['PolicyNames']
        
        for policy_name in inline_policy_names:
            iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

        iam_client.delete_role(
            RoleName=lambda_params._role_arn.split('/')[-1].strip()
        )
    except Exception as e:
        logging(e, utils.Colors.RED)

# TODO: clean this code up
def _wait_for_role_to_exist(lambda_params: LambdaParams, timeout=1, max_attempts=15, stall=10):
    iam_client = get_client('iam')
    role_name = lambda_params._role_arn.split(':')[-1].split('/')[-1].strip()
    attempts = 0
    while attempts < max_attempts:
        try:
            resp = iam_client.get_role(RoleName=role_name)
            print(f"The role '{role_name}' exists.")
            logging(resp, utils.Colors.MAGENTA)
            logging('waiting for another 10 seconds')
            time.sleep(stall)
            return
        except:
            attempts += 1
            print(f"Waiting for the role '{role_name}' to exist... Attempt {attempts}/{max_attempts}")
            time.sleep(timeout)
    print(f"The role '{role_name}' does not exist after waiting.")
    raise Exception("The role does not exist!")


def __create_deployment_package(lambda_params: LambdaParams) -> bytes:
    code_folder_filepath = lambda_params.code_folder_filepath
    deployment_package_files = lambda_params.deployment_package_files
    
    try:
        zip_buffer = io.BytesIO()
        code_folder_filepath_normalized = os.path.normpath(code_folder_filepath)
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, False) as zip_file:
            if not deployment_package_files:
                # Include all files recursively
                for root, _, files in os.walk(code_folder_filepath_normalized):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(
                            file_path.replace('\\', '/'),
                            code_folder_filepath_normalized.replace('\\', '/')
                        )
                        zip_file.write(file_path, arcname=rel_path)
            else:
                # Include only specified files as relative paths
                for file_spec in deployment_package_files:
                    file_path = os.path.normpath(os.path.join(code_folder_filepath_normalized, file_spec))
                    
                    if not file_path.startswith(code_folder_filepath_normalized):
                        raise ValueError(
                            f'File path "{file_spec}" is outside the code folder directory'
                        )
                    
                    if os.path.isdir(file_path):
                        raise ValueError(f'Directory not allowed: "{file_spec}". Only files are permitted.')
                    
                    if not os.path.isfile(file_path):
                        raise FileNotFoundError(f'File not found: {file_spec}')
                    
                    rel_path = os.path.relpath(
                        file_path.replace('\\', '/'),
                        code_folder_filepath_normalized.replace('\\', '/')
                    )
                    zip_file.write(file_path, arcname=rel_path)
        
        zip_file_contents = zipfile.ZipFile(zip_buffer)
        logging(f'Zip file contents: {zip_file_contents.namelist()}', utils.Colors.CYAN)
        zip_buffer.seek(0)
        zip_data = zip_buffer.read()
        return zip_data
    except Exception as e:
        logging(f'Error creating deployment package from: {code_folder_filepath}', utils.Colors.RED)
        raise e


def __create_lambda_function(lambda_client, lambda_params: LambdaParams, role_arn: str, zip_data: bytes):
    """
    Helper method to create a new Lambda function.
    
    Args:
        lambda_client: Boto3 Lambda client
        lambda_params: LambdaParams object with function configuration
        role_arn: IAM role ARN for the function
        zip_data: Deployment package as bytes
        
    Returns:
        dict: Response from create_function API call
    """
    function_name = lambda_params.function_name
    runtime = lambda_params.runtime
    handler_method = lambda_params.handler_method
    
    logging('Creating new Lambda function...', utils.Colors.CYAN)
    
    try:
        resp = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Role=role_arn,
            Handler=handler_method,
            Code={'ZipFile': zip_data}
        )
        
        logging(f'Function creation success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}\n' + \
                f'{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)
        return resp
    except botocore.exceptions.ClientError as client_err:
        error_code = client_err.response.get('Error', {}).get('Code', '')
        
        if error_code == 'InvalidParameterValueException':
            # Role might not be ready yet, wait and retry
            logging('Role may not be ready, waiting...', utils.Colors.YELLOW)
            _wait_for_role_to_exist(lambda_params)
            
            resp = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler_method,
                Code={'ZipFile': zip_data}
            )
            
            logging(f'Function creation success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}\n' + \
                    f'{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)
            return resp
        else:
            logging(f'Error creating function: {client_err}', utils.Colors.RED)
            raise client_err
    except Exception as e:
        logging(f'Unexpected error creating function: {e}', utils.Colors.RED)
        raise e


def __update_lambda_function(lambda_client, lambda_params: LambdaParams, role_arn: str, zip_data: bytes):
    """
    Helper method to update an existing Lambda function.
    
    Args:
        lambda_client: Boto3 Lambda client
        lambda_params: LambdaParams object with function configuration
        role_arn: IAM role ARN for the function
        zip_data: Deployment package as bytes
        
    Returns:
        dict: Response from update_function_code API call
    """
    function_name = lambda_params.function_name
    handler_method = lambda_params.handler_method
    
    logging('Function already exists, updating...', utils.Colors.CYAN)
    
    try:
        # Update function configuration first
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Role=role_arn,
            Handler=handler_method
        )
        
        logging('Updating function configuration...', utils.Colors.CYAN)
        
        # Wait for configuration update to complete
        get_fun_state = lambda: lambda_client.get_function(FunctionName=function_name)['Configuration']['LastUpdateStatus']
        while get_fun_state() == 'InProgress':
            time.sleep(0.5)
        
        # Update function code
        resp = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_data
        )
        
        logging(f'Function update success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}\n' + \
                f'{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)
        return resp
    except Exception as e:
        logging(f'Error updating function: {e}', utils.Colors.RED)
        raise e


# returns the arn of the created function
def deploy_lambda(lambda_params: LambdaParams) -> str:
    """
    Deploy a Lambda function. If the function already exists, update it.
    If it's new, create it.
    
    Args:
        lambda_params: LambdaParams object with function configuration
        
    Returns:
        dict: Response from create_function or update_function_code API call
    """
    lambda_client = get_client('lambda')
    function_name = lambda_params.function_name
    
    logging(f'Deploying Lambda function {function_name}...', utils.Colors.CYAN)
    
    # Step 1: Check if function already exists
    existing_function = __get_lambda_function_details(function_name)
    
    # Step 2: Validate and set up IAM role (fail early before zip data step)
    logging(f'{utils.Constants.TAB}Setting Lambda role...', utils.Colors.CYAN)
    role_name = lambda_params.role_name
    
    if role_name:
        logging(f'Using specified role: {role_name}', utils.Colors.CYAN)
        role_response = __get_lambda_role_from_name(role_name)
        if role_response is None:
            raise ValueError(
                f'IAM role "{role_name}" does not exist. '
                f'Please create the role first or remove role_name to use auto-generated role.'
            )
        role_arn = role_response['Role']['Arn']
        logging(f'Role found: {role_arn}', utils.Colors.GREEN)
    else:
        logging('No role specified, using auto-generated role...', utils.Colors.CYAN)
        role_response = __create_lambda_basic_execution_role(lambda_params)
        role_arn = role_response['Role']['Arn']
        logging(f'Auto-generated role: {role_arn}', utils.Colors.GREEN)
    
    lambda_params._role_arn = role_arn
    
    # Step 3: Create deployment package
    logging('Creating deployment package...', utils.Colors.CYAN)
    zip_data = __create_deployment_package(lambda_params)
    
    # Step 4: Deploy function (create or update)
    logging('Uploading Lambda function code...', utils.Colors.CYAN)
    
    if existing_function:
        # Function exists - update it
        resp = __update_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    else:
        # Function is new - create it
        resp = __create_lambda_function(lambda_client, lambda_params, role_arn, zip_data)
    
    return resp

# TODO: maybe make these parameters all the same to remove any confusion? 
def remove_lambda(lambda_params: LambdaParams):
    logging('Removing lambda function...')

    if (not lambda_params):
        logging('Error in deploy.remove_lambda: no argument specified', utils.Colors.RED)

    function_name = lambda_params.function_name

    try:
        # first get the function and the role associated with it to remove
        lambda_client = get_client('lambda')
            

        resp = lambda_client.get_function(FunctionName=function_name)
        lambda_params._function_arn = resp['Configuration']['FunctionArn']
        lambda_params._role_arn = resp['Configuration']['Role']

        # get rid of "junk" role on lambda function if generated by aws-deploy
        role_name_from_arn = resp['Configuration']['Role'].split('/')[-1].strip()
        expected_auto_role_name = __generate_auto_role_name(lambda_params.function_name)
        if role_name_from_arn == expected_auto_role_name:
            __handle_lambda_remove_role(lambda_client, lambda_params)

        # after role is handled, delete the function
        lambda_client.delete_function(
            FunctionName=function_name
        )

        logging(f'Function removal successful\n{utils.Constants.TAB}function identifier: {function_name}', utils.Colors.GREEN)
    except Exception as e:
        logging(e, utils.Colors.RED)
        raise e
