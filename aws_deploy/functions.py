import os
import io
import json
import time
import zipfile

import botocore

import aws_deploy.utils as utils
from aws_deploy.utils import session, logging
from aws_deploy.params import LambdaParams

# helper method for future lambda integrations, just retreiving the function details form its name
def get_lambda_function_from_name(function_name):
    lambda_client = session.client('lambda')
    resp = None
    
    try:
        resp = lambda_client.get_function(FunctionName=function_name)
    except Exception as e:
        raise e
    
    return resp

def __get_lambda_role_from_name(role_name):
    iam_client = session.client('iam')

    try:
        resp = iam_client.get_role(RoleName=role_name)
        return resp
    except Exception as e:
        # role doesn't exist, so red flag it
        logging(e, utils.Colors.RED)

def __create_lambda_basic_execution_role(lambda_client, lambda_params: LambdaParams):
    iam_client = session.client('iam')

    role_name = f'{lambda_params.function_name}-lambda-basic-execution-role-auto-created'

    try:
        # return this role as-is if it already exists
        resp = iam_client.get_role(RoleName=role_name)
        logging('role already exists!', utils.Colors.CYAN)
        return resp
    except Exception as e:
        logging('role does not exist!', utils.Colors.CYAN)
        pass # do nothing
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    lambda_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "*"
            }
        ]
    }

    # ensure role is created with the necessary tag to allow for reference for potential deletion
    # of the iam role

    sts_client = session.client('sts')
    resp = sts_client.get_caller_identity()
    user_name = None

    if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
        user_name = resp["Arn"].split("/")[1]
    else:
        raise Exception('Log In to user unsuccessful')
    
    if not user_name:
        raise Exception('user_name remains undefined')

    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
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
        PolicyDocument=json.dumps(lambda_policy)
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

    iam_client = session.client('iam')

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
    iam_client = session.client('iam')
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

# returns the arn of the created function
def deploy_lambda(lambda_params: LambdaParams) -> str:
    
    lambda_client = session.client('lambda')

    # quick fix: adding all the variables here
    function_name = lambda_params.function_name
    runtime = lambda_params.runtime
    role_arn = lambda_params.role_name
    handler_method = lambda_params.handler_method
    code_folder_filepath = lambda_params.code_folder_filepath
    deployment_package_files = lambda_params.deployment_package_files

    resp = None

    logging(f'Deploying Lambda function {lambda_params.function_name}...', utils.Colors.CYAN)
    logging(f'{utils.Constants.TAB}Setting Lambda role...', utils.Colors.CYAN)

    # change the role name to role arn
    if role_arn:
        logging('there is a role specified already!', utils.Colors.CYAN)
        role_arn = __get_lambda_role_from_name(role_arn)['Role']['Arn']
    else:
        # create a role if necessary
        logging('creating a new role!', utils.Colors.CYAN)
        role_arn = __create_lambda_basic_execution_role(lambda_client, lambda_params)['Role']['Arn']

    logging(role_arn, utils.Colors.GREEN)
    lambda_params._role_arn = role_arn

    # wait for the role to be fully deployed and then move onto function deployment
    logging(f'Lambda role is set: {role_arn}')


    deployment_package_files = set(deployment_package_files) \
        if type(deployment_package_files) == list else set([deployment_package_files])
    
    try:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, False) as zip_file:
            for cur_dir, _subfolders, files in os.walk(code_folder_filepath):
                for file in files:
                    if file in deployment_package_files:

                        rel_path = os.path.relpath(os.path.join(cur_dir, file).replace('\\', '/'), \
                                                    code_folder_filepath.replace('\\', '/'))
                        zip_file.write(os.path.join(cur_dir, file).replace('\\', '/'), arcname=rel_path)


        zip_file_contents = zipfile.ZipFile(zip_buffer)
        logging(f'Zip file contents: {zip_file_contents.namelist()}')
        zip_buffer.seek(0)  
    except:
        logging(f'Error reading in file: {code_folder_filepath}', utils.Colors.RED)

    logging('Uploading Lambda function code...')

    try:
        logging('attempting to create function!!')
        zip_data = zip_buffer.read() # very similar to f.read() from with open(...) as f

        # avoid a future error: ensure that the role is actually ready to be attached

        resp = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Role=role_arn,
            Handler=handler_method,
            Code={
                'ZipFile':zip_data
            }
        )

        logging(f'Function creation success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}\n' + \
                    f'{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)
        
    except botocore.exceptions.ClientError as client_err:
        
        if client_err.response['Error']['Code'] == 'ResourceConflictException':
            logging('function already exists!!')
            logging(f'Updating function code...')

            try:
                logging('attemting to update function!!')
                # call to both methods for essentially a full update
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    Role=role_arn,
                    Handler=handler_method
                )

                logging(f'Updating function configuration...')
                getFunState = lambda: lambda_client.get_function(FunctionName=function_name)['Configuration']['LastUpdateStatus']
                
                # wait for full function settings update
                while resp := getFunState() == 'InProgress':
                    time.sleep(0.5)
                
                zip_buffer.seek(0)
                zip_data = zip_buffer.read()
                resp = lambda_client.update_function_code(
                    FunctionName=function_name,
                    ZipFile=zip_data
                )

                logging(f'Function code success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}' + \
                            f'\n{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)
                
            except Exception as e:
                logging('Update function failed:' + str(e), utils.Colors.RED)
        elif client_err.response['Error']['Code'] == 'InvalidParameterValueException':
            logging(client_err.response, utils.Colors.RED)
            _wait_for_role_to_exist(lambda_params)

            resp = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler_method,
                Code={
                    'ZipFile':zip_data
                }
            )

            logging(f'Function creation success!\n{utils.Constants.TAB}function name: {resp["FunctionName"]}\n' + \
                    f'{utils.Constants.TAB}arn: {resp["FunctionArn"]}', utils.Colors.GREEN)

        else:
            logging(f'Unhandled client error: {client_err}', utils.Colors.RED)
    except Exception as e:
        logging(e, utils.Colors.RED)

    return resp

# TODO: maybe make these parameters all the same to remove any confusion? 
def remove_lambda(lambda_params: LambdaParams):
    logging('Removing lambda function...')

    if (not lambda_params):
        logging('Error in deploy.remove_lambda: no argument specified', utils.Colors.RED)

    function_name = lambda_params.function_name

    try:
        # first get the function and the role associated with it to remove
        lambda_client = session.client('lambda')
            

        resp = lambda_client.get_function(FunctionName=function_name)
        lambda_params._function_arn = resp['Configuration']['FunctionArn']
        lambda_params._role_arn = resp['Configuration']['Role']

        # get rid of "junk" role on lambda function if generated by aws-deploy
        if resp['Configuration']['Role'].split('/')[-1].strip() == \
            f'{lambda_params.function_name}-lambda-basic-execution-role-auto-created':
            __handle_lambda_remove_role(lambda_client, lambda_params)

        # after role is handled, delete the function
        lambda_client.delete_function(
            FunctionName=function_name
        )

        logging(f'Function removal successful\n{utils.Constants.TAB}function identifier: {function_name}', utils.Colors.GREEN)
    except Exception as e:
        logging(e, utils.Colors.RED)
        raise e
