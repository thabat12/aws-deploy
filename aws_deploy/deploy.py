import os 
import io
import time
import json
from typing import List
import zipfile

import boto3
import botocore.exceptions

import aws_deploy.utils as utils
from aws_deploy.utils import session, logging

from aws_deploy.params import LambdaParams, CognitoParams, RestAPIGatewayParams, DynamoDBParams

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


def __get_lambda_layer_from_name(lambda_client, lambda_params: LambdaParams, layer_name: str):
    resp = lambda_client.list_layers()
    for layer in resp['Layers']:
        if layer['LayerName'] == layer_name:
            return layer
    return None

# helper method for future lambda integrations, just retreiving the function details form its name
def __get_lambda_function_from_name(function_name):
    lambda_client = session.client('lambda')
    resp = None
    
    try:
        resp = lambda_client.get_function(FunctionName=function_name)
    except Exception as e:
        raise e
    
    return resp

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
    lambda_layer_lib_filepath = lambda_params.lambda_layer_lib_filepath

    resp = None

    # change the role name to role arn
    if role_arn:
        logging('there is a role specified already!', utils.Colors.CYAN)
        role_arn = __get_lambda_role_from_name(role_arn)['Role']['Arn']
    else:
        # create a role if necessary
        logging('creating a new role!', utils.Colors.CYAN)
        role_arn = __create_lambda_basic_execution_role(lambda_client, lambda_params)['Role']['Arn']

    logging(role_arn, utils.Colors.GREEN)

    # wait for the role to be fully deployed and then move onto function deployment
    

    logging(f'Derived lambda role arn: {role_arn}')


    deployment_package_files = set(deployment_package_files) \
        if type(deployment_package_files) == list else set([deployment_package_files])
    
    # read file from the folder filepath
    print('code folder filepath', code_folder_filepath)
    try:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED, False) as zip_file:
            for cur_dir, _subfolders, files in os.walk(code_folder_filepath):
                for file in files:
                    if file in deployment_package_files:
                        zip_file.write(os.path.join(cur_dir, file).replace('\\', '/'))


        zip_file_contents = zipfile.ZipFile(zip_buffer)
        logging(f'Zip file contents: {zip_file_contents.namelist()}')
        zip_buffer.seek(0)  

    except:
        logging(f'Error reading in file: {code_folder_filepath}')

    logging('Deploying lambda function...')

    try:
        logging('attempting to create function!!')
        zip_data = zip_buffer.read() # very similar to f.read() from with open(...) as f

        # avoid a future error: ensure that the role is actually ready to be attached

        try:
            resp = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=runtime,
                Role=role_arn,
                Handler=handler_method,
                Code={
                    'ZipFile':zip_data
                }
            )

        except botocore.exceptions.ClientError as e:
            logging('error reached', utils.Colors.BLUE)
            logging('attempting to deploy one more time...', utils.Colors.RED)
            time.sleep(10)

            # will fail if cannot deploy
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
        else:
            logging(f'Client error: {client_err}', utils.Colors.RED)
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

def __attach_lambda_resource_policies_cognito_idp(cognito_client, cognito_params):
    logging('Attaching lambda resource policies to cognito-idp...')
    
    lambda_client = session.client('lambda')

    # first get the resource/ principal arn
    resp = cognito_client.describe_user_pool(UserPoolId=cognito_params.pool_id)
    cognito_params.userpool_arn = resp['UserPool']['Arn']

    # !! principal & source arn set here
    cognito_params._lambda_resource_policy['SourceArn'] = cognito_params.userpool_arn

    # iterate through all the lambda function names and associate new values to resource pol.
    all_functions = CognitoParams.get_boto3_dict(cognito_params.LambdaConfig, False)

    for _, function_arn in all_functions.items():
        function_name = function_arn.split(':')[-1]
        statement_id = f'cognito-idp-{function_name}'
        
        # !! function name, statement id, 
        cognito_params._lambda_resource_policy['FunctionName'] = function_name
        cognito_params._lambda_resource_policy['StatementId'] = statement_id

        try:
            lambda_client.add_permission(
                **cognito_params._lambda_resource_policy
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceConflictException':
                # here i will remove the permission and then add it again
                lambda_client.remove_permission(
                    FunctionName=function_name,
                    StatementId=statement_id,
                )

                lambda_client.add_permission(
                    **cognito_params._lambda_resource_policy
                )

            else:
                logging(e, utils.Colors.RED)

def __find_user_pool_from_name(cognito_client, cognito_params):
    next_token = ''
    done = False
    cur_user_pool = None

    while not done:
        # check to see if the user pool already exists
        resp = cognito_client.list_user_pools(
            MaxResults=20 # if less items exist than specified, then will return truncated output
        ) if not next_token else cognito_client.list_user_pools(
            NextToken=next_token,
            MaxResults= 20
        )

        user_pools = iter(resp['UserPools'])

        while ((cur_user_pool := next(user_pools, None)) is not None):
            if cur_user_pool['Name'] == cognito_params.pool_name:
                done = True
                break

        try:
            next_token = resp['NextToken']
        except Exception as e:
            logging('Searched every userpool', utils.Colors.RED)
            done = True

    if cur_user_pool:
        cognito_params.pool_id = cur_user_pool['Id'] # set upid for future calls

    return cur_user_pool

def __find_user_pool_client_from_name(cognito_client, cognito_params):
    next_token = ''
    done = False
    cur_user_pool_client = None 

    while not done:
        resp = cognito_client.list_user_pool_clients(
            UserPoolId=cognito_params.pool_id,
            MaxResults=5
        ) if not next_token else cognito_client.list_user_pool_clients(
            UserPoolId=cognito_params.pool_id,
            MaxResults=5,
            NextToken=next_token
        )

        user_pool_clients = iter(resp['UserPoolClients'])

        while (cur_user_pool_client := next(user_pool_clients, None)) is not None:
            if cur_user_pool_client['ClientName'] == cognito_params.ClientParams.client_name:
                done = True # set the cur_user_pool_client
                break

        try:
            next_token = resp['NextToken']
        except Exception as e:
            logging('Searched every userpool client', utils.Colors.RED)
            done = True

    if cur_user_pool_client:
        cognito_params.ClientParams.client_id = cur_user_pool_client['ClientId']
    
    return cur_user_pool_client

def __update_user_pool_identity_provider(cognito_client, cognito_params):
    logging(f'{utils.Constants.TAB}Updating user pool idp...')

    resp = cognito_client.update_identity_provider(
        UserPoolId=cognito_params.pool_id,
        ProviderName=cognito_params.IdentityProviderParams.provider_name,
        ProviderDetails=CognitoParams.get_boto3_dict(cognito_params.IdentityProviderParams.ProviderDetails, False),
        AttributeMapping=CognitoParams.get_boto3_dict(cognito_params.IdentityProviderParams.AttributeMapping, False)
    )

    logging(resp, utils.Colors.GREEN)

def __create_new_user_pool_identity_provider(cognito_client, cognito_params):
    logging(f'{utils.Constants.TAB}Creating a new user pool idP...')

    resp = cognito_client.create_identity_provider(
        UserPoolId=cognito_params.pool_id,
        ProviderName=cognito_params.IdentityProviderParams.provider_name,
        ProviderType=cognito_params.IdentityProviderParams.provider_type,
        ProviderDetails=CognitoParams.get_boto3_dict(cognito_params.IdentityProviderParams.ProviderDetails, False),
        AttributeMapping=CognitoParams.get_boto3_dict(cognito_params.IdentityProviderParams.AttributeMapping, False)
    )

    logging(resp, utils.Colors.GREEN)

def __create_new_user_pool_domain(cognito_client, cognito_params):
    logging(f'{utils.Constants.TAB}Creating new user pool domain...')

    resp = cognito_client.create_user_pool_domain(
        Domain=cognito_params.DomainParams.domain,
        UserPoolId=cognito_params.pool_id
    )

    logging(resp, utils.Colors.GREEN)

    domain = lambda name, region, etc='': f'https://{name}.auth.{region}.amazoncognito.com{etc}'
    js_org = domain(cognito_params.DomainParams.domain, session.region_name)
    rd_org = domain(cognito_params.DomainParams.domain, session.region_name, '/oauth2/idpresponse')
    db_tb = utils.Constants.TAB * 2

    logging(f'{utils.Constants.TAB}Created domain\n{db_tb}Authorized JS origin: {js_org}' + \
            f'\n{db_tb}Authorized redirect URI: {rd_org}', utils.Colors.MAGENTA)

def __update_user_pool_domain(cognito_client, cognito_params):
    logging(f'{utils.Constants.TAB}Updating user pool domain...')

    # check to see if the domain specified varies from the domain already existing on cognito
    resp = cognito_client.describe_user_pool(
        UserPoolId=cognito_params.pool_id
    )

    current_cog_dom = None
    try:
        current_cog_dom = resp['UserPool']['Domain']
    except KeyError:
        # if there is no domain currently existing, the domain key will not be present
        __create_new_user_pool_domain(cognito_client, cognito_params)
        return # preemptive return, this is bad but it works

    # this is guaranteed to be a non-null value
    param_cog_dom = cognito_params.DomainParams.domain

    if current_cog_dom != param_cog_dom:
        if not current_cog_dom:
            __create_new_user_pool_domain(cognito_client, cognito_params)
        else:
            cognito_client.delete_user_pool_domain(
                Domain=current_cog_dom,
                UserPoolId=cognito_params.pool_id
            )
            logging(f'Deleted domain {current_cog_dom}')
            __create_new_user_pool_domain(cognito_client, cognito_params)
            
def __update_user_pool_client(cognito_client, cognito_params):
   
   logging(f'{utils.Constants.TAB}Updating userpool client {cognito_params.ClientParams.client_name}...')
   resp = cognito_client.update_user_pool_client(
        UserPoolId=cognito_params.pool_id,
        ClientId=cognito_params.ClientParams.client_id, # this is unique to update fun
        ClientName=cognito_params.ClientParams.client_name,
        ExplicitAuthFlows=cognito_params.ClientParams.explicit_auth_flows,
        SupportedIdentityProviders=cognito_params.ClientParams.supported_identity_providers,
        CallbackURLs=cognito_params.ClientParams.callback_urls,
        AllowedOAuthFlows=cognito_params.ClientParams.allowed_oauth_flows,
        AllowedOAuthScopes=cognito_params.ClientParams.allowed_oauth_scopes,
        AllowedOAuthFlowsUserPoolClient=cognito_params.ClientParams.allowed_oauth_flows_userpool_client
   )

   logging(resp, utils.Colors.GREEN)

def __create_new_user_pool_client(cognito_client, cognito_params):
    logging(f'{utils.Constants.TAB}Creating new userpool client {cognito_params.ClientParams.client_name}...')

    resp = cognito_client.create_user_pool_client(
        UserPoolId=cognito_params.pool_id,
        ClientName=cognito_params.ClientParams.client_name,
        ExplicitAuthFlows=cognito_params.ClientParams.explicit_auth_flows,
        SupportedIdentityProviders=cognito_params.ClientParams.supported_identity_providers,
        CallbackURLs=cognito_params.ClientParams.callback_urls,
        AllowedOAuthFlows=cognito_params.ClientParams.allowed_oauth_flows,
        AllowedOAuthScopes=cognito_params.ClientParams.allowed_oauth_scopes,
        AllowedOAuthFlowsUserPoolClient=cognito_params.ClientParams.allowed_oauth_flows_userpool_client
    )

    logging(resp, utils.Colors.GREEN)

def __update_user_pool(cognito_client, cognito_params):
    logging(f'Updating userpool {cognito_params.pool_name}...')

    # doing a marginal change for lambda config where if every field is none, then just pass in an
    # empty dictionary
    lambda_config_dict = CognitoParams.get_boto3_dict(cognito_params.LambdaConfig)
    found_non_null = False
    for val in lambda_config_dict.values():
        if val != None:
            found_non_null = True
            break

    lambda_config_dict = {} if not found_non_null else lambda_config_dict

    # first, simply call the update_user_pool boto3 function
    resp = cognito_client.update_user_pool(
        UserPoolId=cognito_params.pool_id, # unique to update
        Policies={
            'PasswordPolicy': CognitoParams.get_boto3_dict(cognito_params.Policies.PasswordPolicy)
        },
        LambdaConfig=lambda_config_dict
    )

    # now, attach the custom policies to every single lambda function
    __attach_lambda_resource_policies_cognito_idp(cognito_client, cognito_params)

    # logging(f'Userpool {cognito_params.pool_name} updated', utils.Colors.GREEN)
    logging(resp, utils.Colors.GREEN)

    if cognito_params.IdentityProviderParams.provider_name:
        try:
            # checking to see if idp already exists
            resp = cognito_client.describe_identity_provider(
                UserPoolId=cognito_params.pool_id,
                ProviderName=cognito_params.IdentityProviderParams.provider_name
            )

            __update_user_pool_identity_provider(cognito_client, cognito_params)
        except:
            # provider does not exist
            __create_new_user_pool_identity_provider(cognito_client, cognito_params)

    # handle domain updates if necessary
    if cognito_params.DomainParams.domain:
        __update_user_pool_domain(cognito_client, cognito_params)

    # next, check if pool client create/ update is necessary
    if cognito_params.ClientParams.client_name:
        user_pool_client = __find_user_pool_client_from_name(cognito_client, cognito_params)

        if user_pool_client:
            __update_user_pool_client(cognito_client, cognito_params)
        else:
            __create_new_user_pool_client(cognito_client, cognito_params)

def __create_new_user_pool(cognito_client, cognito_params):
    logging(f'Creating userpool {cognito_params.pool_name}...') 

    lambda_config_dict = CognitoParams.get_boto3_dict(cognito_params.LambdaConfig)
    found_non_null = False
    for val in lambda_config_dict.values():
        if val != None:
            found_non_null = True
            break

    lambda_config_dict = {} if not found_non_null else lambda_config_dict

    resp = cognito_client.create_user_pool(
        PoolName=cognito_params.pool_name,
        UsernameAttributes=cognito_params.username_attributes,
        Policies={
            'PasswordPolicy': CognitoParams.get_boto3_dict(cognito_params.Policies.PasswordPolicy)
        },
        LambdaConfig=lambda_config_dict
    )

    # important: since i already searched and realized no userpool exists, i need to 
    # manually set the user pool id in this location, right before attaching lambda
    # policies (since they depend on the user pool id)
    cognito_params.pool_id = resp['UserPool']['Id']

    # must ensure all lambda functions have the permissions set properly
    __attach_lambda_resource_policies_cognito_idp(cognito_client, cognito_params)
    
    logging(resp, utils.Colors.GREEN)

    if cognito_params.IdentityProviderParams.provider_name:
        __create_new_user_pool_identity_provider(cognito_client, cognito_params)

    if cognito_params.DomainParams.domain:
        __create_new_user_pool_domain(cognito_client, cognito_params)

    # create a new user pool client if necessary
    if cognito_params.ClientParams.client_name:
        __create_new_user_pool_client(cognito_client, cognito_params)

def deploy_cognito_userpool(cognito_params: CognitoParams):

    cognito_client = session.client('cognito-idp')
    logging('Deploying Cognito user pool...')

    # after specifying attributes on the actual instance of the object, use the static properties of the class
    # to convert these into actual dictionary values for use in boto3 api calls

    # call to function will set the userpool id on cognito_params
    cur_user_pool = __find_user_pool_from_name(cognito_client, cognito_params)

    if (cur_user_pool):
        __update_user_pool(cognito_client, cognito_params)
    else:
        __create_new_user_pool(cognito_client, cognito_params)

    # no matter where I am, I need to get the user pool arn
    if not cognito_params.userpool_arn:
        resp = cognito_client.describe_user_pool(UserPoolId=cognito_params.pool_id)
        cognito_params.userpool_arn = resp['UserPool']['Arn']

    # i need the arn of the function to do further api calls
    return cognito_params.userpool_arn

def remove_cognito_user_pool(cognito_params):
    cognito_client = session.client('cognito-idp')
    logging('Removing Cognito user pool...')

    cur_user_pool = __find_user_pool_from_name(cognito_client, cognito_params)

    if cur_user_pool:
        # for removing the current user pool, first you need to delete the associated
        # domain config if that exists, so I need to describe this userpool first
        resp = cognito_client.describe_user_pool(
            UserPoolId=cognito_params.pool_id
        )

        if 'Domain' in resp['UserPool'].keys():
            domain_to_del = resp['UserPool']['Domain']

            logging(f'{utils.Constants.TAB}Domain {domain_to_del} detected in user pool')
            
            resp = cognito_client.delete_user_pool_domain(
                Domain=domain_to_del,
                UserPoolId=cognito_params.pool_id
            )

            def getDomainState(): 
                try:
                    return cognito_client.describe_user_pool_domain(
                        Domain=domain_to_del
                    )['DomainDescription']['Status']
                except Exception as e:
                    return 'GONE!'
                
            # wait for full function settings update
            while (resp := getDomainState()) in ['DELETING', 'ACTIVE']:
                time.sleep(0.5)

            if resp != 'GONE!':
                logging('internal issue with getdomainstate function', utils.Colors.RED)
                raise Exception
            else:
                # should be safe to delete the user pool now
                cognito_client.delete_user_pool(
                    UserPoolId=cognito_params.pool_id
                )
        else:
            logging(resp, utils.Colors.RED)
    else:
        logging(f'Specified user pool {cognito_params.pool_name} does not exist')

class ResourceTreeNode:
    def _insert_node_helper(cur_node, segments, cur_segment_ind, parent_id, my_id):
        if cur_segment_ind >= len(segments):
            return None
        
        if not cur_node:
            cur_my_id = my_id if cur_segment_ind == len(segments) - 1 else None
            cur_node = ResourceTreeNode(parent_id, cur_my_id, segments[cur_segment_ind])

            # not at the leaf, peek ahead and assign
            if cur_segment_ind < len(segments) - 1: 
                cur_node.children[segments[cur_segment_ind + 1]] = \
                    ResourceTreeNode._insert_node_helper(
                        None,
                        segments,
                        cur_segment_ind + 1,
                        cur_my_id,
                        my_id
                    )
            # at the leaf, no need to further recurse
            else:
                return cur_node
        # node is made
        else:
            # parentid reassigned no matter what
            cur_node.parentResourceId = parent_id

            # at leaf node, update my_id
            if cur_segment_ind == len(segments) - 1:
                cur_node.myResourceId = my_id

                # however, there is an additional case of having children node that need to also 
                # reflect this update, so update all children values too if they exist
                for child in cur_node.children.values():
                    child.parentResourceId = my_id

            # not at leaf, peek ahead and assign
            else:
                # node already exists, so pass in existing ref
                if segments[cur_segment_ind + 1] in cur_node.children:
                    cur_node.children[segments[cur_segment_ind + 1]] = \
                        ResourceTreeNode._insert_node_helper(
                            cur_node.children[segments[cur_segment_ind + 1]],
                            segments,
                            cur_segment_ind + 1,
                            cur_node.myResourceId,
                            my_id
                        )
                # node does not exist, pass in None to implicitly create
                else:
                    cur_node.children[segments[cur_segment_ind + 1]] = \
                        ResourceTreeNode._insert_node_helper(
                            None,
                            segments,
                            cur_segment_ind + 1,
                            cur_node.myResourceId,
                            my_id
                        )
        return cur_node

    def insert_path(root, fullPath, resourceId):
        path_segments = fullPath.split('/')
        # automatically assumes that the first segment is just the root
        ResourceTreeNode._insert_node_helper(root, path_segments, 0, None, resourceId)

    def get_path(root, fullPath):
        if fullPath == '/': return root # quick edge case fix

        path_segments = fullPath.split('/')
        assert path_segments[0] == '', 'path must start with /'
        cur_node = root
        for segment in path_segments[1:]:
            if segment in cur_node.children:
                cur_node = cur_node.children[segment]
            else:
                return None
        return cur_node
    
    def get_topological_order(node, cur_path, cur_solution):
        cur_path += '/' + node.pathPart if node.pathPart else ''

        for child in node.children.values():
            ResourceTreeNode.get_topological_order(child, cur_path, cur_solution)

        cur_solution.append(cur_path)

        if node.pathPart == '':
            cur_solution = cur_solution.reverse()

    # returns the node with corresponding data on api gateway_params object
    def _construct_api_resource_tree(gateway_params: RestAPIGatewayParams):
        # get rid of any dependency errors with root resource id not being set or no resource data available
        if not gateway_params._root_resource_id:
            raise Exception("There is no root resource id specified in gateway_params!")
        
        if gateway_params._api_resource_data is None:
            raise Exception("API resource data is None, cannot construct resource tree!")
        
        root = ResourceTreeNode(None, gateway_params._root_resource_id, '')
        
        for resource in gateway_params._api_resource_data:
            resource_id = resource['id']
            resource_path = resource['path']
            ResourceTreeNode.insert_path(root, resource_path, resource_id)

        return root

    def __str__(self) -> str:
        return f'node ({self.pathPart}) :: my id {self.myResourceId} :: parent rid {self.parentResourceId}'
    
    def __repr__(self) -> str:
        return self.__str__()

    def __init__(self, parentResourceId, myResourceId, pathPart):
        self.parentResourceId, self.myResourceId, self.pathPart = parentResourceId, myResourceId, pathPart
        self.children = {
            # for now this is empty
        }

def __get_api_from_name(gateway_client, gateway_params):
    # retrieve the existing apis and scan through to get the current api being developed on
    cur_api = None
    existing_apis = gateway_client.get_rest_apis()

    for api in existing_apis['items']:
        if api['name'] == gateway_params.api_name:
            cur_api = api

    # i will set the root resource id and the api id if the api exists
    if cur_api:
        gateway_params._rest_api_id = cur_api['id']
        gateway_params._root_resource_id = cur_api['rootResourceId']

    return cur_api

def __update_api_gateway(gateway_client, gateway_params):
    logging(f'Updating API with name {gateway_params.api_name}...')

def __create_api_gateway(gateway_client, gateway_params):
    logging(f'Creating API with name {gateway_params.api_name}...')


    resp = gateway_client.create_rest_api(
        name=gateway_params.api_name,
    )

    # setting the important parameters for the gateway_params object
    gateway_params._rest_api_id = resp['id']
    gateway_params._root_resource_id = resp['rootResourceId']

    logging(resp, utils.Colors.GREEN)

# function for handling implicit deletions
def __delete_api_gateway_resources(gateway_client, gateway_params, resources_to_delete):
    logging('Implicit deleting api resources...')
    # adding resources to path to get api resource id data and parent id data
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # optimization: delete only the top-most root of each set of resources
    def get_resource_deletion_roots(root, resources_to_delete):
        visited_nodes = set()
        filtered_resources_to_delete = []

        def find_and_flag(node: ResourceTreeNode, path: List[str], cur_path_index: int):
            if cur_path_index == len(path):
                visited_nodes.add(node)
                return
            elif node in visited_nodes:
                return 
            else:
                path_part = path[cur_path_index]
                find_and_flag(node.children[path_part], path, cur_path_index + 1)

        for resource_to_delete in resources_to_delete:
            resource_path_parts = resource_to_delete.split('/')[1:]
            size_before = len(visited_nodes)
            find_and_flag(root, resource_path_parts, 0)
            size_after = len(visited_nodes)

            if size_after > size_before: filtered_resources_to_delete.append(resource_to_delete)

        return filtered_resources_to_delete
    
    filtered_resources_to_delete = get_resource_deletion_roots(root, resources_to_delete)

    # delete only the root level of resources to delete...
    for resource_to_delete in filtered_resources_to_delete:
        logging(f'Deleting resource: {resource_to_delete} under API {gateway_params.api_name}...')

        resource_id = ResourceTreeNode.get_path(root, resource_to_delete).myResourceId
        
        try:
            gateway_client.delete_resource(restApiId=gateway_params._rest_api_id, resourceId=resource_id)
        except Exception as e:
            logging(e, utils.Colors.RED)

    # repopulate the api resource data
    gateway_params._api_resource_data = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )['items']

def __add_api_gateway_resources(gateway_client, gateway_params, resources_to_add):
    logging(f'Adding api resources...')

    # i want this function to be guaranteed to work no matter what
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # all resources to add are guaranteed to not already exist on api gateway, but they should be valid
    # in terms of adding them onto the resource tree and ensuring that a parent resourceId exists
    new_resources = []

    # first, add everything to the tree to retrieve parent data
    for resource_to_add in resources_to_add:
        # a small check to ensure that the path is valid (starting off from the empty '' node)
        is_valid = resource_to_add.split('/')[0] == ''

        if not is_valid: raise Exception("the path provided is not valid!")

        # implicitly add all parent resource information to the tree
        ResourceTreeNode.insert_path(root, resource_to_add, None)
        new_resources.append(ResourceTreeNode.get_path(root, resource_to_add))
    
    # the step above only adds parent data to the nodes directly below the currently existing paths
    # now when deploying to api gateway, i need to keep track of resource ids and propagate these
    # resource + parent id pairs down the tree the more sequentially I add these resource pahts

    logging(new_resources, utils.Colors.BLUE)

    topologically_sorted_resources = []
    ResourceTreeNode.get_topological_order(root, '', topologically_sorted_resources)

    # now that i have the topologically sorted resources, i need to add them one by one
    for resource in topologically_sorted_resources:
        # if the resource already exists, no need to attempt creating a new resource
        if ResourceTreeNode.get_path(root, resource).myResourceId != None:
            continue

        try:
            resp = gateway_client.create_resource(
                restApiId=gateway_params._rest_api_id,
                parentId=ResourceTreeNode.get_path(root, resource).parentResourceId,
                pathPart=resource.split('/')[-1]
            )

            # overwriting the id to be reflected in the tree, will also update all children of the 
            # currently selected node (this is abstracted away in the insert_path method)
            ResourceTreeNode.insert_path(root, resource, resp['id'])

            logging(f'Created resource {resource} under API {gateway_params.api_name}')
        except Exception as e:
            logging(e, utils.Colors.RED)

    # repopulate the api resource data
    gateway_params._api_resource_data = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )['items']


def __handle_api_gateway_resource_updates(gateway_client, gateway_params):

    # now i need to retrieve all the resources associated with the rest api
    resp = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )

    # setting a private variable for furture references in functions
    gateway_params._api_resource_data = resp['items']

    # here, i will handle implicit deletions, additions, and updates for any api resources
    all_resource_paths = set([resource['path'] for resource in gateway_params._api_resource_data])
    gateway_param_resource_paths = set([resource_param.path for resource_param in gateway_params.resources])

    ###### DELETE RESOURCE LOGIC
    # tricky: deleted resources are all resource paths that are not the paths specified in gateway_params.resources
    #           AND not subpaths of any of these resources either. the best way to ensure this behavior is to
    #           work on the resource tree...
    specified_resources_root = ResourceTreeNode(None, gateway_params._root_resource_id, '')

    # insert every path into specified resource root tree
    for resource in gateway_params.resources:
        ResourceTreeNode.insert_path(specified_resources_root, resource.path, None)
        assert ResourceTreeNode.get_path(specified_resources_root, resource.path) != None

    deleted_resources = set()

    # now for every path on "all_resource_paths", ensure that the path does not exist on specified resource root
    # paths, and if so, it is safe to delete
    for all_resource_cur_resource in all_resource_paths:
        if ResourceTreeNode.get_path(specified_resources_root, all_resource_cur_resource) == None:
            deleted_resources.add(all_resource_cur_resource)

    # adding resources is simple, since implicit paths are a part of addition
    added_resources = gateway_param_resource_paths - all_resource_paths

    # TODO: idk what to do about this
    updated_resources = gateway_param_resource_paths & all_resource_paths

    # now will only delete resources if there is an implicit deletion specification set
    if gateway_params.implicit_deletion and deleted_resources:
        __delete_api_gateway_resources(gateway_client, gateway_params, deleted_resources)

    if added_resources:
        __add_api_gateway_resources(gateway_client, gateway_params, added_resources)

    # i don't understand the update function very well but for the purposes of this api that will be
    # ignored
    if updated_resources: pass # TODO: figure out what to do with this guy later

def __implicit_delete_integration_methods(gateway_client, gateway_params):
    logging('Implicit deleting integration methods...')

    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # all integration methods that have a lambda function configured
    integration_methods = [i for i in gateway_params.resources if i.function_name is not None]

    # if using implicit deletion mode, i must consider all other paths in gateway and delete the 
    # associated integration methods
    all_resource_paths = [r['path'] for r in gateway_params._api_resource_data]

    integration_dict = {
        'restApiId': gateway_params._rest_api_id,
        'resourceId': None,
        'httpMethod': None
    }

    integration_method_dict = {}

    # keep track of all the integration methods that have an integration specified on the gateway
    # params object. 
    for integration_method in integration_methods:
        if integration_method.path not in integration_method_dict:
            integration_method_dict[integration_method.path] = []

        integration_method_dict[integration_method.path].append(integration_method.method)

    for resource_path in all_resource_paths:
        integration_dict['resourceId'] = ResourceTreeNode.get_path(root, resource_path).myResourceId
        
        # get current existing integrations
        resp = gateway_client.get_resource(
            restApiId=integration_dict['restApiId'],
            resourceId=integration_dict['resourceId']
        )

        # enter the integration method deletion job if there are methods specified
        if 'resourceMethods' in resp:
            # delete everything
            existing_methods = resp['resourceMethods'].keys()
            to_delete: List = None
            # the path is configured as an integration path for gateway_params, so only delete the 
            # methods that the client did not specify
            if resource_path in integration_method_dict:
                existing_methods = set(resp['resourceMethods'].keys())
                configured_methods = set(integration_method_dict[resource_path])

                to_delete = list(existing_methods - configured_methods)
            # otherwise delete everything
            else:
                to_delete = list(existing_methods)


            # get rid of any integration that should not exist
            for cur_method in to_delete:
                integration_dict['httpMethod'] = cur_method
                try:
                    gateway_client.delete_method(**integration_dict)
                    logging(f'Deleted method {cur_method} under resource {resource_path}...')
                except Exception as e:
                    logging(e, utils.Colors.RED)

def __handle_gateway_lambda_policy(gateway_client, gateway_params: RestAPIGatewayParams, 
                                   resource_param: RestAPIGatewayParams.ResourceParams):
    # a guaranteed unique SID for this particular integration method's path + method
    statement_sid = f'{gateway_params.api_name}-{gateway_params._rest_api_id}-' + \
        f'{resource_param._resource_id}-{resource_param.method}-invokeFunction'
    
    # define all policy statement parameters
    policy_statement = RestAPIGatewayParams.ResourceParams._lambda_resource_policy
    policy_statement['FunctionName'] = resource_param.function_name
    policy_statement['StatementId'] = statement_sid

    account_number = session.client('iam').get_user()['User']['Arn'].split(':')[4]
    method = '*' if resource_param.method == 'ANY' else resource_param.method

    # rest api id / deployment stage / http method type / resource path part
    policy_statement['SourceArn'] = f'arn:aws:execute-api:{session.region_name}:{account_number}' + \
                        f':{gateway_params._rest_api_id}/*/{method}/{resource_param.path[1:]}'
    
    # check to see whether policy should be created or left alone
    lambda_client = session.client('lambda')

    try:
        cur_policy = lambda_client.get_policy(FunctionName=resource_param.function_name)

        json_policy_statements = json.loads(cur_policy['Policy'])['Statement']

        for json_policy_statement in json_policy_statements:
            if json_policy_statement['Sid'] == statement_sid and \
                json_policy_statement['Condition']['ArnLike']['AWS:SourceArn'] == policy_statement['SourceArn'] and \
                json_policy_statement['Action'] == policy_statement['Action']:
                # no change to be made: the policy statement with same id and same 
                # source arn -- so just leave as is
                return
            elif json_policy_statement['Sid'] == statement_sid:
                # otherwise just remove the statement and re-create it
                logging(f'Removing resource policy on function {resource_param.function_name} on ' + \
                        f'method {resource_param.method}')
                lambda_client.remove_permission(
                    FunctionName=resource_param.function_name,
                    StatementId=statement_sid
                )
                
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # create a new policy anyways
            pass
        else:
            raise e
    except Exception as e:
        raise e
    
    # create the permission
    logging(f'Attaching resource policy on function {resource_param.function_name} on ' + \
                    f'method {resource_param.method}')
    
    try:
        lambda_client.add_permission(**policy_statement)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            pass
        else:
            logging(e + ' under ClientError', utils.Colors.RED)

def __update_integration_method(gateway_client, gateway_params: RestAPIGatewayParams, resource_param: RestAPIGatewayParams.ResourceParams):
    logging(f'Updating integration method {resource_param.method} under resource {resource_param.path}...')

    # for updating, check for lambda function name vs any new function associated
    # and update if needed
    resp = gateway_client.get_integration(
        restApiId=gateway_params._rest_api_id,
        resourceId=resource_param._resource_id,
        httpMethod=resource_param.method
    )

    method_uri = resp['uri']
    current_lambda_function = method_uri.split(':')[-1].split('/')[0]

    # check to see if current lambda function matches the specified one
    if resource_param.function_name != current_lambda_function:
        logging('Function updated, deleting integration and reinstantiating...')

        gateway_client.delete_integration(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method
        )

        gateway_client.delete_method(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method
        )

        __create_integration_method(gateway_client, gateway_params, resource_param)

    else:
        logging('Integration method unchanged, verifying method permissions...')
        __handle_gateway_lambda_policy(gateway_client, gateway_params, resource_param)

def __create_integration_method(gateway_client, gateway_params, resource_param: RestAPIGatewayParams.ResourceParams):
    logging(f'Creating integration method {resource_param.method} under resource {resource_param.path}')

    function_details = __get_lambda_function_from_name(resource_param.function_name)
    function_arn = function_details['Configuration']['FunctionArn']

    if function_details is None:
        raise Exception(f'Could not find lambda function {resource_param.function_name}')
    
    try:
        method_uri = f'arn:aws:apigateway:{session.region_name}:lambda:path/2015-03-31/functions/{function_arn}/invocations'

        # define the method first
        gateway_client.put_method(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            authorizationType=resource_param._authorization_type,
            apiKeyRequired=resource_param._api_key_required
        )

        # add the lambda integration after
        gateway_client.put_integration(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            integrationHttpMethod='POST', # bichal fix this: integration http method fix hopefully works?
            type=resource_param._type,
            connectionType=resource_param._connection_type,
            uri=method_uri
        )

        # bichal fix this: experimenting with integration response
        # passthrough is implicit because contentHandling is not defined
        gateway_client.put_integration_response(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            statusCode='200'
        )

        # method response definition
        gateway_client.put_method_response(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            statusCode='200',
            responseModels={
                'application/json':'Empty'
            }
        )

        __handle_gateway_lambda_policy(gateway_client, gateway_params, resource_param)

    except Exception as e:
        logging(e, utils.Colors.RED)

def __handle_integration_methods(gateway_client, gateway_params):
    # pull the resource tree that is last updated during addition/ deletion of resources
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)
    integration_dict = {
        'restApiId': gateway_params._rest_api_id,
        'resourceId': None,
        'httpMethod': None
    }

    for resource_param in gateway_params.resources:
        if (resource_param.function_name is not None) and (resource_param.method is not None):
            # i may add/ update this current integration
            integration_dict['resourceId'] = ResourceTreeNode.get_path(root, resource_param.path).myResourceId
            integration_dict['httpMethod'] = resource_param.method

            # avoid reconstructing the resource tree by caching the resource id onto the obj
            resource_param._resource_id = integration_dict['resourceId']

            # check to see if resource method already exists or not
            try:
                gateway_client.get_integration(**integration_dict)

                # if i got over to this point, then the integration already exists, so updating is 
                # required in this case
                __update_integration_method(gateway_client, gateway_params, resource_param)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NotFoundException':
                    # guaranteed that creating / putting a new integration method is correct

                    __create_integration_method(gateway_client, gateway_params, resource_param)
                else:
                    logging(str(e.response) + ' under ClientError', utils.Colors.RED)
                    raise Exception()
            except Exception as e:
                logging(e, utils.Colors.RED)


def __handle_integration_updates(gateway_client, gateway_params):

    # first i will handle all implicit deletions if that is set
    # implicit deletions are all of these resource properties:
    #   1. any integration method that is not specified in gateway_params.resources
    #   2. even if specified in gateway_params.resources, if there exists another integration method
    #       that was not otherwise specified in gateway_params.resources[i]'s then that should also
    #       be deleted
    if gateway_params.implicit_deletion:
        __implicit_delete_integration_methods(gateway_client, gateway_params)

    # after deleting all integration methods, it is time to reconfigure lambda functions to work
    # with the specified endpoints... note that gateway_params.resources is guaranteed to exist in 
    # this case
    __handle_integration_methods(gateway_client, gateway_params)

def __handle_api_gateway_deployment(gateway_client, gateway_params):
    
    # here i can safely create a deployment and this will overwrite the past one if existing
    resp = gateway_client.create_deployment(
        restApiId=gateway_params._rest_api_id,
        stageName=gateway_params.deployment_stage
    )

    logging(resp, utils.Colors.GREEN)

    resp = gateway_client.get_stage(
        restApiId=gateway_params._rest_api_id,
        stageName=gateway_params.deployment_stage
    )

    invoke_url = f'https://{gateway_params._rest_api_id}.execute-api.' + \
        f'{session.region_name}.amazonaws.com/{gateway_params.deployment_stage}'

    logging(f'Created API deployment {gateway_params.api_name} under stage {gateway_params.deployment_stage}' + \
                f'\n{utils.Constants.TAB}url: {invoke_url}')


# create a new function that deploys the api gateway
def deploy_api_gateway(gateway_params):
    logging(f'Deploying API Gateway...')

    gateway_client = session.client('apigateway')

    cur_api = __get_api_from_name(gateway_client, gateway_params)

    if not cur_api:
        __create_api_gateway(gateway_client, gateway_params)
    else:
        __update_api_gateway(gateway_client, gateway_params)
    

    __handle_api_gateway_resource_updates(gateway_client, gateway_params)

    # the only reason to handle resource integration updates are if any resource exists in the first
    # place...
    if gateway_params.resources:
        __handle_integration_updates(gateway_client, gateway_params)

    if gateway_params.implicit_deletion and not gateway_params.resources:
        logging('No deployment issued, no resources exist on the API')
    else:
        # after setting up all methods and integrations, simply deploy this new version of the api
        try:
            __handle_api_gateway_deployment(gateway_client, gateway_params)
        except Exception as e:
            logging(e, utils.Colors.RED)

def remove_api_gateway(gateway_params: RestAPIGatewayParams):
    gateway_client = session.client('apigateway')
    cur_api = __get_api_from_name(gateway_client, gateway_params)

    if not cur_api:
        logging('Error: api specified for removal does not exist!')
    else:
        # find all the integrations and remove everything associated with 
        # permissions attached to this api.
        # repopulate the api resource data
        gateway_client.delete_rest_api(restApiId=gateway_params._rest_api_id)

# return table string if exists or return None
def __get_dynamodb_table_from_name(dynamodb_client, dynamodb_params: DynamoDBParams) -> str | None:
    resp = dynamodb_client.list_tables()

    table_names = resp['TableNames']

    print('searched table names:', table_names)
    print(type(table_names))

    if dynamodb_params.table_name in table_names:
        print('this table does exist')
        return dynamodb_params.table_name
    else:
        return None
    
def __update_dynamodb_table(dynamodb_client, dynamodb_params):
    pass
    
def __create_dynamodb_table(dynamodb_client, dynamodb_params: DynamoDBParams):
    logging('Creating DynamoDB table...')

    params = {}
    params['TableName'] = dynamodb_params.table_name

    # all the attributes defined should be included in this list
    attribute_definitions = []

    for attr_name, attr_type in dynamodb_params.attributes:
        attribute_definitions.append({
            'AttributeName': attr_name,
            'AttributeType': attr_type
        })

    params['AttributeDefinitions'] = attribute_definitions

    # key schema is the primary key stuff
    key_schema = []

    key_schema.append({
        'AttributeName': dynamodb_params.partition_key,
        'KeyType': dynamodb_params._HASH
    })

    if dynamodb_params.sort_key:
        key_schema.append({
            'AttributeName': dynamodb_params.sort_key,
            'KeyType': dynamodb_params._RANGE
        })

    params['KeySchema'] = key_schema

    # lsis
    local_secondary_index = []

    for lsi, _ in dynamodb_params.attributes:
        if lsi == dynamodb_params.partition_key or \
            lsi == dynamodb_params.sort_key:
            continue

        local_secondary_index.append(
            {
                'IndexName': lsi,
                'KeySchema': [
                    {
                        'AttributeName': dynamodb_params.partition_key,
                        'KeyType': 'HASH'
                    },
                    {
                        'AttributeName': lsi,
                        'KeyType': 'RANGE'
                    }
                ],
                'Projection': {
                    'ProjectionType': 'KEYS_ONLY'
                }
            })

    if local_secondary_index:
        params['LocalSecondaryIndexes'] = local_secondary_index
    params['BillingMode'] = dynamodb_params.billing_mode
    params['ProvisionedThroughput'] = {
        'ReadCapacityUnits': dynamodb_params.read_capacity_units,
        'WriteCapacityUnits': dynamodb_params.write_capacity_units
    }

    logging(params, utils.Colors.BLUE)

    dynamodb_client.create_table(**params)

def remove_dynamodb(dynamodb_params: DynamoDBParams):
    dynamodb_client = session.client('dynamodb')

    try:
        resp = dynamodb_client.describe_table(
            TableName=dynamodb_params.table_name
        )

        accepted_states = set(['ACTIVE', 'INACCESSIBLE_ENCRYPTION_CREDENTIALS',
                                'ARCHIVING', 'ARCHIVED'])
        
        while resp['Table']['TableStatus'] not in accepted_states:
            time.sleep(2)

            resp = dynamodb_client.describe_table(
                TableName=dynamodb_params.table_name
            )

    except Exception as e:
        raise(e)

    dynamodb_client.delete_table(
        TableName=dynamodb_params.table_name
    )

def deploy_dynamodb(dynamodb_params):

    dynamodb_client = session.client('dynamodb')

    # is None if the table does not already exist
    table_name = __get_dynamodb_table_from_name(dynamodb_client, dynamodb_params)

    if not table_name:
        __create_dynamodb_table(dynamodb_client, dynamodb_params)
    else:
        logging('code for update table here')