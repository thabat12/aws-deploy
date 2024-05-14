import time

import botocore

from aws_deploy.params import CognitoParams
import aws_deploy.utils as utils
from aws_deploy.utils import logging, session

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
