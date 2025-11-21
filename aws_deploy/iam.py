import json

import botocore

import aws_deploy.utils as utils
from aws_deploy.utils import get_client, logging


class IAMParams:
    def __init__(self, role_config: dict):
        self.role_config = role_config
        self._role_arn = None
        self._role_name = None


def deploy_iam_role(iam_params: IAMParams):
    iam_client = get_client('iam')
    
    role_name = iam_params.role_config.get('RoleName')
    if not role_name:
        raise ValueError('RoleName is required in role_config')
    
    iam_params._role_name = role_name
    
    try:
        resp = iam_client.get_role(RoleName=role_name)
        logging('Role already exists!', utils.Colors.CYAN)
        iam_params._role_arn = resp['Role']['Arn']
        return resp
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code != 'NoSuchEntity':
            raise e
        logging('Role does not exist, creating...', utils.Colors.CYAN)
    
    create_role_kwargs = iam_params.role_config.copy()
    
    if 'AssumeRolePolicyDocument' in create_role_kwargs:
        if isinstance(create_role_kwargs['AssumeRolePolicyDocument'], dict):
            create_role_kwargs['AssumeRolePolicyDocument'] = json.dumps(
                create_role_kwargs['AssumeRolePolicyDocument']
            )
    
    if 'Tags' not in create_role_kwargs:
        sts_client = get_client('sts')
        sts_resp = sts_client.get_caller_identity()
        
        if sts_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
            user_arn = sts_resp["Arn"]
            create_role_kwargs['Tags'] = [
                {
                    'Key': 'Creator',
                    'Value': user_arn
                }
            ]
    
    resp = iam_client.create_role(**create_role_kwargs)
    iam_params._role_arn = resp['Role']['Arn']
    
    if 'Policies' in iam_params.role_config:
        for policy in iam_params.role_config['Policies']:
            policy_name = policy.get('PolicyName')
            policy_document = policy.get('PolicyDocument')
            
            if isinstance(policy_document, dict):
                policy_document = json.dumps(policy_document)
            
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
    
    try:
        iam_client.get_waiter('role_exists').wait(RoleName=role_name)
        resp = iam_client.get_role(RoleName=role_name)
        return resp
    except Exception as e:
        raise e


def remove_iam_role(iam_params: IAMParams):
    iam_client = get_client('iam')
    
    role_name = iam_params._role_name
    if not role_name and iam_params._role_arn:
        role_name = iam_params._role_arn.split('/')[-1].strip()
    
    if not role_name:
        raise ValueError('Role name or ARN must be provided')
    
    try:
        attached_policies_resp = iam_client.list_attached_role_policies(
            RoleName=role_name
        )
        
        for policy in attached_policies_resp.get('AttachedPolicies', []):
            iam_client.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['PolicyArn']
            )
        
        inline_policies_resp = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies_resp.get('PolicyNames', []):
            iam_client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
        
        iam_client.delete_role(RoleName=role_name)
        logging(f'Role {role_name} removed successfully', utils.Colors.GREEN)
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'NoSuchEntity':
            logging(f'Role {role_name} does not exist', utils.Colors.YELLOW)
            return
        raise e
    except Exception as e:
        logging(f'Error removing role: {e}', utils.Colors.RED)
        raise e

