import json
import botocore.exceptions
import docker
import botocore
from botocore.client import BaseClient
import base64
import subprocess

import aws_deploy.utils as utils
from aws_deploy.utils import session, logging
from aws_deploy.params import ECRParams, ECSParams

def deploy_ecr_image(ecr_params: ECRParams):

    logging(f"Deploying Docker image to ECR repository {ecr_params.repository_name}...")

    ecr_params._registry_id = session.client('sts').get_caller_identity()['Account']
    ecr_client = session.client('ecr')
    resp = None

    try:
        # requires the ecr:CreateRepository action
        resp = ecr_client.create_repository(
            repositoryName=ecr_params.repository_name
        )

        ecr_params._repository_uri = resp['repository']['repositoryUri']

    except botocore.exceptions.ClientError as client_err:

        if client_err.response['Error']['Code'] == 'RepositoryAlreadyExistsException':
            logging(f"ECR repository {ecr_params.repository_name} already exists. Proceeding to update...", 
                    utils.Colors.GREEN)
            
            # requires the ecr:DescribeRepositories action
            repositories = ecr_client.describe_repositories(
                registryId=ecr_params._registry_id,
                repositoryNames=[ecr_params.repository_name]
            )

            ecr_params._repository_uri = repositories['repositories'][0]['repositoryUri']
        else:
            raise client_err
    except Exception as e:
        raise e

    docker_client = None

    try:
        docker_client = docker.from_env()
    except Exception as e:
        logging('Docker client failed to initialize! Check if Docker Engine is running.', utils.Colors.RED)
        raise e

    img = docker_client.images.get(f'{ecr_params.image_name}')
    img.tag(
        repository=ecr_params._repository_uri,
        tag=ecr_params.image_tag
    )

    # requires the ecr:GetAuthorizationToken action
    resp = ecr_client.get_authorization_token(
        registryIds=[ecr_params._registry_id]
    )

    auth_token = resp['authorizationData'][0]['authorizationToken']
    auth_token = base64.standard_b64decode(auth_token).decode().split(':')[-1].strip()
    
    proxy_endpoint = resp['authorizationData'][0]['proxyEndpoint']

    logging(f'proxy endpoint is : {proxy_endpoint}', utils.Colors.CYAN)
    
    docker_client.login(username='AWS', password=auth_token, registry=proxy_endpoint)
    
    # requires the ecr:InitiateLayerUpload action
    # requires the ecr:UploadLayerPart action
    # requires the ecr:CompleteLayerUpload action
    # requires the ecr:BatchCheckLayerAvailability action
    # requires the ecr:PutImage action
    push_logs = docker_client.images.push(ecr_params._repository_uri, stream=True, decode=True)

    for log in push_logs: 
        logging(log, utils.Colors.YELLOW)

    return {
        'proxy_endpoint': proxy_endpoint
    }

def remove_ecr_image(ecr_params: ECRParams):
    
    ecr_client = session.client('ecr')

    # ecr:DescribeImages
    resp = ecr_client.describe_images(
        repositoryName=ecr_params.repository_name,
        imageIds=[
            {
                'imageTag': ecr_params.image_tag
            }
        ]
    )

    img_digest = resp['imageDetails'][0]['imageDigest']

    # ecr:BatchDeleteImage
    ecr_client.batch_delete_image(
        repositoryName=ecr_params.repository_name,
        imageIds=[
            {
                'imageDigest': img_digest
            }
        ]
    )

    # ecr:ListImages
    images = ecr_client.list_images(
        repositoryName=ecr_params.repository_name
    )

    logging(images, utils.Colors.MAGENTA)

    if not images['imageIds']:
        # ecr:DeleteRepository
        ecr_client.delete_repository(
            repositoryName=ecr_params.repository_name
        )

def deploy_ecs(ecs_params: ECSParams):
    ecs_client = session.client('ecs')

    # ecs:ListClusters
    resp = ecs_client.list_clusters()
    cluster_arns = filter(lambda name: ecs_params.cluster_name == name.split('/')[-1], resp['clusterArns'])

    while 'nextToken' in resp.keys():
        resp = ecs_client.list_clusters(nextToken=resp['nextToken'])
        cluster_arns = filter(lambda name: ecs_params.cluster_name == name.split('/')[-1], resp['clusterArns'])
        if cluster_arns: break

    if not cluster_arns:
        # ecs:CreateCluster
        # ecs:TagResource
        ecs_client.create_cluster(
            clusterName=ecs_params.cluster_name,
            tags=[ {'key': 'tag', 'value': ecs_params._tag_name} ],
            capacityProviders=ecs_params.capacity_providers
        )

        logging(f'Created new ECS cluster with name {ecs_params.cluster_name}')
    else:
        logging(f'ECS cluster with name {ecs_params.cluster_name} already exists')


    # REGISTER A TASK DEFINITION
    


    # ensure role is created with the necessary tag to allow for reference for potential deletion
    # of the iam role
    iam_client = session.client('iam')

    try:
        iam_client.get_role(RoleName=ecs_params._ecs_execution_role_name)
    except:
        logging(f'Creating and attaching new IAM role {ecs_params._ecs_execution_role_name} to task definition')
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
            RoleName=ecs_params._ecs_execution_role_name,
            AssumeRolePolicyDocument=json.dumps(ecs_params._ecs_trust_policy),
            Tags=[ { 'Key': 'Creator', 'Value': user_name } ]
        )

        # deploy & retrieve function arn
        iam_client.put_role_policy(
            RoleName=ecs_params._ecs_execution_role_name,
            PolicyName=ecs_params._ecs_execution_policy_name,
            PolicyDocument=json.dumps(ecs_params._ecs_execution_role)
        )


    resp = iam_client.get_role(RoleName=ecs_params._ecs_execution_role_name)
    

    logging(resp, utils.Colors.GREEN)
    # ecs_client.register_task_definition(
    #     family=ecs_params.task_definition_name,
    #     taskRoleArn=ecs_params._ecs_task_execution_role_name
    #     # taskRoleArn

    # )
    
    logging('autogenerated role should exist now', utils.Colors.GREEN)

    

def remove_ecs(ecs_params):
    pass