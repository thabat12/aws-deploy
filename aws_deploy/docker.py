import botocore.exceptions
import docker
import botocore
import base64

import aws_deploy.utils as utils
from aws_deploy.utils import session, logging
from aws_deploy.params import ECRParams

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

    docker_client = docker.from_env()
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

def remove_ecr_image(ecr_params: ECRParams):
    pass