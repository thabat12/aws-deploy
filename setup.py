import zipfile
import json
import io
import os

import boto3
import botocore.exceptions

from aws_deploy.functions import deploy_lambda, remove_lambda
from aws_deploy.gateway import deploy_rest_api, remove_rest_api
from aws_deploy.params import LambdaParams, CognitoParams, RestAPIGatewayParams, ECRParams, ECSParams
from aws_deploy.docker import deploy_ecr_image, remove_ecr_image, deploy_ecs

from aws_deploy.utils import Constants, logging, session
import aws_deploy.utils as utils

sts_client = session.client('sts')
resp = sts_client.get_caller_identity()

if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
    logging(f'Log in successful', utils.Colors.GREEN)
    logging(f'{Constants.TAB}User: {resp["Arn"].split("/")[1]}', utils.Colors.GREEN)
else:
    logging(f'Bad Request: HTTP status code: {resp["HttpStatusCode"]}', utils.Colors.RED)

ecr_params = ECRParams()
# the image "bucket" that you submit into
ecr_params.repository_name = 'simple-web-container-repo'
# the image that is already built that is to be placed in that bucket
ecr_params.image_name = 'simple-web-container'
# a certain tag to give to that image for identificaiton purposes
ecr_params.image_tag = 'v1'

# resp = deploy_ecr_image(ecr_params)
logging(resp, utils.Colors.RED)
# remove_ecr_image(ecr_params)

ecs_params = ECSParams()
ecs_params.cluster_name = 'boto3cluster'
ecs_params.capacity_providers = ['FARGATE', 'FARGATE_SPOT']
'''
plan on how to do this




'''

deploy_ecs(ecs_params)