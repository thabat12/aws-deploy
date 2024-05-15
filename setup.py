import zipfile
import json
import io
import os

import boto3
import botocore.exceptions

from aws_deploy.functions import deploy_lambda, remove_lambda
from aws_deploy.gateway import deploy_rest_api, remove_rest_api
from aws_deploy.params import LambdaParams, CognitoParams, RestAPIGatewayParams, ECRParams
from aws_deploy.docker import deploy_ecr_image, remove_ecr_image

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
ecr_params.repository_name = 'myrepo'
ecr_params.image_name = 'go-app'
ecr_params.image_tag = 'v2'

deploy_ecr_image(ecr_params)

ecr_params.image_tag = 'v3'
deploy_ecr_image(ecr_params)
remove_ecr_image(ecr_params)