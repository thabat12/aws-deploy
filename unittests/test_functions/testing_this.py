import json

def lambda_handler(event, context):
    return json.dumps('Hi there, this is deployed through code!')