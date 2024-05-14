from aws_deploy.params import DynamoDBParams
from aws_deploy.utils import logging, session
import aws_deploy.utils as utils

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

    # pre-checking to enforce some restrictions on dynamodb deployments
    if not dynamodb_params.sort_key and len(dynamodb_params.attributes) > 1:
        logging('table contains excess lsis with only one primary key ' + \
                str(dynamodb_params.attributes), utils.Colors.YELLOW)
        raise Exception('Restriction: Do not create local secondary indices' + \
                        ' if the primary key does not have a sort!')

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
        # TODO: work on update table logic here later

        logging('TODO: UPDATE TABLE NOT IMPLEMENTED', utils.Colors.RED)

