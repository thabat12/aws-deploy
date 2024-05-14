import json

def lambda_handler(event, context):
    """
    Lambda handler function.
    
    Parameters:
        - event: Event data passed to the Lambda function.
        - context: Lambda execution context.

    Returns:
        A dictionary containing the response data.
    """
    # Your Lambda function logic goes here
    # Example: Return a simple message
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Hello from Lambda!'})
    }
