def lambda_handler(event, context):
    event['response']['autoConfirmUser'] = True

    if 'email' in event['request']['userAttributes']:
        event['response']['autoVerifyEmail'] = True

    # now i know this functin is updated
    return event