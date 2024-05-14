class LambdaParams:
    function_name = None
    runtime = 'python3.8'
    role_name = None
    handler_method = None 
    code_folder_filepath = None
    deployment_package_files = None
    lambda_layer_lib_filepath = None

    _function_arn = None
    _role_arn = None  

class CognitoParams:
    pool_name = 'developedWithCode'
    pool_id = None
    userpool_arn = None

    def remap_underscores(underscored_string):
        return ''.join(word.capitalize() for word in underscored_string.split('_'))
    
    def get_boto3_dict(cls, remap_underscores=True):
        if (remap_underscores):
            return {CognitoParams.remap_underscores(p):getattr(cls, p) \
                    for p in dir(cls) if ('__' not in p) and (not callable(p))}
        else:
            return {p:getattr(cls, p) for p in dir(cls) if ('__' not in p) and (not callable(p))}

    class Policies:
        class PasswordPolicy:
            minimum_length = 6
            require_uppercase = False
            require_lowercase = False 
            require_numbers = False
            require_symbols = False
            temporary_password_validity_days = 1
    
    deletion_protection = 'INACTIVE'

    class LambdaConfig:
        pre_sign_up = 'arn:aws:lambda:us-east-2:758259432754:function:preSignUpLambdaTriggerTradingSimCognitoUserpool'
        
        # 'arn:aws:lambda:us-east-2:758259432754:function:preSignUpLambdaTriggerTradingSimCognitoUserpool'

    # since every lambda function shares the same resource policy, placing all the resource
    # policies together in params and making them immutable seems like the best idea to me
    
    _lambda_resource_policy = {
        "FunctionName": None,
        "Action": 'lambda:InvokeFuncion',
        "StatementId": None,
        "Principal": 'cognito-idp.amazonaws.com',
        "SourceArn": None,
        "SourceAccount": "758259432754" # TODO: make this a variable
    }


    auto_verified_attributes = ['phone_number', 'email']
    alias_attributes = ['preferred_username']
    username_attributes = ['email']

    class ClientParams:
        client_id = None # will be updated in the code
        client_name = 'client1'
        explicit_auth_flows = ['ALLOW_REFRESH_TOKEN_AUTH', 'ALLOW_USER_SRP_AUTH', 'ALLOW_USER_PASSWORD_AUTH', 'ALLOW_ADMIN_USER_PASSWORD_AUTH']
        allowed_oauth_scopes = ['phone', 'email', 'openid']
        supported_identity_providers = ['COGNITO', 'Google']
        callback_urls = ['https://google.com/']
        allowed_oauth_flows = ['code', 'implicit'] # may be either code, implicit, or client credentials
        # in my experience, implicit gets things working for signing up auto stuff
        allowed_oauth_flows_userpool_client = True

    class IdentityProviderParams:
        class ProviderDetails:
            client_id = '1040516850328-sv2d7puurebdo53l0m4dr21hqpcjqi2c.apps.googleusercontent.com'
            client_secret = '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'
            authorize_scopes = 'openid profile email'
            api_version = '' # adding this to "filter" the values and for testing that functionality
        
        class AttributeMapping:
            email = 'email'
            name = 'names'
            picture = 'picture'
        
        provider_name = 'Google' # existence of this determines deployment
        provider_type = 'Google'

    class DomainParams:
        domain = 'abhinavbichal2'

    def __init__(self):
        # because i'm making an instance of this class
        self.Policies = CognitoParams.Policies()
        self.Policies.PasswordPolicy = self.Policies.PasswordPolicy()
        self.LambdaConfig = CognitoParams.LambdaConfig()
        self.ClientParams = CognitoParams.ClientParams()
        self.IdentityProviderParams = CognitoParams.IdentityProviderParams()
        self.IdentityProviderParams.ProviderDetails = self.IdentityProviderParams.ProviderDetails()
        self.IdentityProviderParams.AttributeMapping = self.IdentityProviderParams.AttributeMapping()
        self.DomainParams = CognitoParams.DomainParams()

# this class will only focus on creating RESTful APIs through API Gateway
class RestAPIGatewayParams:
    implicit_deletion = False

    api_name = None
    deployment_stage = 'default'

    # internal function stuff
    _rest_api_id = None
    _root_resource_id = None
    _api_resource_data = None

    class ResourceParams:

        _lambda_resource_policy = {
            "FunctionName": None,
            "Action": 'lambda:InvokeFunction',
            "StatementId": None,
            "Principal": 'apigateway.amazonaws.com',
            "SourceArn": None
        }

        # internal function stuff
        _resource_id = None
        _type = 'AWS'
        _connection_type = 'INTERNET'
        _http_method = 'POST'
        _authorization_type = 'NONE'
        _api_key_required = False

        def __init__(self, path, function_name, method = 'ANY'):
            self.path = path
            self.function_name = function_name
            self.method = method

    def __init__(self):
        self.resources = []

    def add_resource(self, path, function_name = None, method = None):
        self.resources.append(RestAPIGatewayParams.ResourceParams(path, function_name, method))

class DynamoDBParams:
    table_name = None
    attributes = []

    # primary key
    partition_key = None
    partition_key_type = None
    sort_key = None
    sort_key_type = None

    billing_mode = 'PROVISIONED'

    read_capacity_units = 1
    write_capacity_units = 1

    
    _HASH = 'HASH'
    _RANGE = 'RANGE'

    def __init__(self):
        # reset everything as a defensive mechanism to prevent static type influencing variables
        self.table_name = None
        self.attributes = []
        self.partition_key, self.partition_key_type = None, None
        self.sort_key, self.sort_key_type = None, None
        self.billing_mode = 'PROVISIONED'
        self.read_capacity_units = 1
        self.write_capacity_units = 1
        self._HASH = 'HASH'
        self._RANGE = 'RANGE'

    
    def add_local_secondary_index(self, attr, data_type):
        self.attributes.append((attr, data_type))

    def set_partition_key(self, key, key_type):
        self.partition_key = key
        self.partition_key_type = key_type
        self.attributes.append((key, key_type))

    def set_sort_key(self, sort, sort_type):
        self.sort_key = sort
        self.sort_key_type = sort_type
        self.attributes.append((sort, sort_type))