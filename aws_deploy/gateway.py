import json
from typing import List

import botocore

from aws_deploy.params import RestAPIGatewayParams
from aws_deploy.utils import logging, session
from aws_deploy.functions import get_lambda_function_from_name
import aws_deploy.utils as utils

class ResourceTreeNode:
    def _insert_node_helper(cur_node, segments, cur_segment_ind, parent_id, my_id):
        if cur_segment_ind >= len(segments):
            return None
        
        if not cur_node:
            cur_my_id = my_id if cur_segment_ind == len(segments) - 1 else None
            cur_node = ResourceTreeNode(parent_id, cur_my_id, segments[cur_segment_ind])

            # not at the leaf, peek ahead and assign
            if cur_segment_ind < len(segments) - 1: 
                cur_node.children[segments[cur_segment_ind + 1]] = \
                    ResourceTreeNode._insert_node_helper(
                        None,
                        segments,
                        cur_segment_ind + 1,
                        cur_my_id,
                        my_id
                    )
            # at the leaf, no need to further recurse
            else:
                return cur_node
        # node is made
        else:
            # parentid reassigned no matter what
            cur_node.parentResourceId = parent_id

            # at leaf node, update my_id
            if cur_segment_ind == len(segments) - 1:
                cur_node.myResourceId = my_id

                # however, there is an additional case of having children node that need to also 
                # reflect this update, so update all children values too if they exist
                for child in cur_node.children.values():
                    child.parentResourceId = my_id

            # not at leaf, peek ahead and assign
            else:
                # node already exists, so pass in existing ref
                if segments[cur_segment_ind + 1] in cur_node.children:
                    cur_node.children[segments[cur_segment_ind + 1]] = \
                        ResourceTreeNode._insert_node_helper(
                            cur_node.children[segments[cur_segment_ind + 1]],
                            segments,
                            cur_segment_ind + 1,
                            cur_node.myResourceId,
                            my_id
                        )
                # node does not exist, pass in None to implicitly create
                else:
                    cur_node.children[segments[cur_segment_ind + 1]] = \
                        ResourceTreeNode._insert_node_helper(
                            None,
                            segments,
                            cur_segment_ind + 1,
                            cur_node.myResourceId,
                            my_id
                        )
        return cur_node

    def insert_path(root, fullPath, resourceId):
        path_segments = fullPath.split('/')
        # automatically assumes that the first segment is just the root
        ResourceTreeNode._insert_node_helper(root, path_segments, 0, None, resourceId)

    def get_path(root, fullPath):
        if fullPath == '/': return root # quick edge case fix

        path_segments = fullPath.split('/')
        assert path_segments[0] == '', 'path must start with /'
        cur_node = root
        for segment in path_segments[1:]:
            if segment in cur_node.children:
                cur_node = cur_node.children[segment]
            else:
                return None
        return cur_node
    
    def get_topological_order(node, cur_path, cur_solution):
        cur_path += '/' + node.pathPart if node.pathPart else ''

        for child in node.children.values():
            ResourceTreeNode.get_topological_order(child, cur_path, cur_solution)

        cur_solution.append(cur_path)

        if node.pathPart == '':
            cur_solution = cur_solution.reverse()

    # returns the node with corresponding data on api gateway_params object
    def _construct_api_resource_tree(gateway_params: RestAPIGatewayParams):
        # get rid of any dependency errors with root resource id not being set or no resource data available
        if not gateway_params._root_resource_id:
            raise Exception("There is no root resource id specified in gateway_params!")
        
        if gateway_params._api_resource_data is None:
            raise Exception("API resource data is None, cannot construct resource tree!")
        
        root = ResourceTreeNode(None, gateway_params._root_resource_id, '')
        
        for resource in gateway_params._api_resource_data:
            resource_id = resource['id']
            resource_path = resource['path']
            ResourceTreeNode.insert_path(root, resource_path, resource_id)

        return root

    def __str__(self) -> str:
        return f'node ({self.pathPart}) :: my id {self.myResourceId} :: parent rid {self.parentResourceId}'
    
    def __repr__(self) -> str:
        return self.__str__()

    def __init__(self, parentResourceId, myResourceId, pathPart):
        self.parentResourceId, self.myResourceId, self.pathPart = parentResourceId, myResourceId, pathPart
        self.children = {
            # for now this is empty
        }

def __get_api_from_name(gateway_client, gateway_params):
    # retrieve the existing apis and scan through to get the current api being developed on
    cur_api = None
    existing_apis = gateway_client.get_rest_apis()

    for api in existing_apis['items']:
        if api['name'] == gateway_params.api_name:
            cur_api = api

    # i will set the root resource id and the api id if the api exists
    if cur_api:
        gateway_params._rest_api_id = cur_api['id']
        gateway_params._root_resource_id = cur_api['rootResourceId']

    return cur_api

def __update_api_gateway(gateway_client, gateway_params):
    logging(f'Updating API with name {gateway_params.api_name}...')

def __create_api_gateway(gateway_client, gateway_params):
    logging(f'Creating API with name {gateway_params.api_name}...')


    resp = gateway_client.create_rest_api(
        name=gateway_params.api_name,
    )

    # setting the important parameters for the gateway_params object
    gateway_params._rest_api_id = resp['id']
    gateway_params._root_resource_id = resp['rootResourceId']

    logging(resp, utils.Colors.GREEN)

# function for handling implicit deletions
def __delete_api_gateway_resources(gateway_client, gateway_params, resources_to_delete):
    logging('Implicit deleting api resources...')
    # adding resources to path to get api resource id data and parent id data
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # optimization: delete only the top-most root of each set of resources
    def get_resource_deletion_roots(root, resources_to_delete):
        visited_nodes = set()
        filtered_resources_to_delete = []

        def find_and_flag(node: ResourceTreeNode, path: List[str], cur_path_index: int):
            if cur_path_index == len(path):
                visited_nodes.add(node)
                return
            elif node in visited_nodes:
                return 
            else:
                path_part = path[cur_path_index]
                find_and_flag(node.children[path_part], path, cur_path_index + 1)

        for resource_to_delete in resources_to_delete:
            resource_path_parts = resource_to_delete.split('/')[1:]
            size_before = len(visited_nodes)
            find_and_flag(root, resource_path_parts, 0)
            size_after = len(visited_nodes)

            if size_after > size_before: filtered_resources_to_delete.append(resource_to_delete)

        return filtered_resources_to_delete
    
    filtered_resources_to_delete = get_resource_deletion_roots(root, resources_to_delete)

    # delete only the root level of resources to delete...
    for resource_to_delete in filtered_resources_to_delete:
        logging(f'Deleting resource: {resource_to_delete} under API {gateway_params.api_name}...')

        resource_id = ResourceTreeNode.get_path(root, resource_to_delete).myResourceId
        
        try:
            gateway_client.delete_resource(restApiId=gateway_params._rest_api_id, resourceId=resource_id)
        except Exception as e:
            logging(e, utils.Colors.RED)

    # repopulate the api resource data
    gateway_params._api_resource_data = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )['items']

def __add_api_gateway_resources(gateway_client, gateway_params, resources_to_add):
    logging(f'Adding api resources...')

    # i want this function to be guaranteed to work no matter what
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # all resources to add are guaranteed to not already exist on api gateway, but they should be valid
    # in terms of adding them onto the resource tree and ensuring that a parent resourceId exists
    new_resources = []

    # first, add everything to the tree to retrieve parent data
    for resource_to_add in resources_to_add:
        # a small check to ensure that the path is valid (starting off from the empty '' node)
        is_valid = resource_to_add.split('/')[0] == ''

        if not is_valid: raise Exception("the path provided is not valid!")

        # implicitly add all parent resource information to the tree
        ResourceTreeNode.insert_path(root, resource_to_add, None)
        new_resources.append(ResourceTreeNode.get_path(root, resource_to_add))
    
    # the step above only adds parent data to the nodes directly below the currently existing paths
    # now when deploying to api gateway, i need to keep track of resource ids and propagate these
    # resource + parent id pairs down the tree the more sequentially I add these resource pahts

    logging(new_resources, utils.Colors.BLUE)

    topologically_sorted_resources = []
    ResourceTreeNode.get_topological_order(root, '', topologically_sorted_resources)

    # now that i have the topologically sorted resources, i need to add them one by one
    for resource in topologically_sorted_resources:
        # if the resource already exists, no need to attempt creating a new resource
        if ResourceTreeNode.get_path(root, resource).myResourceId != None:
            continue

        try:
            resp = gateway_client.create_resource(
                restApiId=gateway_params._rest_api_id,
                parentId=ResourceTreeNode.get_path(root, resource).parentResourceId,
                pathPart=resource.split('/')[-1]
            )

            # overwriting the id to be reflected in the tree, will also update all children of the 
            # currently selected node (this is abstracted away in the insert_path method)
            ResourceTreeNode.insert_path(root, resource, resp['id'])

            logging(f'Created resource {resource} under API {gateway_params.api_name}')
        except Exception as e:
            logging(e, utils.Colors.RED)

    # repopulate the api resource data
    gateway_params._api_resource_data = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )['items']

def __handle_api_gateway_resource_updates(gateway_client, gateway_params):

    # now i need to retrieve all the resources associated with the rest api
    resp = gateway_client.get_resources(
        restApiId=gateway_params._rest_api_id
    )

    # setting a private variable for furture references in functions
    gateway_params._api_resource_data = resp['items']

    # here, i will handle implicit deletions, additions, and updates for any api resources
    all_resource_paths = set([resource['path'] for resource in gateway_params._api_resource_data])
    gateway_param_resource_paths = set([resource_param.path for resource_param in gateway_params.resources])

    ###### DELETE RESOURCE LOGIC
    # tricky: deleted resources are all resource paths that are not the paths specified in gateway_params.resources
    #           AND not subpaths of any of these resources either. the best way to ensure this behavior is to
    #           work on the resource tree...
    specified_resources_root = ResourceTreeNode(None, gateway_params._root_resource_id, '')

    # insert every path into specified resource root tree
    for resource in gateway_params.resources:
        ResourceTreeNode.insert_path(specified_resources_root, resource.path, None)
        assert ResourceTreeNode.get_path(specified_resources_root, resource.path) != None

    deleted_resources = set()

    # now for every path on "all_resource_paths", ensure that the path does not exist on specified resource root
    # paths, and if so, it is safe to delete
    for all_resource_cur_resource in all_resource_paths:
        if ResourceTreeNode.get_path(specified_resources_root, all_resource_cur_resource) == None:
            deleted_resources.add(all_resource_cur_resource)

    # adding resources is simple, since implicit paths are a part of addition
    added_resources = gateway_param_resource_paths - all_resource_paths

    # now will only delete resources if there is an implicit deletion specification set
    if deleted_resources:
        __delete_api_gateway_resources(gateway_client, gateway_params, deleted_resources)

    if added_resources:
        __add_api_gateway_resources(gateway_client, gateway_params, added_resources)

def __implicit_delete_integration_methods(gateway_client, gateway_params):
    logging('Implicit deleting integration methods...')

    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)

    # all integration methods that have a lambda function configured
    integration_methods = [i for i in gateway_params.resources if i.function_name is not None]

    # if using implicit deletion mode, i must consider all other paths in gateway and delete the 
    # associated integration methods
    all_resource_paths = [r['path'] for r in gateway_params._api_resource_data]

    integration_dict = {
        'restApiId': gateway_params._rest_api_id,
        'resourceId': None,
        'httpMethod': None
    }

    integration_method_dict = {}

    # keep track of all the integration methods that have an integration specified on the gateway
    # params object. 
    for integration_method in integration_methods:
        if integration_method.path not in integration_method_dict:
            integration_method_dict[integration_method.path] = []

        integration_method_dict[integration_method.path].append(integration_method.method)

    for resource_path in all_resource_paths:
        integration_dict['resourceId'] = ResourceTreeNode.get_path(root, resource_path).myResourceId
        
        # get current existing integrations
        resp = gateway_client.get_resource(
            restApiId=integration_dict['restApiId'],
            resourceId=integration_dict['resourceId']
        )

        # enter the integration method deletion job if there are methods specified
        if 'resourceMethods' in resp:
            # delete everything
            existing_methods = resp['resourceMethods'].keys()
            to_delete: List = None
            # the path is configured as an integration path for gateway_params, so only delete the 
            # methods that the client did not specify
            if resource_path in integration_method_dict:
                existing_methods = set(resp['resourceMethods'].keys())
                configured_methods = set(integration_method_dict[resource_path])

                to_delete = list(existing_methods - configured_methods)
            # otherwise delete everything
            else:
                to_delete = list(existing_methods)


            # get rid of any integration that should not exist
            for cur_method in to_delete:
                integration_dict['httpMethod'] = cur_method
                try:
                    gateway_client.delete_method(**integration_dict)
                    logging(f'Deleted method {cur_method} under resource {resource_path}...')
                except Exception as e:
                    logging(e, utils.Colors.RED)

def __handle_gateway_lambda_policy(gateway_client, gateway_params: RestAPIGatewayParams, 
                                   resource_param: RestAPIGatewayParams.ResourceParams):
    # a guaranteed unique SID for this particular integration method's path + method
    statement_sid = f'{gateway_params.api_name}-{gateway_params._rest_api_id}-' + \
        f'{resource_param._resource_id}-{resource_param.method}-invokeFunction'
    
    # define all policy statement parameters
    policy_statement = RestAPIGatewayParams.ResourceParams._lambda_resource_policy
    policy_statement['FunctionName'] = resource_param.function_name
    policy_statement['StatementId'] = statement_sid

    account_number = session.client('iam').get_user()['User']['Arn'].split(':')[4]
    method = '*' if resource_param.method == 'ANY' else resource_param.method

    # rest api id / deployment stage / http method type / resource path part
    policy_statement['SourceArn'] = f'arn:aws:execute-api:{session.region_name}:{account_number}' + \
                        f':{gateway_params._rest_api_id}/*/{method}/{resource_param.path[1:]}'
    
    # check to see whether policy should be created or left alone
    lambda_client = session.client('lambda')

    try:
        cur_policy = lambda_client.get_policy(FunctionName=resource_param.function_name)

        json_policy_statements = json.loads(cur_policy['Policy'])['Statement']

        for json_policy_statement in json_policy_statements:
            if json_policy_statement['Sid'] == statement_sid and \
                json_policy_statement['Condition']['ArnLike']['AWS:SourceArn'] == policy_statement['SourceArn'] and \
                json_policy_statement['Action'] == policy_statement['Action']:
                # no change to be made: the policy statement with same id and same 
                # source arn -- so just leave as is
                return
            elif json_policy_statement['Sid'] == statement_sid:
                # otherwise just remove the statement and re-create it
                logging(f'Removing resource policy on function {resource_param.function_name} on ' + \
                        f'method {resource_param.method}')
                lambda_client.remove_permission(
                    FunctionName=resource_param.function_name,
                    StatementId=statement_sid
                )
                
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # create a new policy anyways
            pass
        else:
            raise e
    except Exception as e:
        raise e
    
    # create the permission
    logging(f'Attaching resource policy on function {resource_param.function_name} on ' + \
                    f'method {resource_param.method}')
    
    try:
        lambda_client.add_permission(**policy_statement)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            pass
        else:
            logging(e + ' under ClientError', utils.Colors.RED)

def __remove_all_associated_gateway_lambda_policies(gateway_client, gateway_params):
    # this is required to construct the API resource tree
    gateway_params._api_resource_data = gateway_client.get_resources(
            restApiId=gateway_params._rest_api_id
    )['items']

    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)
    # all integration methods that have a lambda function configured
    integration_methods: List[RestAPIGatewayParams.ResourceParams] = [i for i in gateway_params.resources if i.function_name is not None]

    logging('Cleaning up all relevant method lambda permissions...')

    # remove all relevant permissions
    lambda_client = session.client('lambda')

    for im in integration_methods:

        function_spec = get_lambda_function_from_name(im.function_name)

        statement_sid = f'{gateway_params.api_name}-{gateway_params._rest_api_id}-' + \
        f'{im._resource_id}-{im.method}-invokeFunction'

        try:
            lambda_client.remove_permission(
                FunctionName=im.function_name,
                StatementId=statement_sid
            )
        except Exception as e:
            # strange behavior but let it pass
            logging(f"permission {statement_sid} unable to be deleted on function {im.function_name}", 
                    utils.Colors.YELLOW)

        logging('Removing statement sid ' + str(statement_sid) + ' for method ' + str(im.function_name))


    pass

def __update_integration_method(gateway_client, gateway_params: RestAPIGatewayParams, resource_param: RestAPIGatewayParams.ResourceParams):
    logging(f'Updating integration method {resource_param.method} under resource {resource_param.path}...')

    # for updating, check for lambda function name vs any new function associated
    # and update if needed
    resp = gateway_client.get_integration(
        restApiId=gateway_params._rest_api_id,
        resourceId=resource_param._resource_id,
        httpMethod=resource_param.method
    )

    method_uri = resp['uri']
    current_lambda_function = method_uri.split(':')[-1].split('/')[0]

    # check to see if current lambda function matches the specified one
    if resource_param.function_name != current_lambda_function:
        logging('Function updated, deleting integration and reinstantiating...')

        gateway_client.delete_integration(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method
        )

        gateway_client.delete_method(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method
        )

        __create_integration_method(gateway_client, gateway_params, resource_param)

    else:
        logging('Integration method unchanged, verifying method permissions...')
        __handle_gateway_lambda_policy(gateway_client, gateway_params, resource_param)

def __create_integration_method(gateway_client, gateway_params, resource_param: RestAPIGatewayParams.ResourceParams):
    logging(f'Creating integration method {resource_param.method} under resource {resource_param.path}')

    function_details = get_lambda_function_from_name(resource_param.function_name)
    function_arn = function_details['Configuration']['FunctionArn']

    if function_details is None:
        raise Exception(f'Could not find lambda function {resource_param.function_name}')
    
    try:
        method_uri = f'arn:aws:apigateway:{session.region_name}:lambda:path/2015-03-31/functions/{function_arn}/invocations'

        # define the method first
        gateway_client.put_method(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            authorizationType=resource_param._authorization_type,
            apiKeyRequired=resource_param._api_key_required
        )

        # add the lambda integration after
        gateway_client.put_integration(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            integrationHttpMethod='POST', # bichal fix this: integration http method fix hopefully works?
            type=resource_param._type,
            connectionType=resource_param._connection_type,
            uri=method_uri
        )

        # bichal fix this: experimenting with integration response
        # passthrough is implicit because contentHandling is not defined
        gateway_client.put_integration_response(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            statusCode='200'
        )

        # method response definition
        gateway_client.put_method_response(
            restApiId=gateway_params._rest_api_id,
            resourceId=resource_param._resource_id,
            httpMethod=resource_param.method,
            statusCode='200',
            responseModels={
                'application/json':'Empty'
            }
        )

        __handle_gateway_lambda_policy(gateway_client, gateway_params, resource_param)

    except Exception as e:
        logging(e, utils.Colors.RED)

def __handle_integration_methods(gateway_client, gateway_params):
    # pull the resource tree that is last updated during addition/ deletion of resources
    root = ResourceTreeNode._construct_api_resource_tree(gateway_params)
    integration_dict = {
        'restApiId': gateway_params._rest_api_id,
        'resourceId': None,
        'httpMethod': None
    }

    for resource_param in gateway_params.resources:
        if (resource_param.function_name is not None) and (resource_param.method is not None):
            # i may add/ update this current integration
            integration_dict['resourceId'] = ResourceTreeNode.get_path(root, resource_param.path).myResourceId
            integration_dict['httpMethod'] = resource_param.method

            # avoid reconstructing the resource tree by caching the resource id onto the obj
            resource_param._resource_id = integration_dict['resourceId']

            # check to see if resource method already exists or not
            try:
                gateway_client.get_integration(**integration_dict)

                # if i got over to this point, then the integration already exists, so updating is 
                # required in this case
                __update_integration_method(gateway_client, gateway_params, resource_param)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NotFoundException':
                    # guaranteed that creating / putting a new integration method is correct

                    __create_integration_method(gateway_client, gateway_params, resource_param)
                else:
                    logging(str(e.response) + ' under ClientError', utils.Colors.RED)
                    raise Exception()
            except Exception as e:
                logging(e, utils.Colors.RED)

def __handle_integration_updates(gateway_client, gateway_params):

    # first i will handle all implicit deletions if that is set
    # implicit deletions are all of these resource properties:
    #   1. any integration method that is not specified in gateway_params.resources
    #   2. even if specified in gateway_params.resources, if there exists another integration method
    #       that was not otherwise specified in gateway_params.resources[i]'s then that should also
    #       be deleted
    __implicit_delete_integration_methods(gateway_client, gateway_params)

    # after deleting all integration methods, it is time to reconfigure lambda functions to work
    # with the specified endpoints... note that gateway_params.resources is guaranteed to exist in 
    # this case
    __handle_integration_methods(gateway_client, gateway_params)

def __handle_api_gateway_deployment(gateway_client, gateway_params):
    
    # here i can safely create a deployment and this will overwrite the past one if existing
    resp = gateway_client.create_deployment(
        restApiId=gateway_params._rest_api_id,
        stageName=gateway_params.deployment_stage
    )

    logging(resp, utils.Colors.GREEN)

    resp = gateway_client.get_stage(
        restApiId=gateway_params._rest_api_id,
        stageName=gateway_params.deployment_stage
    )

    invoke_url = f'https://{gateway_params._rest_api_id}.execute-api.' + \
        f'{session.region_name}.amazonaws.com/{gateway_params.deployment_stage}'

    logging(f'Created API deployment {gateway_params.api_name} under stage {gateway_params.deployment_stage}' + \
                f'\n{utils.Constants.TAB}url: {invoke_url}')
    
    return resp

# create a new function that deploys the api gateway
def deploy_rest_api(gateway_params):
    logging(f'Deploying API Gateway...')

    gateway_client = session.client('apigateway')

    cur_api = __get_api_from_name(gateway_client, gateway_params)

    if not cur_api:
        __create_api_gateway(gateway_client, gateway_params)
    else:
        __update_api_gateway(gateway_client, gateway_params)
    

    __handle_api_gateway_resource_updates(gateway_client, gateway_params)

    # the only reason to handle resource integration updates are if any resource exists in the first
    # place...
    if gateway_params.resources:
        __handle_integration_updates(gateway_client, gateway_params)

    # after setting up all methods and integrations, simply deploy this new version of the api
    try:
        return __handle_api_gateway_deployment(gateway_client, gateway_params)
    except Exception as e:
        logging(e, utils.Colors.RED)

def remove_rest_api(gateway_params: RestAPIGatewayParams):
    gateway_client = session.client('apigateway')
    cur_api = __get_api_from_name(gateway_client, gateway_params)

    if not cur_api:
        logging('Error: api specified for removal does not exist!')
        raise Exception('Specified API does not exist!')
    else:
        # find all the integrations and remove everything associated with 
        # permissions attached to this api.
        # repopulate the api resource data
        __remove_all_associated_gateway_lambda_policies(gateway_client, gateway_params)

        gateway_client.delete_rest_api(restApiId=gateway_params._rest_api_id)