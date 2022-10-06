from cloudify.exceptions import NonRecoverableError
from cloudify.manager import get_rest_client


def _get_secret_names(ctx, node_ids=None, node_instance_ids=None):
    secret_names = []
    if node_instance_ids:
        for instance in ctx.node_instances:
            if instance.id in node_instance_ids:
                secret_names.extend(
                    list(instance.runtime_properties.get('local_secrets',
                                                         {}).values()))
    elif node_ids:
        for node in ctx.nodes:
            if node.id in node_ids:
                for instance in node.instances:
                    secret_names.extend(
                        list(instance.runtime_properties.get('local_secrets',
                                                             {}).values()))
    return secret_names


def execute_with_secrets(ctx,
                         workflow_id,
                         workflow_params,
                         workflow_node_ids=None,
                         workflow_node_instance_ids=None,
                         secrets_node_ids=None,
                         secrets_node_instance_ids=None,
                         **kwargs):
    # Prepare the environment
    rest_client = get_rest_client()

    parameters = {}
    if secrets_node_ids and secrets_node_instance_ids:
        raise NonRecoverableError(
            'Parameters \'secrets_node_ids\' and '
            '\'secrets_node_instance_ids\' are mutually exclusive. '
            'Node IDs: {} and node instance IDs: {} provided.'.format(
                secrets_node_ids, secrets_node_instance_ids
            )
        )
    if secrets_node_instance_ids:
        parameters['node_instance_ids'] = secrets_node_instance_ids
    elif secrets_node_ids:
        parameters['node_ids'] = secrets_node_ids
    else:
        raise NonRecoverableError(
            'Both workflow parameters: \'secrets_node_ids\' and '
            '\'secrets_node_instance_ids\' are empty.'
        )

    # Schedule the removal of secrets
    delete_parameters = parameters
    delete_parameters['operation'] = 'cloudify.interfaces.vault.delete'
    rest_client.executions.start(
        deployment_id=ctx.deployment.id,
        workflow_id='execute_operation',
        queue=True,
        parameters=delete_parameters,
    )

    # Obtain and save secrets
    secrets_graph = ctx.graph_mode()
    secrets_sequence = secrets_graph.sequence()
    if secrets_node_instance_ids:
        for instance in ctx.node_instances:
            if instance.id in secrets_node_instance_ids:
                secrets_sequence.add(
                    instance.execute_operation(
                        operation='cloudify.interfaces.lifecycle.start'))
    elif secrets_node_ids:
        for node in ctx.nodes:
            if node.id in secrets_node_ids:
                for instance in node.instances:
                    secrets_sequence.add(
                        instance.execute_operation(
                            operation='cloudify.interfaces.lifecycle.start'))
    secrets_graph.execute()


    # Execute target workflow on deployment
    if not workflow_params.get('secret_names', None):
        workflow_params['secret_names'] = _get_secret_names(
            ctx,
            secrets_node_ids,
            secrets_node_instance_ids,
        )
    if workflow_node_ids and workflow_node_instance_ids:
        raise NonRecoverableError(
            'Parameters \'workflow_node_ids\' and '
            '\'workflow_node_instance_ids\' are mutually exclusive. '
            'Node IDs: {} and node instance IDs: {} provided.'.format(
                workflow_node_ids, workflow_node_instance_ids
            )
        )

    workflow_graph = ctx.graph_mode()
    workflow_sequence = workflow_graph.sequence()
    if workflow_node_instance_ids:
        for instance in ctx.node_instances:
            if instance.id in workflow_node_instance_ids:
                workflow_sequence.add(
                    instance.execute_operation(
                        operation='cloudify.interfaces.lifecycle.start',
                        allow_kwargs_override=True,
                        kwargs={
                            'workflow_id': workflow_id,
                            'resource_config': {
                                'executions_start_args': {
                                    'allow_custom_parameters': True,
                                    'parameters': workflow_params,
                                }
                            }
                        },
                    )
                )
    elif workflow_node_ids:
        for node in ctx.nodes:
            if node.id in workflow_node_ids:
                for instance in node.instances:
                    workflow_sequence.add(
                        instance.execute_operation(
                            operation='cloudify.interfaces.lifecycle.start',
                            allow_kwargs_override=True,
                            kwargs={
                                'workflow_id': workflow_id,
                                'resource_config': {
                                    'executions_start_args': {
                                        'allow_custom_parameters': True,
                                        'parameters': workflow_params,
                                    }
                                }
                            },
                        )
                    )
    else:
        for node in ctx.nodes:
            if 'cloudify.nodes.Component' not in node.type_hierarchy:
                continue
            for instance in node.instances:
                workflow_sequence.add(
                    instance.execute_operation(
                        operation='cloudify.interfaces.lifecycle.start',
                        allow_kwargs_override=True,
                        kwargs={
                            'workflow_id': workflow_id,
                            'resource_config': {
                                'executions_start_args': {
                                    'allow_custom_parameters': True,
                                    'parameters': workflow_params,
                                }
                            }
                        },
                    )
                )
    workflow_graph.execute()
