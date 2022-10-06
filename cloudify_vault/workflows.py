########
# Copyright (c) 2014-2022 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from cloudify.exceptions import NonRecoverableError
from cloudify.manager import get_rest_client


def execute_with_secrets(ctx,
                         workflow_id,
                         workflow_params,
                         workflow_node_ids=None,
                         workflow_node_instance_ids=None,
                         secrets_node_ids=None,
                         secrets_node_instance_ids=None,
                         **kwargs):
    # Prepare the environment
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
    rest_client = get_rest_client()
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
