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
import json
import hvac
from cloudify.decorators import operation
from cloudify.manager import get_rest_client
from functools import wraps


def with_vault(func):
    @wraps(func)
    def f(*args, **kwargs):
        ctx = kwargs['ctx']
        url = ctx.node.properties['client_config']['url']
        token = ctx.node.properties['client_config']['token']
        kwargs['vault_client'] = hvac.Client(url=url, token=token)
        return func(*args, **kwargs)
    return f


@operation
@with_vault
def create_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get('secret_key', '')
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get('secret_value', '')
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get('create_secret', '')
    secret_name = \
        ctx.node.properties.get('resource_config', {}).get('secret_name', secret_key)
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get('mount_point', 'secret')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    if use_external_resource:
        read_secret_result = vault_client.secrets.kv.v1.read_secret(
            path=secret_key,
            mount_point=mount_point,
        )
        if create_secret:
            rest_client = get_rest_client()
            secret_to_store = json.dumps(read_secret_result['data'])
            secret_name = secret_name or secret_key
            rest_client.secrets.create(secret_name,
                                       secret_to_store,
                                       update_if_exists=True)
            ctx.instance.runtime_properties[secret_key] = \
                {'secret_name': secret_name}

    else:
        create_result = vault_client.secrets.kv.v1.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
            mount_point=mount_point,
        )
        ctx.instance.runtime_properties['create_result_status_code'] = create_result.status_code
        if create_secret:
            rest_client = get_rest_client()
            secret_name = secret_name or secret_key
            rest_client.secrets.create(secret_name,
                                       secret_value,
                                       update_if_exists=True)


@operation
@with_vault
def update_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get('secret_key', '')
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get('secret_value', {})
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get('mount_point', 'secret')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    if use_external_resource:
        ctx.logger.info('Not updating external resource')
    else:
        update_result = vault_client.secrets.kv.v1.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
            mount_point=mount_point,
        )
        ctx.instance.runtime_properties['create_result'] = update_result


@operation
@with_vault
def delete_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get('secret_key', '')
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get('create_secret', '')
    secret_name = \
        ctx.node.properties.get('resource_config', {}).get('secret_name', secret_key)
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get('mount_point', 'secret')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    if use_external_resource:
        ctx.logger.info('Not deleting external resource')
        if create_secret:
            rest_client = get_rest_client()
            secret_name = secret_name or secret_key
            rest_client.secrets.delete(secret_name)
    else:
        vault_client.secrets.kv.v1.delete_secret(
            path=secret_key,
            mount_point=mount_point,
        )


@operation
@with_vault
def bunch_create_secrets(ctx, vault_client, **kwargs):
    secret_list = \
        ctx.node.properties.get('resource_config', {})
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)
    for secret in secret_list:
        secret_key = secret.get('secret_key', '')
        secret_value = secret.get('secret_value', '')
        create_secret = secret.get('create_secret', '')
        secret_name = secret.get('secret_name', secret_key)
        mount_point = secret.get('mount_point', 'secret')

        if use_external_resource:
            read_secret_result = vault_client.secrets.kv.v1.read_secret(
                path=secret_key,
                mount_point=mount_point,
            )
            if create_secret:
                rest_client = get_rest_client()
                secret_to_store = json.dumps(read_secret_result['data'])
                secret_name = secret_name or secret_key
                rest_client.secrets.create(secret_name,
                                        secret_to_store,
                                        update_if_exists=True)
                ctx.instance.runtime_properties[secret_key] = \
                    {'secret_name': secret_name}

        else:
            create_result = vault_client.secrets.kv.v1.create_or_update_secret(
                path=secret_key,
                secret=secret_value,
                mount_point=mount_point,
            )
            ctx.instance.runtime_properties['create_result_status_code'] = create_result.status_code
            if create_secret:
                rest_client = get_rest_client()
                secret_name = secret_name or secret_key
                rest_client.secrets.create(secret_name,
                                        secret_value,
                                        update_if_exists=True)


@operation
@with_vault
def bunch_delete_secrets(ctx, vault_client, **kwargs):
    secret_list = \
        ctx.node.properties.get('resource_config', {})
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)
    if use_external_resource:
        ctx.logger.info('Not deleting external resource')
    for secret in secret_list:
        secret_key = secret.get('secret_key', '')
        create_secret = secret.get('create_secret', '')
        secret_name = secret.get('secret_name', secret_key)
        mount_point = secret.get('mount_point', 'secret')

        if create_secret:
            rest_client = get_rest_client()
            secret_name = secret_name or secret_key
            rest_client.secrets.delete(secret_name)
        if not use_external_resource:
            vault_client.secrets.kv.v1.delete_secret(
                path=secret_key,
                mount_point=mount_point,
            )
