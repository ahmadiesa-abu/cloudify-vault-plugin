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

from functools import wraps

from cloudify.decorators import operation
from cloudify.manager import get_rest_client


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
        ctx.node.properties.get('resource_config', {}).get('secret_key', "")
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get('secret_value', "")
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get('create_secret', "")
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    if use_external_resource:
        read_secret_result = vault_client.secrets.kv.v2.read_secret(
            path=secret_key,
        )
        ctx.instance.runtime_properties[secret_key] = \
            read_secret_result['data']['data']

        if create_secret:
            rest_client = get_rest_client()
            secret_to_store = json.dumps(read_secret_result['data']['data'])
            rest_client.secrets.create(secret_key, secret_to_store,
                                       update_if_exists=True)
    else:
        create_result = vault_client.secrets.kv.v2.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
        )
        ctx.instance.runtime_properties['create_result'] = create_result


@operation
@with_vault
def update_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get('secret_key', "")
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get('secret_value', {})
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    if use_external_resource:
        ctx.logger.info('not updating external resource')
    else:
        update_result = vault_client.secrets.kv.v2.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
        )
        ctx.instance.runtime_properties['create_result'] = update_result


@operation
@with_vault
def delete_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get('secret_key', "")
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get('create_secret', "")

    if use_external_resource:
        ctx.logger.info('not deleting external resource')
        if create_secret:
            rest_client = get_rest_client()
            rest_client.secrets.delete(secret_key)
    else:
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=secret_key,
        )
