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
from cloudify import constants
from cloudify import utils
from cloudify.decorators import operation
from cloudify.manager import get_rest_client
from cloudify_rest_client import CloudifyClient
from functools import wraps
import hvac
import json
import os


def with_vault(func):
    @wraps(func)
    def f(*args, **kwargs):
        ctx = kwargs['ctx']
        url = ctx.node.properties['client_config']['url']
        root_token = ctx.node.properties['client_config']['token']
        use_api_client_token = ctx.node.properties['client_config'].get(
                'use_api_client_token',
                False
            )

        if use_api_client_token:
            temp_client = hvac.Client(url=url, token=root_token)
            token_policies = ctx.node.properties.get(
                'client_token_policies',
                ['secret']
            )
            create_token_response = temp_client.auth.token.create(
                policies=token_policies,
                ttl='90s',
                renewable=False
            )
            del temp_client
            client_token = create_token_response['auth']['client_token']
            kwargs['vault_client'] = hvac.Client(url=url, token=client_token)
        else:
            kwargs['vault_client'] = hvac.Client(url=url, token=root_token)

        return func(*args, **kwargs)
    return f


def configure_rest_client(
    ctx,
    host=utils.get_manager_rest_service_host(),
    port=utils.get_manager_rest_service_port(),
    protocol=constants.SECURED_PROTOCOL,
    headers={},
    cert=utils.get_local_rest_certificate(),
    username='',
    password='',
    tenant='',
    kerberos_env=utils.get_kerberos_indication(
        os.environ.get(constants.KERBEROS_ENV_KEY)
    ),
):
    if not username and not password:
        return get_rest_client()
    else:
        if isinstance(host, list):
            host = str(host[0])
        if utils.get_is_bypass_maintenance():
            headers['X-BYPASS-MAINTENANCE'] = 'True'
        rest_client = CloudifyClient(
            host=host,
            port=port,
            protocol=protocol,
            headers=headers,
            cert=cert,
            username=username,
            password=password,
            tenant=tenant or utils.get_tenant_name(),
            kerberos_env=kerberos_env,
        )
        return rest_client


def _create_secret(ctx,
                   vault_client,
                   secret_key,
                   secret_value,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username='',
                   executor_password=''):
    if use_external_resource:
        ctx.logger.info('Reading from Vault at key: {}'.format(secret_key))
        read_secret_result = vault_client.secrets.kv.v1.read_secret(
            path=secret_key,
            mount_point=mount_point,
        )
        if create_secret:
            secret_value = json.dumps(read_secret_result['data'])
    else:
        ctx.logger.info('Creating Vault secret: {}'.format(secret_key))
        create_result = vault_client.secrets.kv.v1.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
            mount_point=mount_point,
        )
        ctx.instance.runtime_properties['create_result_status_code'] = \
            create_result.status_code

    if create_secret:
        rest_client = configure_rest_client(ctx=ctx,
                                            username=executor_username,
                                            password=executor_password)
        secret_name = secret_name or secret_key
        ctx.logger.info('Creating local secret: {}'.format(secret_name))
        rest_client.secrets.create(secret_name,
                                   secret_value,
                                   update_if_exists=True,
                                   visibility='tenant',
                                   is_hidden_value=True)
        ctx.instance.runtime_properties[secret_key] = \
            {'secret_name': secret_name}


def _update_secret(ctx,
                   vault_client,
                   secret_key,
                   secret_value,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username='',
                   executor_password=''):
    if use_external_resource:
        ctx.logger.info('Not updating external resource')
    else:
        ctx.logger.info('Updating Vault secret: {}'.format(secret_key))
        update_result = vault_client.secrets.kv.v1.create_or_update_secret(
            path=secret_key,
            secret=secret_value,
            mount_point=mount_point,
        )
        ctx.instance.runtime_properties['create_result'] = update_result

    if create_secret:
        rest_client = configure_rest_client(ctx=ctx,
                                            username=executor_username,
                                            password=executor_password)
        secret_name = secret_name or secret_key
        ctx.logger.info('Updating local secret: {}'.format(secret_name))
        rest_client.secrets.create(secret_name,
                                   secret_value,
                                   update_if_exists=True,
                                   visibility='tenant',
                                   is_hidden_value=True)


def _delete_secret(ctx,
                   vault_client,
                   secret_key,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username='',
                   executor_password=''):
    if use_external_resource:
        ctx.logger.info('Not deleting external resource')
    else:
        ctx.logger.info('Deleting Vault secret: {}'.format(secret_key))
        vault_client.secrets.kv.v1.delete_secret(
            path=secret_key,
            mount_point=mount_point,
        )
    if create_secret:
        rest_client = configure_rest_client(ctx=ctx,
                                            username=executor_username,
                                            password=executor_password)
        secret_name = secret_name or secret_key
        ctx.logger.info('Deleting local secret: {}'.format(secret_name))
        rest_client.secrets.delete(secret_name)


@operation
@with_vault
def create_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_key', '')
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_value', '')
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get(
            'create_secret', False)
    secret_name = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_name', secret_key)
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get(
            'mount_point', 'secret')
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    _create_secret(ctx,
                   vault_client,
                   secret_key,
                   secret_value,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username,
                   executor_password)


@operation
@with_vault
def update_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_key', '')
    secret_value = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_value', {})
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get(
            'create_secret', False)
    secret_name = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_name', secret_key)
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get(
            'mount_point', 'secret')
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    _update_secret(ctx,
                   vault_client,
                   secret_key,
                   secret_value,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username,
                   executor_password)


@operation
@with_vault
def delete_secret(ctx, vault_client, **kwargs):
    secret_key = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_key', '')
    create_secret = \
        ctx.node.properties.get('resource_config', {}).get(
            'create_secret', False)
    secret_name = \
        ctx.node.properties.get('resource_config', {}).get(
            'secret_name', secret_key)
    mount_point = \
        ctx.node.properties.get('resource_config', {}).get(
            'mount_point', 'secret')
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    _delete_secret(ctx,
                   vault_client,
                   secret_key,
                   create_secret,
                   secret_name,
                   mount_point,
                   use_external_resource,
                   executor_username,
                   executor_password)


@operation
@with_vault
def bunch_create_secrets(ctx, vault_client, **kwargs):
    secret_list = \
        ctx.node.properties.get('resource_config', [])
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    for secret in secret_list:
        secret_key = secret.get('secret_key', '')
        secret_value = secret.get('secret_value', '')
        create_secret = secret.get('create_secret', False)
        secret_name = secret.get('secret_name', secret_key)
        mount_point = secret.get('mount_point', 'secret')

        _create_secret(ctx,
                       vault_client,
                       secret_key,
                       secret_value,
                       create_secret,
                       secret_name,
                       mount_point,
                       use_external_resource,
                       executor_username,
                       executor_password)


@operation
@with_vault
def bunch_update_secrets(ctx, vault_client, **kwargs):
    secret_list = \
        ctx.node.properties.get('resource_config', [])
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    for secret in secret_list:
        secret_key = secret.get('secret_key', '')
        secret_value = secret.get('secret_value', '')
        create_secret = secret.get('create_secret', False)
        secret_name = secret.get('secret_name', secret_key)
        mount_point = secret.get('mount_point', 'secret')

        _update_secret(ctx,
                       vault_client,
                       secret_key,
                       secret_value,
                       create_secret,
                       secret_name,
                       mount_point,
                       use_external_resource,
                       executor_username,
                       executor_password)


@operation
@with_vault
def bunch_delete_secrets(ctx, vault_client, **kwargs):
    secret_list = \
        ctx.node.properties.get('resource_config', [])
    executor_username = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'username', '')
    executor_password = \
        ctx.node.properties.get('executor_user_config', {}).get(
            'password', '')
    use_external_resource = \
        ctx.node.properties.get('use_external_resource', False)

    for secret in secret_list:
        secret_key = secret.get('secret_key', '')
        create_secret = secret.get('create_secret', False)
        secret_name = secret.get('secret_name', secret_key)
        mount_point = secret.get('mount_point', 'secret')

        _delete_secret(ctx,
                       vault_client,
                       secret_key,
                       create_secret,
                       secret_name,
                       mount_point,
                       use_external_resource,
                       executor_username,
                       executor_password)
