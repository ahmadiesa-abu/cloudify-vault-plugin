from cloudify.manager import get_rest_client
import hvac
import json
import uuid


def _configure_vault_client(rest_client):
    vault_url = rest_client.secrets.get('vault_url').get('value', '')
    vault_token = rest_client.secrets.get('vault_token').get('value', '')
    return hvac.Client(url=vault_url, token=vault_token)


def _read_and_save_secrets(ctx,
                           rest_client,
                           vault_client,
                           secret_list,
                           secrets_suffix):
    for secret in secret_list:
        assert isinstance(secret, dict), \
            'List elements have to be objects with \'secret_key\' defined'
        assert 'secret_key' in secret, 'Key \'secret_key\' must be included'

        secret_key = secret.get('secret_key', '')
        mount_point = secret.get('mount_point', 'secret')
        secret_name = secret_key + '-' + secrets_suffix

        ctx.logger.info('Reading from Vault at key: {}'.format(secret_key))
        read_secret_result = vault_client.secrets.kv.v1.read_secret(
            path=secret_key,
            mount_point=mount_point,
        )
        secret_value = json.dumps(read_secret_result['data'])
        ctx.logger.info('Creating local secret: {}'.format(secret_name))
        rest_client.secrets.create(secret_name,
                                   secret_value,
                                   update_if_exists=True)


def execute_with_secrets(ctx,
                         workflow_id,
                         target_deployment_id,
                         secret_list,
                         node_ids,
                         node_instance_ids,
                         **kwargs):
    rest_client = get_rest_client()
    vault_client = _configure_vault_client(rest_client)
    secrets_suffix = str(uuid.uuid4())

    # Schedule the removal of secrets
    secret_names = [secret.get('secret_key', '') + '-' + secrets_suffix
                    for secret in secret_list]
    rest_client.executions.start(
        deployment_id=ctx.deployment.id,
        workflow_id='remove_local_secrets',
        queue=True,
        parameters={
            'secret_list': secret_names,
        },
    )

    # Obtain and save secrets
    _read_and_save_secrets(ctx,
                           rest_client,
                           vault_client,
                           secret_list,
                           secrets_suffix)

    # Execute target workflow on deployment
    rest_client.executions.start(
        deployment_id=target_deployment_id,
        workflow_id=workflow_id,
        parameters={
            'node_ids': node_ids,
            'node_instance_ids': node_instance_ids,
            **kwargs,
        }
    )


def remove_local_secrets(ctx, secret_list, **kwargs):
    rest_client = get_rest_client()
    assert isinstance(secret_list, list)

    if not secret_list:
        ctx.logger.info('Empty list of secrets to delete')
        return

    for secret_name in secret_list:
        assert isinstance(secret_name, str)
        ctx.logger.info('Deleting local secret: {}'.format(secret_name))
        rest_client.secrets.delete(secret_name)
