# Cloudify Vault Plugin
========================

This plugin provides the following functionality:

* Create Vault Secret.
* Read Vault Secret.
* Update Vault Secret.
* Delete Vault Secret.

## Usage

```yaml

dsl_definitions:

  vault_config: &vault_config
    url: 'http://127.0.0.1:8200'
    token: 'superdupertoken'


node_templates:
  my_secret:
    type: cloudify.nodes.vault.Secret
    properties:
      client_config: *vault_config
      resource_config:
        secret_key: {get_input: secret_key}
        secret_value: {get_input: secret_value}

  my_secrets:
    type: cloudify.nodes.vault.Bunch_secrets
    properties:
      client_config: *vault_config
      use_external_resource: true
      resource_config:
        - secret_key: hello2
          create_secret: true
        - secret_key: hello3
          create_secret: true
          secret_name: hello3_secret
```

## Tests

To run the example plugin tests, the included `dev-requirements.txt` should be installed.

```
pip install -r dev-requirements.txt
```
