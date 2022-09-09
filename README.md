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
    type: cloudify.nodes.vault.secret
    properties:
      client_config: *vault_config
      resource_config:
        secret_key: {get_input: secret_key}
        secret_value: {get_input: secret_value}

```

## Tests

To run the example plugin tests, the included `dev-requirements.txt` should be installed.

```
pip install -r dev-requirements.txt
```
