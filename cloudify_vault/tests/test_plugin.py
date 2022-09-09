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
import copy
import mock
import unittest

from uuid import uuid1

from cloudify.state import current_ctx
from cloudify.mocks import MockCloudifyContext

from cloudify_vault.tasks import (create_secret, update_secret, delete_secret)


create_result = {
    'request_id': '36f91256-f1db-94bc-ce61-d0a58794d152',
    'lease_id': '',
    'renewable': False,
    'lease_duration': 0,
    'data': {
        'created_time': '2022-09-09T08:39:26.237965769Z',
        'custom_metadata': None,
        'deletion_time': '',
        'destroyed': False,
        'version': 1
    },
    'wrap_info': None,
    'warnings': None,
    'auth': None
}

read_result = {
    'request_id': 'cab67af4-7709-e483-7000-71e25f03d442',
    'lease_id': '',
    'renewable': False,
    'lease_duration': 0,
    'data': {
        'data': {
            'value': 'just_for_fun'
        },
        'metadata': {
            'created_time': '2022-09-09T12:21:07.524328847Z',
            'custom_metadata': None,
            'deletion_time': '',
            'destroyed': False, 'version': 1
        }
    },
    'wrap_info': None,
    'warnings': None,
    'auth': None
}


class TestPlugin(unittest.TestCase):

    def setUp(self):
        super(TestPlugin, self).setUp()

    def get_client_conf_props(self):
        return {
            "client_config": {
                "url": "http://127.0.0.1:8200",
                "token": "foobartall"
            }
        }

    def mock_ctx(self,
                 test_name,
                 test_properties,
                 test_runtime_properties=None):
        test_node_id = uuid1()
        ctx = MockCloudifyContext(
                node_id=test_node_id,
                properties=test_properties,
                runtime_properties=test_runtime_properties,
        )
        return ctx

    def test_create_secret(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
            }
        })
        ctx = self.mock_ctx('test_create_secret', node_props)
        current_ctx.set(ctx=ctx)

        mock_create = mock.Mock()
        mock_create.secrets.kv.v2.create_or_update_secret.return_value = \
            create_result
        mock_client = mock.MagicMock(return_value=mock_create)

        with mock.patch('hvac.Client', mock_client):
            kwargs = {
                'ctx': ctx
            }
            create_secret(**kwargs)
            self.assertEqual(
                ctx.instance.runtime_properties['create_result'],
                create_result)

    def test_create_secret_use_external(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
            },
            "use_external_resource": True
        })

        ctx = self.mock_ctx('test_create_secret_use_external', node_props)
        current_ctx.set(ctx=ctx)

        mock_read = mock.Mock()
        mock_read.secrets.kv.v2.read_secret.return_value = \
            read_result
        mock_client = mock.MagicMock(return_value=mock_read)

        with mock.patch('hvac.Client', mock_client):
            kwargs = {
                'ctx': ctx
            }
            create_secret(**kwargs)
            self.assertEqual(
                ctx.instance.runtime_properties['test_secret'],
                read_result['data']['data'])

    def test_create_secret_use_external_create_secret(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
                "create_secret": True,
            },
            "use_external_resource": True,
        })
        ctx = self.mock_ctx('test_create_secret_use_external_create_secret',
                            node_props)
        current_ctx.set(ctx=ctx)

        mock_read = mock.Mock()
        mock_read.secrets.kv.v2.read_secret.return_value = \
            read_result
        mock_client = mock.MagicMock(return_value=mock_read)

        mock_cfy_secrets = mock.Mock()
        mock_cfy_secrets.secrets.create = mock.Mock()
        mock_cfy_client = mock.MagicMock(return_value=mock_cfy_secrets)

        with mock.patch('hvac.Client', mock_client):
            with mock.patch('cloudify_vault.tasks.get_rest_client',
                            mock_cfy_client):
                kwargs = {
                    'ctx': ctx
                }
                create_secret(**kwargs)
                self.assertEqual(
                    ctx.instance.runtime_properties['test_secret'],
                    read_result['data']['data'])
                self.assertTrue(mock_cfy_secrets.secrets.create.called)

    def test_update_secret(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
            }
        })
        node_instance_props = {
            'create_result': create_result
        }

        update_result = copy.deepcopy(create_result)
        update_result['data']['version'] = 2
        ctx = self.mock_ctx('test_update_secret', node_props,
                            node_instance_props)
        current_ctx.set(ctx=ctx)

        mock_update = mock.Mock()
        mock_update.secrets.kv.v2.create_or_update_secret.return_value = \
            update_result
        mock_client = mock.MagicMock(return_value=mock_update)

        with mock.patch('hvac.Client', mock_client):
            kwargs = {
                'ctx': ctx
            }
            update_secret(**kwargs)
            self.assertEqual(
                ctx.instance.runtime_properties['create_result'],
                update_result)

    def test_update_secret_use_external(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
            },
            "use_external_resource": True,
        })
        node_instance_props = {
            'create_result': create_result
        }

        update_result = copy.deepcopy(create_result)
        update_result['data']['version'] = 2
        ctx = self.mock_ctx('test_update_secret_use_external', node_props,
                            node_instance_props)
        current_ctx.set(ctx=ctx)

        mock_update = mock.Mock()
        mock_update.secrets.kv.v2.create_or_update_secret.return_value = \
            update_result
        mock_client = mock.MagicMock(return_value=mock_update)

        with mock.patch('hvac.Client', mock_client):
            kwargs = {
                'ctx': ctx
            }
            update_secret(**kwargs)
            self.assertFalse(mock_update.secrets.kv.v2.
                             create_or_update_secret.called)

    def test_delete_secret(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
            }
        })
        ctx = self.mock_ctx('test_delete_secret', node_props)
        current_ctx.set(ctx=ctx)

        delete_mock = mock.Mock()
        delete_mock.secrets.kv.v2.delete_metadata_and_all_versions = \
            mock.Mock()
        mock_client = mock.MagicMock(return_value=delete_mock)

        with mock.patch('hvac.Client', mock_client):
            kwargs = {
                'ctx': ctx
            }
            delete_secret(**kwargs)
            self.assertTrue(delete_mock.secrets.kv.v2.
                            delete_metadata_and_all_versions.called)

    def test_delete_secret_use_external(self):
        node_props = self.get_client_conf_props()
        node_props.update({
            "resource_config": {
                "secret_key": "test_secret",
                "secret_value": {"value": "super_secret_value"},
                "create_secret": True,
            },
            "use_external_resource": True,
        })
        ctx = self.mock_ctx('test_delete_secret_use_external', node_props)
        current_ctx.set(ctx=ctx)

        delete_mock = mock.Mock()
        delete_mock.secrets.kv.v2.delete_metadata_and_all_versions = \
            mock.Mock()
        mock_client = mock.MagicMock(return_value=delete_mock)

        mock_cfy_secrets = mock.Mock()
        mock_cfy_secrets.secrets.delete = mock.Mock()
        mock_cfy_client = mock.MagicMock(return_value=mock_cfy_secrets)

        with mock.patch('hvac.Client', mock_client):
            with mock.patch('cloudify_vault.tasks.get_rest_client',
                            mock_cfy_client):
                kwargs = {
                    'ctx': ctx
                }
                delete_secret(**kwargs)
                self.assertFalse(delete_mock.secrets.kv.v2.
                                 delete_metadata_and_all_versions.called)
                self.assertTrue(mock_cfy_secrets.secrets.delete.called)
