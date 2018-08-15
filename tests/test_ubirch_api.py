# ubirch API tests
#
# @author Matthias L. Jugel
#
# Copyright (c) 2018 ubirch GmbH.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import unittest
import uuid
from json import JSONDecodeError
from ubirch.ubirch_api import KEY_SERVICE, AVATAR_SERVICE, CHAIN_SERVICE, NOTARY_SERVICE

import msgpack
import requests_mock

import ubirch

logger = logging.getLogger(__name__)

# test fixtures
TEST_LOCAL_KEY_SERVICE = "http://localhost:8095/api/keyService/v1"
TEST_LOCAL_AVATAR_SERVICE = "http://localhost:8080/api/avatarService/v1"
TEST_LOCAL_CHAIN_SERVICE = "http://localhost:8097/api/v1/chainService"
TEST_LOCAL_NOTARY_SERVICE = "https://localhost:8098/api/v1/notaryService"
TEST_ENV_KEY_SERVICE = "https://key.{}.ubirch.com/api/keyService/v1"
TEST_ENV_AVATAR_SERVICE = "https://api.ubirch.{}.ubirch.com/api/avatarService/v1"
TEST_ENV_CHAIN_SERVICE = "https://api.ubirch.{}.ubirch.com/api/v1/chainService"
TEST_ENV_NOTARY_SERVICE = "http://n.dev.ubirch.com:8080/v1/notaryService"

# TODO this test class needs some more functional tests
class TestUbirchAPI(unittest.TestCase):

    def test_create_api_defaults(self):
        api = ubirch.API()

        self.assertEqual(TEST_LOCAL_KEY_SERVICE, api.get_url(KEY_SERVICE))
        self.assertEqual(TEST_LOCAL_AVATAR_SERVICE, api.get_url(AVATAR_SERVICE))
        self.assertEqual(TEST_LOCAL_CHAIN_SERVICE, api.get_url(CHAIN_SERVICE))
        self.assertEqual(TEST_LOCAL_NOTARY_SERVICE, api.get_url(NOTARY_SERVICE))
        self.assertDictEqual({}, api._auth)

    def test_create_api_with_auth(self):
        AUTH_TOKEN = "ABC:TOKEN:DEF"
        api = ubirch.API(auth=AUTH_TOKEN)

        self.assertEqual(TEST_LOCAL_KEY_SERVICE, api.get_url(KEY_SERVICE))
        self.assertEqual(TEST_LOCAL_AVATAR_SERVICE, api.get_url(AVATAR_SERVICE))
        self.assertEqual(TEST_LOCAL_CHAIN_SERVICE, api.get_url(CHAIN_SERVICE))
        self.assertEqual(TEST_LOCAL_NOTARY_SERVICE, api.get_url(NOTARY_SERVICE))
        self.assertDictEqual({'Authorization': AUTH_TOKEN}, api._auth)

    def test_create_api_with_env(self):
        api = ubirch.API(env='test')

        self.assertEqual(TEST_ENV_KEY_SERVICE.format("test"), api.get_url(KEY_SERVICE))
        self.assertEqual(TEST_ENV_AVATAR_SERVICE.format("test"), api.get_url(AVATAR_SERVICE))
        self.assertEqual(TEST_ENV_CHAIN_SERVICE.format("test"), api.get_url(CHAIN_SERVICE))
        self.assertEqual(TEST_ENV_NOTARY_SERVICE.format("test"), api.get_url(NOTARY_SERVICE))

    def test_create_api_with_debug(self):
        import http.client as http_client

        # prepare the logging level
        logger = logging.getLogger(ubirch.ubirch_api.__name__)
        orig_level = logger.level
        logger.setLevel(logging.DEBUG)

        ubirch.API(debug=True)
        self.assertEqual(http_client.HTTPConnection.debuglevel, 1)
        urllib_logger = logging.getLogger("requests.packages.urllib3")
        self.assertEqual(urllib_logger.level, logging.DEBUG)
        self.assertEqual(urllib_logger.propagate, True)

        # reset logging level
        logger.setLevel(orig_level)

    @requests_mock.mock()
    def test_is_identity_registered(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().is_identity_registered(uuid.uuid4()))

    @requests_mock.mock()
    def test_is_identity_registered_fails(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='')
        try:
            self.assertFalse(ubirch.API().is_identity_registered(uuid.uuid4()))
        except JSONDecodeError as e:
            pass

    @requests_mock.mock()
    def test_register_identity_json(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().register_identity(str.encode(json.dumps({}))))

    @requests_mock.mock()
    def test_register_identity_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().register_identity(msgpack.packb([1, 2, 3])))

    @requests_mock.mock()
    def test_device_exists(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().device_exists(uuid.uuid4()))

    @requests_mock.mock()
    def test_device_delete(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().device_delete(uuid.uuid4()))

    @requests_mock.mock()
    def test_device_create(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().device_create({}))

    @requests_mock.mock()
    def test_send_json(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().send(str.encode(json.dumps({}))))

    @requests_mock.mock()
    def test_send_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().send(msgpack.packb([1,2,3])))

    @requests_mock.mock()
    def test_anchor(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().anchor(b'This is a Test'))