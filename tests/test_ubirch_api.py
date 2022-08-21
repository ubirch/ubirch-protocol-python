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

import json, msgpack
from json import JSONDecodeError
import logging
import uuid
import base64

import unittest
import requests, requests_mock

import ubirch
from ubirch.ubirch_api import KEY_SERVICE, NIOMON_SERVICE, VERIFICATION_SERVICE

logger = logging.getLogger(__name__)

# Test fixtures
TEST_ENV_KEY_SERVICE = "https://identity.{}.ubirch.com/api/keyService/v1/pubkey"
TEST_ENV_NIOMON_SERVICE = "https://niomon.{}.ubirch.com/"
TEST_ENV_VERIFIER_SERVICE = "https://verify.{}.ubirch.com/api/upp"

TEST_UUID_STRING = "4d9d5bfd-37c1-48ff-ad67-cb0385f3b7f5"
TEST_UUID = uuid.UUID(TEST_UUID_STRING)
TEST_AUTH = "95DC841D-8E30-4DEC-B67F-563EEE7277D6"

RESPONSE_IDENTITY_IS_REGISTERED = [{'pubKeyInfo': {'algorithm': 'ECC_ED25519', 'created': '2022-06-28T13:55:33.000Z', 'hwDeviceId': '4d9d5bfd-37c1-48ff-ad67-cb0385f3b7f5', 'pubKey': 'MtQF1vT4rjVAxxom/tdtqxDGEwTRDb/krZtDDW3E7nM=', 'pubKeyId': 'MtQF1vT4rjVAxxom/tdtqxDGEwTRDb/krZtDDW3E7nM=', 'validNotAfter': '2032-06-25T13:55:33.000Z', 'validNotBefore': '2022-06-28T13:55:33.000Z'}, 'signature': 'df78343c3d4e04e60aa99806ca3372cfd6bc90c6d695cb61b614ffd2f9790bfac59992ead6941cbc87a33bd9d86d4e346004ce8c9898bbe8c193fcc3edf69e0e'}]
RESPONSE_IDENTITY_NOT_REGISTERED = []

# TODO this test class needs some more functional tests
class TestUbirchAPI(unittest.TestCase):

    def test_create_api_with_env(self):
        api = ubirch.API(env='demo')

        self.assertEqual(TEST_ENV_KEY_SERVICE.format("demo"), api.get_url(KEY_SERVICE))
        self.assertEqual(TEST_ENV_NIOMON_SERVICE.format("demo"), api.get_url(NIOMON_SERVICE))
        self.assertEqual(TEST_ENV_VERIFIER_SERVICE.format("demo"), api.get_url(VERIFICATION_SERVICE))

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
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, json=RESPONSE_IDENTITY_IS_REGISTERED)
        is_registered_response = ubirch.API().is_identity_registered(TEST_UUID)
        self.assertTrue(is_registered_response)
        self.assertEqual(TEST_UUID_STRING, is_registered_response[0]['pubKeyInfo']['hwDeviceId'])

    @requests_mock.mock()
    def test_is_identity_registered_fails(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, json=RESPONSE_IDENTITY_NOT_REGISTERED)
        self.assertFalse(ubirch.API().is_identity_registered(uuid.uuid4()))

    @requests_mock.mock()
    def test_register_identity_json(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().register_identity(str.encode(json.dumps({}))))

    @requests_mock.mock()
    def test_register_identity_json_fails(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{}', status_code='403')
        self.assertEqual('403', ubirch.API().register_identity(str.encode(json.dumps({}))).status_code)

    @requests_mock.mock()
    def test_register_identity_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().register_identity(msgpack.packb([1, 2, 3])))

    @requests_mock.mock()
    def test_register_identity_msgpack_fails(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{}', status_code='403')
        self.assertEqual('403', ubirch.API().register_identity(msgpack.packb([1, 2, 3])).status_code)

    @requests_mock.mock()
    def test_deregister_identity_json(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().deregister_identity(str.encode(json.dumps({}))))

    @unittest.expectedFailure
    @requests_mock.mock()
    def test_deregister_identity_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().deregister_identity(msgpack.packb([1, 2, 3])))

    @requests_mock.mock()
    def test_send_json(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().send(TEST_UUID, str.encode(json.dumps({}))))

    @requests_mock.mock()
    def test_send_json_fails(self, mock):
        pass

    @requests_mock.mock()
    def test_send_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().send(TEST_UUID, msgpack.packb([1,2,3])))

    @requests_mock.mock()
    def test_send_msgpack_fails(self, mock):
        pass

    @requests_mock.mock()
    def test_auth_headers_set_json(self, mock): # testing set_authentication() and _update_authentication() methods
        def check_headers_callback(request, context):
            headers = request.headers
            self.assertEqual(headers['Content-Type'], 'application/json')
            self.assertEqual(headers['X-Ubirch-Hardware-Id'], TEST_UUID_STRING)
            self.assertEqual(headers['X-Ubirch-Credential'], base64.b64encode(TEST_AUTH.encode()).decode())
            self.assertEqual(headers['X-Ubirch-Auth-Type'], 'ubirch')

        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text=check_headers_callback)

        api = ubirch.API(env='demo')
        api.set_authentication(TEST_UUID, TEST_AUTH)
        api.send(TEST_UUID, str.encode(json.dumps({'message': 'test'})))

    @requests_mock.mock()
    def test_headers_set_msgpack(self, mock):
        def check_headers_callback(request, context):
            headers = request.headers
            self.assertEqual(headers['Content-Type'], 'application/json')
            self.assertEqual(headers['X-Ubirch-Hardware-Id'], TEST_UUID_STRING)
            self.assertEqual(headers['X-Ubirch-Credential'], base64.b64encode(TEST_AUTH.encode()).decode())
            self.assertEqual(headers['X-Ubirch-Auth-Type'], 'ubirch')

        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text=check_headers_callback)

        api = ubirch.API(env='demo')
        api.set_authentication(TEST_UUID, TEST_AUTH)
        api.send(TEST_UUID, b'{"message": "test"}')