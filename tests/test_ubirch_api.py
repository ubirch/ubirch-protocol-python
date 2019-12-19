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

import msgpack
import requests_mock

import ubirch
from ubirch.ubirch_api import KEY_SERVICE, NIOMON_SERVICE, VERIFICATION_SERVICE

logger = logging.getLogger(__name__)

# test fixtures
TEST_ENV_KEY_SERVICE = "https://key.{}.ubirch.com/api/keyService/v1/pubkey"
TEST_ENV_NIOMON_SERVICE = "https://niomon.{}.ubirch.com/"
TEST_ENV_VERIFIER_SERVICE = "https://verify.{}.ubirch.com/api/upp"

TEST_UUID = uuid.UUID("ecdf0d5c-ddcf-4511-bb71-41219a4fe6d4")


# TODO this test class needs some more functional tests
class TestUbirchAPI(unittest.TestCase):

    def test_create_api_with_env(self):
        api = ubirch.API(env='test')

        self.assertEqual(TEST_ENV_KEY_SERVICE.format("test"), api.get_url(KEY_SERVICE))
        self.assertEqual(TEST_ENV_NIOMON_SERVICE.format("test"), api.get_url(NIOMON_SERVICE))
        self.assertEqual(TEST_ENV_VERIFIER_SERVICE.format("test"), api.get_url(VERIFICATION_SERVICE))

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
    def test_send_msgpack(self, mock):
        mock.register_uri(requests_mock.ANY, requests_mock.ANY, text='{"result":"OK"}')
        self.assertTrue(ubirch.API().send(TEST_UUID, msgpack.packb([1,2,3])))
