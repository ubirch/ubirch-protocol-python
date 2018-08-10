# ubirch key store tests
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

import logging
import os
import unittest
import uuid
from datetime import datetime

import ubirch

logger = logging.getLogger(__name__)

# test fixtures
TEST_KEYSTORE_FILE = "__test.jks"
TEST_PASSWORD = "abcdef12345"


class TestUbirchKeyStore(unittest.TestCase):

    def test_create_keystore(self):
        self.assertIsInstance(ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD), ubirch.KeyStore)

    def test_keystore_is_saved(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        ks.create_ed25519_keypair(uuid.uuid4())
        self.assertTrue(os.path.isfile(TEST_KEYSTORE_FILE), "KeyStore has not been saved")
        os.remove(TEST_KEYSTORE_FILE)

    def test_create_new_keypair(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ed25519_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))

    def test_do_not_create_duplicate(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        (vk, sk) = ks.create_ed25519_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))

        try:
            ks.create_ed25519_keypair(id)
        except Exception as e:
            self.assertEqual(e.args[0], "uuid '{}' already exists in keystore".format(id.hex))

        # check again that the keus have not changed
        self.assertEqual(vk, ks.find_verifying_key(id))
        self.assertEqual(sk, ks.find_signing_key(id))

    def test_exists_signing_key(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ed25519_keypair(id)
        self.assertTrue(ks.exists_signing_key(id))

    def test_exists_signing_key_fails(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        self.assertFalse(ks.exists_signing_key(id))

    def test_exists_verifying_key(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ed25519_keypair(id)
        self.assertTrue(ks.exists_verifying_key(id))

    def test_exists_verifying_key_fails(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        self.assertFalse(ks.exists_verifying_key(id))

    def test_get_certificate(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        (vk, sk) = ks.create_ed25519_keypair(id)
        certificate = ks.get_certificate(id)
        self.assertIsNotNone(certificate)
        self.assertEqual( "ECC_ED25519", certificate["algorithm"])
        self.assertEqual( id.bytes, certificate["hwDeviceId"])
        self.assertEqual(vk.to_bytes(), certificate["pubKey"])
        self.assertEqual(vk.to_bytes(), certificate["pubKeyId"])
        self.assertGreaterEqual(int(datetime.utcnow().timestamp()), certificate["validNotBefore"])
        self.assertLessEqual(int(datetime.utcnow().timestamp()), certificate["validNotAfter"])

    def test_get_certificate_fails(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        self.assertIsNone(ks.get_certificate(id))
