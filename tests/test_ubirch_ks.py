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
from os import urandom
import unittest
import uuid
from datetime import datetime
import ecdsa, ed25519, hashlib
from uuid import UUID

import ubirch

logger = logging.getLogger(__name__)

# test fixtures
TEST_KEYSTORE_FILE = "__test.jks"
TEST_LOAD_KEYSTORE_FILE = "test_load_keystore.jks"
TEST_LOAD_KEYSTORE_UUID = UUID(hex="02012531-60A5-412C-A36B-65720C1F4C10")
TEST_PASSWORD = "abcdef12345"


class TestUbirchKeyStore(unittest.TestCase):

    def test_create_keystore(self):
        self.assertIsInstance(ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD), ubirch.KeyStore)

    def test_keystore_is_saved(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        ks.create_ed25519_keypair(uuid.uuid4())
        self.assertTrue(os.path.isfile(TEST_KEYSTORE_FILE), "KeyStore has not been saved")
        os.remove(TEST_KEYSTORE_FILE)

    def test_load_keystore(self):
        """
        load a keystore saved in the tests folder.
        If called from outside of folder `tests/` try to find it inside `tests/`
        """
        local_test_load_kestore_file = TEST_LOAD_KEYSTORE_FILE
        # Has to be reinitialized to not change global fixtures

        if not os.path.exists(TEST_LOAD_KEYSTORE_FILE):
            local_test_load_kestore_file = "tests/" + local_test_load_kestore_file

        if os.path.exists(local_test_load_kestore_file):
            ks_load = ubirch.KeyStore(local_test_load_kestore_file, TEST_PASSWORD)
            self.assertIsInstance(ks_load, ubirch.KeyStore, "Keystore could not be loaded")
            self.assertIsNotNone(ks_load.get_certificate(TEST_LOAD_KEYSTORE_UUID), "Certificate could not be loaded. This can be caused by running the test from a wrong path.")

    def test_create_save_load_keystore(self):
        test_uuid = uuid.uuid4()
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        ks.create_ed25519_keypair(test_uuid)

        ks_load = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        self.assertIsInstance(ks_load, ubirch.KeyStore, "Keystore could not be loaded")
        os.remove(TEST_KEYSTORE_FILE)


    def test_insert_key_wrong_type_fails(self):
        """
        Give ed25519 keys to ecdsa functions and vice versa.
        Assert that a TypeError is raised with a message complaining about the wrong type
        """
        ks = ubirch.KeyStore(TEST_LOAD_KEYSTORE_FILE, TEST_PASSWORD)
        sk_ed25519, \
        vk_ed25519 = ed25519.create_keypair(entropy=urandom)

        sk_ecdsa = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, entropy=urandom, hashfunc=hashlib.sha256)
        vk_ecdsa = sk_ecdsa.get_verifying_key()

        with self.assertRaises(TypeError) as context:
            ks.insert_ed25519_keypair(uuid.uuid4(), sk_ecdsa, vk_ecdsa)
            self.assertIn(context.exception.args[0], "key provided is not a ")

        with self.assertRaises(TypeError) as context:
            ks.insert_ecdsa_keypair(uuid.uuid4(), sk_ed25519, vk_ed25519)
            self.assertIn(context.exception.args[0], "key provided is not a ")

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
