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
import binascii
import ecdsa 
import hashlib


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

    def test_create_new_keypair_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ecdsa_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))

    def test_create_new_keypair_ecdsa_wrong_curve(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        try:
            ks.create_ecdsa_keypair(uuid=id, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256),
        except Exception as e:
            self.assertEqual(e.args[0], "Curve not supported! Currently only supports [ecdsa.NIST256p]")

        self.assertIsNone(ks.find_verifying_key(id))
        self.assertIsNone(ks.find_signing_key(id))

    def test_create_new_keypair_ecdsa_wrong_hashfunc(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        try:
            ks.create_ecdsa_keypair(uuid=id, curve=ecdsa.NIST256p, hashfunc=hashlib.sha512),
        except Exception as e:
            self.assertEqual(e.args[0], "Hashing algorithm not supported! Currently only supports [hashlib.sha256]")

        self.assertIsNone(ks.find_verifying_key(id))
        self.assertIsNone(ks.find_signing_key(id))

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

    def test_do_not_create_duplicate_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        (vk, sk) = ks.create_ecdsa_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))
       
        try:
            ks.create_ecdsa_keypair(id)
        except Exception as e:
            self.assertEqual(e.args[0], "uuid '{}' already exists in keystore".format(id.hex))

        # get the original keys
        vk_orig = ks.find_verifying_key(id)
        sk_orig = ks.find_signing_key(id)
        # check again that the keys have not changed
        self.assertEqual(binascii.hexlify(vk.to_string()), binascii.hexlify(vk_orig.to_string()))
        self.assertEqual(binascii.hexlify(sk.to_string()), binascii.hexlify(sk_orig.to_string()))

    def test_exists_signing_key(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ed25519_keypair(id)
        self.assertTrue(ks.exists_signing_key(id))

    def test_exists_signing_key_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ecdsa_keypair(id)
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

    def test_exists_verifying_key_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ecdsa_keypair(id)
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

    def test_get_certificate_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        (vk, sk) = ks.create_ecdsa_keypair(id)
        certificate = ks.get_certificate(id)
        self.assertIsNotNone(certificate)
        self.assertEqual( "ecdsa-p256v1", certificate["algorithm"])
        self.assertEqual( id.bytes, certificate["hwDeviceId"])
        self.assertEqual(vk.to_string(), certificate["pubKey"])
        self.assertEqual(vk.to_string(), certificate["pubKeyId"])
        self.assertGreaterEqual(int(datetime.utcnow().timestamp()), certificate["validNotBefore"])
        self.assertLessEqual(int(datetime.utcnow().timestamp()), certificate["validNotAfter"])

    def test_get_multiple_certificates(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id_ed = uuid.uuid4()
        (vk_ed, sk) = ks.create_ed25519_keypair(id_ed)
        id_ec = uuid.uuid4()
        (vk_ec, sk) = ks.create_ecdsa_keypair(id_ec)
        certificate_ed = ks.get_certificate(id_ed)
        self.assertIsNotNone(certificate_ed)
        self.assertEqual( "ECC_ED25519", certificate_ed["algorithm"])
        self.assertEqual( id_ed.bytes, certificate_ed["hwDeviceId"])
        self.assertEqual(vk_ed.to_bytes(), certificate_ed["pubKey"])
        self.assertEqual(vk_ed.to_bytes(), certificate_ed["pubKeyId"])
        self.assertGreaterEqual(int(datetime.utcnow().timestamp()), certificate_ed["validNotBefore"])
        self.assertLessEqual(int(datetime.utcnow().timestamp()), certificate_ed["validNotAfter"])
        certificate_ec = ks.get_certificate(id_ec)
        self.assertIsNotNone(certificate_ec)
        self.assertEqual( "ecdsa-p256v1", certificate_ec["algorithm"])
        self.assertEqual( id_ec.bytes, certificate_ec["hwDeviceId"])
        self.assertEqual(vk_ec.to_string(), certificate_ec["pubKey"])
        self.assertEqual(vk_ec.to_string(), certificate_ec["pubKeyId"])
        self.assertGreaterEqual(int(datetime.utcnow().timestamp()), certificate_ec["validNotBefore"])
        self.assertLessEqual(int(datetime.utcnow().timestamp()), certificate_ec["validNotAfter"])

    def test_get_certificate_fails(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        self.assertIsNone(ks.get_certificate(id))

    def test_delete_keypair(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ed25519_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))
        ks.delete_verifying_key(id)
        ks.delete_signing_key(id)
        self.assertIsNone(ks.find_verifying_key(id))
        self.assertIsNone(ks.find_signing_key(id))

    def test_delete_keypair_ecdsa(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        id = uuid.uuid4()
        ks.create_ecdsa_keypair(id)
        self.assertIsNotNone(ks.find_verifying_key(id))
        self.assertIsNotNone(ks.find_signing_key(id))
        ks.delete_verifying_key(id)
        ks.delete_signing_key(id)
        self.assertIsNone(ks.find_verifying_key(id))
        self.assertIsNone(ks.find_signing_key(id))

