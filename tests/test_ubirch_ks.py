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
<<<<<<< HEAD
from uuid import UUID
=======
import random, math
from scipy import special
>>>>>>> 65a318462be416896432d2bdaae2f57e4e67e44e

import ubirch
from ubirch.ubirch_ks import ED25519Certificate, ECDSACertificate

logger = logging.getLogger(__name__)

# test fixtures
TEST_KEYSTORE_FILE = "test_keystore_direct_delete.jks"
TEST_LOAD_KEYSTORE_FILE = "test_load_keystore.jks"
TEST_LOAD_KEYSTORE_UUID = UUID(hex="02012531-60A5-412C-A36B-65720C1F4C10")
TEST_PASSWORD = "abcdef12345"

TEST_UUID_STRING = "4d9d5bfd-37c1-48ff-ad67-cb0385f3b7f5"
TEST_UUID = uuid.UUID(TEST_UUID_STRING)
#TEST_PRIV_ED25519 = bytes.fromhex("a6abdc5466e0ab864285ba925452d02866638a8acb5ebdc065d2506661301417")
#TEST_PUBL_ED25519 = bytes.fromhex("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068")

class TestED25519Certificate(unittest.TestCase):

    def test_create_ed25519_cert(self):
        sk, vk = ed25519.create_keypair(entropy=urandom)
        self.assertIsInstance(ED25519Certificate(uuid.uuid4(), vk), ED25519Certificate)
        # TODO generate keys from fixtures

class TestECDSACertificate(unittest.TestCase):

    def test_create_ecdsa_cert(self):
        sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p, entropy=urandom, hashfunc=hashlib.sha256)
        vk = sk.get_verifying_key()
        # TODO generate keys from fixtures
        #  ecdsa.SigningKey.from_string(TEST_PRIV_ED25519, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        self.assertIsInstance(ECDSACertificate(uuid.uuid4(), vk), ECDSACertificate)

class TestUbirchKeyStore(unittest.TestCase):

    def test_create_keystore(self):
        self.assertIsInstance(ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD), ubirch.KeyStore)

    def test_keystore_is_saved(self):
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        ks.create_ed25519_keypair(uuid.uuid4())
        self.assertTrue(os.path.isfile(TEST_KEYSTORE_FILE), "KeyStore has not been saved")
        os.remove(TEST_KEYSTORE_FILE)

    def test_load_keystore(self):
<<<<<<< HEAD
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
=======
        ks = ubirch.KeyStore(TEST_LOAD_KEYSTORE_FILE, TEST_PASSWORD)
        self.assertIsInstance(ks, ubirch.KeyStore, "Keystore could not be loaded")
        cert = ks.get_certificate(TEST_UUID)
        self.assertIsNotNone(ks.get_certificate(TEST_UUID), "Certificate could not be loaded")  # Fails if tests are not run inside of tests/ folder
>>>>>>> 65a318462be416896432d2bdaae2f57e4e67e44e

    def test_create_save_load_keystore(self):
        test_uuid = uuid.uuid4()
        ks = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        ks.create_ed25519_keypair(test_uuid)

        ks_load = ubirch.KeyStore(TEST_KEYSTORE_FILE, TEST_PASSWORD)
        self.assertIsInstance(ks_load, ubirch.KeyStore, "Keystore could not be loaded")
        os.remove(TEST_KEYSTORE_FILE)


    def test_insert_key_fails_wrong_type(self):
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

class TestKeystoreSecurity(unittest.TestCase):
    def test_random_bit_frequency(self):
        p_val_limit = 0.01

        def monobit(bin_data):
            """
            Note that this description is taken from the NIST documentation [1]
            [1] http://csrc.nist.gov/publications/nistpubs/800-22-rev1a/SP800-22rev1a.pdf

            The focus of this test is the proportion of zeros and ones for the entire sequence. The purpose of this test is
            to determine whether the bit of ones and zeros in a sequence are approximately the same as would be expected
            for a truly random sequence. This test assesses the closeness of the fraction of ones to 1/2, that is the bit
            of ones and zeros ina  sequence should be about the same. All subsequent tests depend on this test.

            :param bin_data: a binary string
            :return: the p-value from the test
            """
            count = 0
            # If the bit is 0 minus 1, else add 1
            for bit in bin_data:
                if bit == 0:
                    count -= 1
                elif bit == 1:
                    count += 1
                else:
                    raise ValueError("Binary data must be 0 or 1")

            # Calculate the p value
            sobs = count / math.sqrt(len(bin_data))
            p_val = special.erfc(math.fabs(sobs) / math.sqrt(2))
            return p_val

        random_bits = [random.randrange(2) for _ in range(1000)]
        p_val_calc = monobit(random_bits)

        self.assertGreater(p_val_calc, p_val_limit, "Random data did not pass Frequency (Monobit) test. (p_val_calc was smaller than p_val_limit)\n This means with 99% confidence that something is wrong, but in 1% of tests there is a false positive.\n Random data was :\n" + str(random_bits))

        # if p_val_calc > p_val_limit:
        #     print(">> Frequency Test: PASSED (P val > 0.01) -->", p_val_calc)
        # else:
        #     print(">> Frequency Test: NOT PASSED (P val < 0.01)  -->  ", p_val_calc)