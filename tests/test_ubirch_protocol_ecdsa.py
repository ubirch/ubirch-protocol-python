# ubirch protocol tests
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

import binascii
import hashlib
import logging
import os
import unittest
from uuid import UUID

import ecdsa
import ed25519

import ubirch
from ubirch.ubirch_protocol import SIGNED, CHAINED

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s',
                    level=logging.DEBUG)


# test fixtures
TEST_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
TEST_PRIV = bytes.fromhex("8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937")
TEST_PUBL = bytes.fromhex("55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771")

# expected simple signed message
EXPECTED_SIGNED = bytearray(bytes.fromhex(
    "9522c4106eac4d0b16e645088c4622e7451ea5a1ccef01c4403820f3f14de6d38a124778861c05279a07a2437e3b5b30b9e1b033440cf121d836cb587592201cba6cdac377da13d6a11104e8443aa9fd58178bfe3492379667"))

EXPECTED_SIGNED_HASH = bytearray(bytes.fromhex(
    "9522c4106eac4d0b16e645088c4622e7451ea5a1ccefc4404dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510ac440"
))

# expected sequence of chained messages (contained signatures are placeholders only, ecdsa is not deterministic)
EXPECTED_CHAINED = [
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccee01c4401fdd132be93216aa844b1d1a0838f1664babfa1fedab7b25ce48d0c9e124480b6c76e1780e877bda664c6d5795b2f0fe6660f78a27afb1228d84f37e92839b94")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c4401fdd132be93216aa844b1d1a0838f1664babfa1fedab7b25ce48d0c9e124480b6c76e1780e877bda664c6d5795b2f0fe6660f78a27afb1228d84f37e92839b94ccee02c440ecd0676ac764a3b939f34422dc2cf56ebc7bbe2bcb3c7febc606e5832c38f60392c43371be134df6cf99301108bc5f09f1d04763427e79379d25a6923c2fcfcc")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c440ecd0676ac764a3b939f34422dc2cf56ebc7bbe2bcb3c7febc606e5832c38f60392c43371be134df6cf99301108bc5f09f1d04763427e79379d25a6923c2fcfccccee03c440d3fcc18a4bec661a803af456873efaea3962afb2ec16955c0f7054ae6b0a169f00d2d86a74976f299a270a3450798b3cc43b2162c036ba76d8244279b044211e"))
]

EXPECTED_CHAINED_HASH = bytearray(bytes.fromhex(
    "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccefc4404dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510ac4404595bdc73ae1e33725d6085141d6d0843f37820c65b55d16d45ed6373c16e63c503d2ab3500ce81f3d4889923279df7f76bf065417b047fa8aaf0a3d29ea3d35"
))


# a simple implementation of the ubirch protocol, having a fixed single key (from fixtures)
class Protocol(ubirch.Protocol):
    sk = ecdsa.SigningKey.from_string(TEST_PRIV, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
    vk = ecdsa.VerifyingKey.from_string(TEST_PUBL, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

    def _hash(self, message: bytes) -> bytes:
        return hashlib.sha256(message).digest()

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        if isinstance(self.sk, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(self.sk, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return self.sk.sign(final_message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        if isinstance(self.vk, ecdsa.VerifyingKey):
            # no hashing required here
            final_message = message
            #final_message = hashlib.sha256(message).digest()
        elif isinstance(self.vk, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Verifying Key is neither ed25519, nor ecdsa!"))    
         
        return self.vk.verify(signature, final_message)


class TestUbirchProtocolECDSA(unittest.TestCase):
    def test_sign_not_implemented(self):
        p = ubirch.Protocol()
        try:
            p.message_signed(TEST_UUID, 0xEF, 1)
        except NotImplementedError as e:
            self.assertEqual(e.args[0], 'signing not implemented')

    def test_verify_not_implemented(self):
        p = ubirch.Protocol()
        try:
            p.verfiy_signature(None, EXPECTED_SIGNED)
        except NotImplementedError as e:
            self.assertEqual(e.args[0], 'verification not implemented')

    def test_create_signed_message(self):
        p = Protocol()
        message = p.message_signed(TEST_UUID, 0xEF, 1)
        logger.debug("MESSAGE: %s", binascii.hexlify(message))
        self.assertEqual(EXPECTED_SIGNED[0:-64], message[0:-64])
        self.assertEqual(p.verfiy_signature(TEST_UUID, message), True)

    def test_create_signed_message_with_hash(self):
        p = Protocol()
        message = p.message_signed(TEST_UUID, 0xEF, hashlib.sha512(b'1').digest())
        logger.debug("MESSAGE: %s", binascii.hexlify(message))
        self.assertEqual(EXPECTED_SIGNED_HASH, message[0:-64])
        self.assertEqual(p.verfiy_signature(TEST_UUID, message), True)
        
    def test_create_chained_messages(self):
        p = Protocol()
        last_signature = bytearray(b'\0'*64)
        for i in range(0, 3):
            message = p.message_chained(TEST_UUID, 0xEE, i + 1)
            logger.debug("LASTSIG: %s", binascii.hexlify(last_signature))
            logger.debug("MESSAGE: %s", binascii.hexlify(message))
            EXPECTED = EXPECTED_CHAINED[i].copy()
            EXPECTED[22:22+64] = last_signature
            logger.debug("EXPECT : %s", binascii.hexlify(EXPECTED))
            self.assertEqual(EXPECTED[0:-64], message[0:-64], "message #{} failed".format(i + 1))
            self.assertEqual(last_signature, message[22:22+64])
            self.assertEqual(p.verfiy_signature(TEST_UUID, message), True)
            last_signature = message[-64:]

    def test_create_chained_message_with_hash(self):
        p = Protocol()
        message = p.message_chained(TEST_UUID, 0xEF, hashlib.sha512(b'1').digest())
        logger.debug("MESSAGE: %s", binascii.hexlify(message))

        self.assertEqual(EXPECTED_CHAINED_HASH[0:-64], message[0:-64])
        self.assertEqual(p.verfiy_signature(TEST_UUID, message), True)

    def test_verify_signed_message(self):
        p = Protocol()
        unpacked = p.unpack_upp(EXPECTED_SIGNED)
        self.assertEqual(p.verfiy_signature(UUID(bytes=unpacked[1]), bytearray(EXPECTED_SIGNED)), True)
        self.assertEqual(SIGNED, unpacked[0])
        self.assertEqual(TEST_UUID.bytes, unpacked[1])
        self.assertEqual(0xEF, unpacked[2])
        self.assertEqual(1, unpacked[3])

    def test_verify_chained_messages(self):
        p = Protocol()
        last_signature = b'\0' * 64
        for i in range(0, 3):
            unpacked = p.unpack_upp(EXPECTED_CHAINED[i])
            self.assertEqual(p.verfiy_signature(UUID(bytes=unpacked[1]), bytearray(EXPECTED_CHAINED[i])), True)
            self.assertEqual(CHAINED, unpacked[0])
            self.assertEqual(TEST_UUID.bytes, unpacked[1])
            self.assertEqual(last_signature, unpacked[2])
            self.assertEqual(0xEE, unpacked[3])
            self.assertEqual(i + 1, unpacked[4])
            # update the last signature we expect in the next message
            last_signature = unpacked[5]


class TestUbirchProtocolSIM(unittest.TestCase):
    def test_verify_registration_message_sim_v1(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v1.0-ecdsa-register.mpack"), "rb") as f:
            message = f.read()

        vk = "06784eaaf180c1091a135bfe4804306f696fc56a4a75d12e269bfcafb67498d5a963fb72aaaca9fa3209bdf9b34d249c493bd5cd0a4d3763e425c8f461af50a5"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)

        self.assertEqual(p.verfiy_signature(None, bytearray(message)), True)
        self.assertEqual(vk, binascii.hexlify(unpacked[3][b'pubKey']).decode())

    def test_verify_signed_message_sim_v1(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v1.0-ecdsa-message.mpack"), "rb") as f:
            message = f.read()

        vk = "06784eaaf180c1091a135bfe4804306f696fc56a4a75d12e269bfcafb67498d5a963fb72aaaca9fa3209bdf9b34d249c493bd5cd0a4d3763e425c8f461af50a5"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)
        logger.debug(repr(unpacked))

        self.assertEqual(p.verfiy_signature(UUID(bytes=unpacked[1]), bytearray(message)), True)
        self.assertEqual(hashlib.sha256(b"UBIRCH").digest(), unpacked[3])

    def test_verify_registration_message_sim_v2(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v2.0-ecdsa-register.mpack"), "rb") as f:
            message = f.read()

        vk = "a3c14cff55de8459fe4367a98cc399c19bb74615e24b4254742ff0393d71bd8dd55af363480e2ff201d5dca2603cbd9cd68ffea783cec86ff50aabbc540fc75d"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)
        logger.debug(repr(unpacked))

        self.assertEqual(p.verfiy_signature(UUID(bytes=unpacked[1]), message), True)
        self.assertEqual(vk, binascii.hexlify(unpacked[3]['pubKey']).decode())

    def test_verify_signed_message_sim_v2(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        with open(os.path.join(loc, "v2.0-ecdsa-message.mpack"), "rb") as f:
            message = f.read()

        vk = "a3c14cff55de8459fe4367a98cc399c19bb74615e24b4254742ff0393d71bd8dd55af363480e2ff201d5dca2603cbd9cd68ffea783cec86ff50aabbc540fc75d"
        p = Protocol()
        p.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(vk), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        unpacked = p.unpack_upp(message)
        logger.debug(repr(unpacked))

        self.assertEqual(p.verfiy_signature(UUID(bytes=unpacked[1]), message), True)
        self.assertEqual(hashlib.sha256(b"UBIRCH").digest(), unpacked[3])
