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

import ed25519
import ecdsa

import ubirch
from ubirch.ubirch_protocol import SIGNED, CHAINED

logger = logging.getLogger(__name__)

# test fixtures
TEST_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
TEST_PRIV = bytes.fromhex("a6abdc5466e0ab864285ba925452d02866638a8acb5ebdc065d2506661301417")
TEST_PUBL = bytes.fromhex("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068")

# expected simple signed message
EXPECTED_SIGNED = bytearray(bytes.fromhex(
    "9522c4106eac4d0b16e645088c4622e7451ea5a1ccef01c440c8f1c19fb64ca6ecd68a336bbffb39e8f4e6ee686de725ce9e23f76945fc2d734b4e77f9f02cb0bb2d4f8f8e361efc5ea10033bdc741a24cff4d7eb08db6340b"
))
EXPECTED_SIGNED_HASH = bytearray(bytes.fromhex(
    "9522c4106eac4d0b16e645088c4622e7451ea5a1ccefc4404dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510ac440c79663647d486d6c4c577d12cb34b825988c9eb4a8d322dbd2ceb8b17c99ce3dd34295cf641ea312ee77c15a2c9b404a32d67abb414061b7639e1ea5a20ce90b"
))
EXPECTED_SIGNED_UNPACKED = [
    34, b'n\xacM\x0b\x16\xe6E\x08\x8cF"\xe7E\x1e\xa5\xa1', 239, 1, b'\xc8\xf1\xc1\x9f\xb6L\xa6\xec\xd6\x8a3k\xbf\xfb9\xe8\xf4\xe6\xeehm\xe7%\xce\x9e#\xf7iE\xfc-sKNw\xf9\xf0,\xb0\xbb-O\x8f\x8e6\x1e\xfc^\xa1\x003\xbd\xc7A\xa2L\xffM~\xb0\x8d\xb64\x0b'
]
EXPECTED_SIGNED_MSG_SIG_SPLIT = (
    b'\x95"\xc4\x10n\xacM\x0b\x16\xe6E\x08\x8cF"\xe7E\x1e\xa5\xa1\xcc\xef\x01',
    b'\xc8\xf1\xc1\x9f\xb6L\xa6\xec\xd6\x8a3k\xbf\xfb9\xe8\xf4\xe6\xeehm\xe7%\xce\x9e#\xf7iE\xfc-sKNw\xf9\xf0,\xb0\xbb-O\x8f\x8e6\x1e\xfc^\xa1\x003\xbd\xc7A\xa2L\xffM~\xb0\x8d\xb64\x0b'
)

# expected sequence of chained messages
EXPECTED_CHAINED = [
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccee01c440296544cbafaae7646422c7f5cf8c7e8d0767df257b6d66e237f0f98ca8375eb44dc156460785984b570196ea6834e210dcf991fbbb6cd986a50ae2e2b5268f09"
    )),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c440296544cbafaae7646422c7f5cf8c7e8d0767df257b6d66e237f0f98ca8375eb44dc156460785984b570196ea6834e210dcf991fbbb6cd986a50ae2e2b5268f09ccee02c44033c137b6caf084a5c480a0f129650507f0236be63da60c1cdc89ae4576c5e8b4dd26945ad584c2c76ba130e1d46f9ae65e59e99f4f16c379329ab6aaf04ab107"
    )),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44033c137b6caf084a5c480a0f129650507f0236be63da60c1cdc89ae4576c5e8b4dd26945ad584c2c76ba130e1d46f9ae65e59e99f4f16c379329ab6aaf04ab107ccee03c440a0a6247a71e31626831d00ba06e0a5bf1a608da1ab8cbdc92664d1675b95a9d92c444ffe2a9ead4e39b187ed4b95c1ad32e06b9795897cdc568c84230fc8c90c"
    ))
]
EXPECTED_CHAINED_NO_SIGNATURE = bytearray(bytes.fromhex(
    '9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccef01c4403ad26406f027189a7835a20f62415621cb70808ef66b442cf006faff9f6f162dd9c455da9b82151cb223cad8d2f7a683dc2281633c2e3d7a769bfeb3137bff00'
))
EXPECTED_CHAINED_HASH = bytearray(bytes.fromhex(
    "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccefc4404dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510ac440dde50cad0db567dee187513e2d11bb2d9ba24a85fe6dddc4a0dc0b28fa2cd28bca72a60aa15dda962ae46488c80ae67a67445d257c56febf4f3c5221d95c2309"
))
BROKEN_UPP_NO_DATA_CONTENT = bytearray(bytes.fromhex(
    '9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0c440024c0cbcf659a248ed7c1c3ef417009fab3f81676d2c4c268ce35424b22a632921d61d443e779a10613fa2c73a8219fa8c2d5c0c80fc68d0f528c7b2756dac0f'
))

# a simple implementation of the ubirch protocol, having a fixed single key (from fixtures)
class Protocol(ubirch.Protocol):
    sk = ed25519.SigningKey(TEST_PRIV)
    vk = ed25519.VerifyingKey(TEST_PUBL)

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
        elif isinstance(self.vk, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest()
        else:
            raise(ValueError("Verifying Key is neither ed25519, nor ecdsa!"))

        return self.vk.verify(signature, final_message)


class TestUbirchProtocol(unittest.TestCase):
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

    def test_get_unpacked_index(self):
        p = Protocol()

        # test indexes of signatures for unsigned messages
        self.assertEqual(p.get_unpacked_index(0b0001, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_SIG), -1)
        self.assertEqual(p.get_unpacked_index(0b0001, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_PREV_SIG), -1)

        # test indexes of signatures for signed messages
        self.assertEqual(p.get_unpacked_index(0b0010, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_SIG), 4)
        self.assertEqual(p.get_unpacked_index(0b0010, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_PREV_SIG), -1)

        # test indexes of signatures for chained messages
        self.assertEqual(p.get_unpacked_index(0b0011, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_SIG), 5)
        self.assertEqual(p.get_unpacked_index(0b0011, ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_PREV_SIG), 2)

    def test_unpack_upp(self):
        p = Protocol()
        self.assertEqual(p.unpack_upp(EXPECTED_SIGNED), EXPECTED_SIGNED_UNPACKED)

    def test_unpack_upp_fails(self):
        p = Protocol()

        BROKEN_EXPECTED_SIGNED = EXPECTED_SIGNED.copy()
        BROKEN_EXPECTED_SIGNED[1] = 0
        self.assertRaises(ValueError, p.unpack_upp, BROKEN_EXPECTED_SIGNED)

    def test_upp_msgpack_split_signature(self):
        p = Protocol()
        self.assertEqual(p.upp_msgpack_split_signature(EXPECTED_SIGNED), EXPECTED_SIGNED_MSG_SIG_SPLIT)

    def test_upp_msgpack_split_signature_fails_wrong_version_byte(self):
        p = Protocol()
        BROKEN_EXPECTED_SIGNED = EXPECTED_SIGNED.copy()
        BROKEN_EXPECTED_SIGNED[1]  = 100

        with self.assertRaises(ValueError) as context:
            p.upp_msgpack_split_signature(BROKEN_EXPECTED_SIGNED)
            self.assertIn(context.exception.args[0], "Invalid UPP version byte:")

    def test_upp_msgpack_split_signature_fails_upp_too_short(self):
        p = Protocol()
        BROKEN_EXPECTED_SIGNED = b'1'

        with self.assertRaises(ValueError) as context:
            p.upp_msgpack_split_signature(BROKEN_EXPECTED_SIGNED)
            self.assertIn(context.exception.args[0], "The UPP-msgpack is too short:")

    # Todo test message creation with table driven funcs

    def test_create_signed_message(self):
        p = Protocol()
        message = p.message_signed(TEST_UUID, 0xEF, 1)
        self.assertEqual(EXPECTED_SIGNED, message)

    def test_create_signed_message_with_hash(self):
        p = Protocol()
        message = p.message_signed(TEST_UUID, 0xEF, hashlib.sha512(b'1').digest())
        self.assertEqual(EXPECTED_SIGNED_HASH, message)

    def test_create_chained_messages(self):
        p = Protocol()
        for i in range(0, 3):
            message = p.message_chained(TEST_UUID, 0xEE, i + 1)
            self.assertEqual(EXPECTED_CHAINED[i], message, "message #{} failed".format(i + 1))

    def test_create_chained_message_with_hash(self):
        p = Protocol()
        message = p.message_chained(TEST_UUID, 0xEF, hashlib.sha512(b'1').digest())
        self.assertEqual(EXPECTED_CHAINED_HASH, message)

    def test_verify_signed_message(self):
        p = Protocol()
        unpacked = p.unpack_upp(EXPECTED_SIGNED)
        
        self.assertTrue(p.verfiy_signature(UUID(bytes=unpacked[1]), bytes(EXPECTED_SIGNED)))
        self.assertEqual(SIGNED, unpacked[0])
        self.assertEqual(TEST_UUID.bytes, unpacked[1])
        self.assertEqual(0xEF, unpacked[2])
        self.assertEqual(1, unpacked[3])

    def test_verify_chained_messages(self):
        p = Protocol()
        last_signature = b'\0' * 64
        
        for i in range(0, 3):
            unpacked = p.unpack_upp(EXPECTED_CHAINED[i])
            self.assertTrue(p.verfiy_signature(UUID(bytes=unpacked[1]), bytes(EXPECTED_CHAINED[i])))
            
            self.assertEqual(CHAINED, unpacked[0])
            self.assertEqual(TEST_UUID.bytes, unpacked[1])
            self.assertEqual(last_signature, unpacked[2])
            self.assertEqual(0xEE, unpacked[3])
            self.assertEqual(i + 1, unpacked[4])
            
            # update the last signature we expect in the next message
            last_signature = unpacked[5]

    # TODO add randomized message generation and verification

    @unittest.expectedFailure
    def test_verify_signed_message_fails_no_data_content(self):
        p = Protocol()
        self.assertFalse(p.verify_signature(TEST_UUID, bytes(BROKEN_UPP_NO_DATA_CONTENT)))

    def test_set_saved_signatures(self):
        p = Protocol()
        p.set_saved_signatures({TEST_UUID: "1234567890"})

        self.assertEqual({TEST_UUID: "1234567890"}, p.get_saved_signatures())

    def test_set_saved_signatures_changed(self):
        p = Protocol()
        p.set_saved_signatures({TEST_UUID: "1234567890"})
        self.assertEqual({TEST_UUID: "1234567890"}, p.get_saved_signatures())

        # sign a message and expect the last signature for this UUID to change
        p.message_signed(TEST_UUID, 0xEF, 1, True)
        self.assertEqual({TEST_UUID: EXPECTED_SIGNED[-64:]}, p.get_saved_signatures())

    def test_set_saved_signatures_unchanged(self):
        p = Protocol()
        p.set_saved_signatures({TEST_UUID: "1234567890"})
        self.assertEqual({TEST_UUID: "1234567890"}, p.get_saved_signatures())

        # sign a message and do not save the last signature
        p.message_signed(TEST_UUID, 0xEF, 1, False)
        self.assertEqual({TEST_UUID: "1234567890"}, p.get_saved_signatures())

    def test_reset_saved_signatures(self):
        p = Protocol()
        p.set_saved_signatures({TEST_UUID: "1234567890"})
        self.assertEqual({TEST_UUID: "1234567890"}, p.get_saved_signatures())

        # sign a message and expect the last signature for this UUID to change
        p.message_signed(TEST_UUID, 0xEF, 1, True)
        p.reset_signature(TEST_UUID)
        self.assertEqual({}, p.get_saved_signatures())

    def test_reset_saved_signatures_in_upp(self):
        # sign a message and reset signature. Check if the signature is removed from the next message
        p = Protocol()
        p.set_saved_signatures({TEST_UUID: "1234567890"})

        p.message_chained(TEST_UUID, 0xEF, 1)
        p.reset_signature(TEST_UUID)
        next_chained = p.message_chained(TEST_UUID, 0xEF, 1)
        self.assertEqual(EXPECTED_CHAINED_NO_SIGNATURE, next_chained)


    def test_unpack_register_v1(self):
        class ProtocolNoVerify(ubirch.Protocol):
            def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> bytes:
                pass

        p = ProtocolNoVerify()

        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

        with open(os.path.join(loc, "v1.0-register.mpack"), "rb") as f:
            message = f.read()

        unpacked = p.unpack_upp(message)

        self.assertEqual(SIGNED & 0x0f, unpacked[0] & 0x0f)
        self.assertEqual(1, unpacked[0] >> 4)
        self.assertEqual(UUID(bytes=bytes.fromhex("00000000000000000000000000000000")), UUID(bytes=unpacked[1]))
        self.assertEqual(0x01, unpacked[2])

        payload = unpacked[3]
        expectedPubKey = binascii.unhexlify("2c37eee25b08490a9936e0c4d1f8f2091bebdbc3b08e29164e833a33742df91a")

        self.assertEqual(b'ECC_ED25519', payload[b'algorithm'])
        self.assertEqual( 1542793437, payload[b'created'])
        self.assertEqual(b'\0'*16, payload[b'hwDeviceId'])
        self.assertEqual(expectedPubKey, payload[b'pubKey'])
        self.assertEqual(expectedPubKey, payload[b'pubKeyId'])
        self.assertEqual( 1574329437, payload[b'validNotAfter'])
        self.assertEqual( 1542793437, payload[b'validNotBefore'])