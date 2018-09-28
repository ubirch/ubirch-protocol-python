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
import unittest
from uuid import UUID

import ed25519
import pytest

import ubirch
from ubirch.ubirch_protocol import SIGNED, CHAINED

logger = logging.getLogger(__name__)

# test fixtures
TEST_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
TEST_PRIV = bytes.fromhex("a6abdc5466e0ab864285ba925452d02866638a8acb5ebdc065d2506661301417")
TEST_PUBL = bytes.fromhex("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068")

# expected simple signed message
EXPECTED_SIGNED = bytes.fromhex(
    "9512b06eac4d0b16e645088c4622e7451ea5a1ccef01da0040578a5b22ceb3e1"
    "d0d0f8947c098010133b44d3b1d2ab398758ffed11507b607ed37dbbe006f645"
    "f0ed0fdbeb1b48bb50fd71d832340ce024d5a0e21c0ebc8e0e")

# expected sequence of chained messages
EXPECTED_CHAINED = [
    bytes.fromhex(
        "9613b06eac4d0b16e645088c4622e7451ea5a1da004000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000ccee01da00408e58872a"
        "8a3baa13ec28dd9cf22957f28fb4d2e7e048f2d3f61fe2c7f45f3c46d4b4f95a"
        "eae3dacf0359f15617492e82fb21635b8ff6a420dc61dd3a16f85c09"),
    bytes.fromhex(
        "9613b06eac4d0b16e645088c4622e7451ea5a1da00408e58872a8a3baa13ec28"
        "dd9cf22957f28fb4d2e7e048f2d3f61fe2c7f45f3c46d4b4f95aeae3dacf0359"
        "f15617492e82fb21635b8ff6a420dc61dd3a16f85c09ccee02da0040da8777b7"
        "2b80d9708e6956c1a2164f5f04f085d5595787faf3521672bcc172071cfe90b3"
        "37cc94118258ede362cf1d3e078b9ae2aff4e038e6f8c8658e8f530e"),
    bytes.fromhex(
        "9613b06eac4d0b16e645088c4622e7451ea5a1da0040da8777b72b80d9708e69"
        "56c1a2164f5f04f085d5595787faf3521672bcc172071cfe90b337cc94118258"
        "ede362cf1d3e078b9ae2aff4e038e6f8c8658e8f530eccee03da0040a9bed504"
        "5af0379bd2e999e51a8d97e459517bc539a576a3f0a3c9f109d5b737ab0535d7"
        "8418e9d9d65188fcfb2c70a020237b451366dd8dcacd1b5b23cd4609")
]


# a simple implementation of the ubirch protocol, having a fixed single key (from fixtures)
class Protocol(ubirch.Protocol):
    sk = ed25519.SigningKey(TEST_PRIV)
    vk = ed25519.VerifyingKey(TEST_PUBL)

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.sk.sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> bytes:
        return self.vk.verify(signature, hashlib.sha512(message).digest())


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
            p.message_verify(EXPECTED_SIGNED)
        except NotImplementedError as e:
            self.assertEqual(e.args[0], 'verification not implemented')

    def test_create_signed_message(self):
        p = Protocol()
        message = p.message_signed(TEST_UUID, 0xEF, 1)
        logger.debug("MESSAGE: %s", binascii.hexlify(message))
        self.assertEqual(EXPECTED_SIGNED, message)

    def test_create_chained_messages(self):
        p = Protocol()
        for i in range(0, 3):
            message = p.message_chained(TEST_UUID, 0xEE, i + 1)
            logger.debug("MESSAGE: %s", binascii.hexlify(message))
            self.assertEqual(EXPECTED_CHAINED[i], message, "message #{} failed".format(i + 1))

    def test_verify_signed_message(self):
        p = Protocol()
        unpacked = p.message_verify(EXPECTED_SIGNED)
        self.assertEqual(SIGNED, unpacked[0])
        self.assertEqual(TEST_UUID.bytes, unpacked[1])
        self.assertEqual(0xEF, unpacked[2])
        self.assertEqual(1, unpacked[3])

    def test_verify_chained_messages(self):
        p = Protocol()
        last_signature = b'\0' * 64
        for i in range(0, 3):
            unpacked = p.message_verify(EXPECTED_CHAINED[i])
            self.assertEqual(CHAINED, unpacked[0])
            self.assertEqual(TEST_UUID.bytes, unpacked[1])
            self.assertEqual(last_signature, unpacked[2])
            self.assertEqual(0xEE, unpacked[3])
            self.assertEqual(i + 1, unpacked[4])
            # update the last signature we expect in the next message
            last_signature = unpacked[5]

    # TODO add randomized message generation and verification

    def test_verify_fails_missing_data(self):
        p = Protocol()
        message = EXPECTED_SIGNED[0:-67]
        try:
            p.message_verify(message)
        except Exception as e:
            self.assertEqual(e.args[0], "message format wrong (size < 70 bytes): {}".format(len(message)))


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
