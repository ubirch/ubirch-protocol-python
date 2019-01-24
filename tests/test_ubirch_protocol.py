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
import logging
import os
import unittest
from uuid import UUID

import ed25519

import ubirch
from ubirch.ubirch_protocol import SIGNED, CHAINED

logger = logging.getLogger(__name__)

# test fixtures
TEST_UUID = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
TEST_PRIV = bytes.fromhex("a6abdc5466e0ab864285ba925452d02866638a8acb5ebdc065d2506661301417")
TEST_PUBL = bytes.fromhex("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068")

# expected simple signed message
EXPECTED_SIGNED = bytearray(bytes.fromhex(
    "9522c4106eac4d0b16e645088c4622e7451ea5a1ccef01"
    "c440c8f1c19fb64ca6ecd68a336bbffb39e8f4e6ee686de725ce9e23f76945fc2d"
    "734b4e77f9f02cb0bb2d4f8f8e361efc5ea10033bdc741a24cff4d7eb08db6340b"))

# expected sequence of chained messages
EXPECTED_CHAINED = [
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000ccee01c440296544cbaf"
        "aae7646422c7f5cf8c7e8d0767df257b6d66e237f0f98ca8375eb44dc1564607"
        "85984b570196ea6834e210dcf991fbbb6cd986a50ae2e2b5268f09")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c440296544cbafaae7646422"
        "c7f5cf8c7e8d0767df257b6d66e237f0f98ca8375eb44dc156460785984b5701"
        "96ea6834e210dcf991fbbb6cd986a50ae2e2b5268f09ccee02c44033c137b6ca"
        "f084a5c480a0f129650507f0236be63da60c1cdc89ae4576c5e8b4dd26945ad5"
        "84c2c76ba130e1d46f9ae65e59e99f4f16c379329ab6aaf04ab107")),
    bytearray(bytes.fromhex(
        "9623c4106eac4d0b16e645088c4622e7451ea5a1c44033c137b6caf084a5c480"
        "a0f129650507f0236be63da60c1cdc89ae4576c5e8b4dd26945ad584c2c76ba1"
        "30e1d46f9ae65e59e99f4f16c379329ab6aaf04ab107ccee03c440a0a6247a71"
        "e31626831d00ba06e0a5bf1a608da1ab8cbdc92664d1675b95a9d92c444ffe2a"
        "9ead4e39b187ed4b95c1ad32e06b9795897cdc568c84230fc8c90c"))
]


# a simple implementation of the ubirch protocol, having a fixed single key (from fixtures)
class Protocol(ubirch.Protocol):
    sk = ed25519.SigningKey(TEST_PRIV)
    vk = ed25519.VerifyingKey(TEST_PUBL)

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.sk.sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.vk.verify(signature, message)


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

    def test_unpack_legacy_trackle_message(self):
        loc = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

        with open(os.path.join(loc, "v0.4-trackle-production.mpack"), "rb") as f:
            message = f.read()

        class ProtocolNoVerify(ubirch.Protocol):
            def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> bytes:
                pass

        p = ProtocolNoVerify()
        unpacked = p.message_verify(message)
        self.assertEqual(CHAINED & 0x0f, unpacked[0] & 0x0f)
        self.assertEqual(UUID(bytes=bytes.fromhex("af931b05acca758bc2aaeb98d6f93329")), UUID(bytes=unpacked[1]))
        self.assertEqual(0x54, unpacked[3])

        payload = unpacked[4]
        self.assertEqual("v1.0.2-PROD-20180326103205 (v5.6.6)", bytes.decode(payload[0]))
        self.assertEqual(2766, payload[1])
        self.assertEqual(3, payload[2])
        self.assertEqual(736, len(payload[3]))
        self.assertEqual(3519, payload[3].get(1533846771))
        self.assertEqual(3914, payload[3].get(1537214378))
