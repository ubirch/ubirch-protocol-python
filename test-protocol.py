#! /usr/bin/env python3
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
from uuid import UUID

from ubirch import UbirchKeyStore, UbirchProtocol
from ubirch.ubirch_protocol import CHAINED

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)

keystore = UbirchKeyStore("test-jks.jks", "test-keystore")

uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

print(repr(keystore.find_signing_key(uuid)))
print(repr(keystore.find_verifying_key(uuid)))


class Proto(UbirchProtocol):
    def _sign(self, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)


proto = Proto(CHAINED)
print(binascii.hexlify(proto.message(b'\x01' * 16, 0x00, [1, 2, 3])))
print(binascii.hexlify(proto.message(b'\x01' * 16, 0x00, [4, 5, 6])))
