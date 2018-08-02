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
from typing import Optional
from uuid import UUID

import ubirch
from ubirch.ubirch_protocol import CHAINED

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()

keystore = ubirch.KeyStore("test-jks.jks", "test-keystore")

uuid = UUID(hex="575A5601FD744F8EB6AEEF592CDEE12C")
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

logger.debug(repr(keystore.find_signing_key(uuid)))
logger.debug(repr(keystore.find_verifying_key(uuid)))


class Proto(ubirch.Protocol):
    def _sign(self, message: bytes) -> bytes:
        return keystore.find_signing_key(uuid).sign(message)

    def _save_signature(self, signature: bytes) -> None:
        try:
            with open(uuid.hex + ".sig", "wb+") as f:
                f.write(signature)
        except Exception as e:
            logger.error("can't write signature file: {}".format(e))

    def _load_signature(self) -> bytes:
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                return f.read(64)
        except Exception as e:
            logger.warning("can't read signature file: {}".format(e))
        return b'\0' * 64


proto = Proto(CHAINED)
logger.info(binascii.hexlify(proto.message(b'\x01' * 16, 0x00, [1, 2, 3])))
logger.info(binascii.hexlify(proto.message(b'\x01' * 16, 0x00, [4, 5, 6])))
