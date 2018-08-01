#! /usr/bin/env python3
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
