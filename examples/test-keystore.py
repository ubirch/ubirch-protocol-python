import binascii
import hashlib
import json
import logging
import random
import time
from uuid import UUID

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not keystore.exists_signing_key(uuid):
            keystore.create_ecdsa_keypair(uuid)

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


########################################################################

uuid = UUID(hex="c8e5026e-5aef-4ad1-a7f0-1111820bf060")

# create a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)

# create a message like being sent to the customer backend
# include an ID and timestamp in the data message to ensure a unique hash
message = {
    "id": str(uuid),
    "ts": int(time.time()),
    "data": "{:d}".format(random.randint(0, 100))
}

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# hash the message
message_hash = hashlib.sha256(serialized).digest()
logger.info("message hash: {}".format(binascii.b2a_base64(message_hash).decode().rstrip("\n")))

# create a new chained protocol message with the message hash
upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)
logger.info("UPP: {}".format(binascii.hexlify(upp).decode()))

# verify the upp
unpacked = protocol.message_verify(upp)
print("UPP verified")
