import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
from uuid import UUID

from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):
    UUID_PROD = UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not keystore.exists_signing_key(uuid):
            keystore.create_ed25519_keypair(uuid)

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(self.UUID_PROD):
            self.__ks.insert_ed25519_verifying_key(self.UUID_PROD, self.PUB_PROD)

        # load last signature for device
        self.load(uuid)

        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def persist(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.info("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


########################################################################

if len(sys.argv) < 3:
    print("usage:")
    print("  python3 example-client.py <UUID> <ubirch-auth-token>")
    sys.exit(0)

env = "prod"
uuid = UUID(hex=sys.argv[1])
auth = sys.argv[2]

# create a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)

# create an instance of the UBIRCH API and set the auth token
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

# register the public key at the UBIRCH key service
if not api.is_identity_registered(uuid):
    certificate = keystore.get_certificate(uuid)
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
    r = api.register_identity(key_registration)
    if r.status_code == codes.ok:
        logger.info("{}: public key registered".format(uuid))
    else:
        logger.error("{}: registration failed".format(uuid))
        sys.exit(1)

# create a message like being sent to the customer backend
# include an ID and timestamp in the data message to ensure a unique hash
message = {
    "id": str(uuid),
    "ts": int(time.time()),
    "data": "{:d}".format(random.randint(0, 100))
}
# >> send data to customer backend <<

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# hash the message
message_hash = hashlib.sha256(serialized).digest()
logger.info("message hash: {}".format(binascii.b2a_base64(message_hash).decode().rstrip("\n")))

# create a new chained protocol message with the message hash
upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)
logger.info("UPP: {}".format(binascii.hexlify(upp).decode()))

# send chained protocol message to UBIRCH authentication service
r = api.send(uuid, upp)
if r.status_code == codes.ok:
    logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(r.content).decode()))
else:
    logger.error("sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
    sys.exit(1)

# verify the backend response
try:
    protocol.message_verify(r.content)
    logger.info("backend response signature successfully verified")
except Exception as e:
    logger.error("backend response signature verification FAILED! {}".format(repr(e)))
    sys.exit(1)

# save last signature
protocol.persist(uuid)
