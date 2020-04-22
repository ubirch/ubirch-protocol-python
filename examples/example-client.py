import binascii
import hashlib
import json
import logging
import pickle
import random
import sys
import time
from uuid import UUID

from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store
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
        except:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)


########################################################################


def get_random_temperature() -> float:
    """get a random floating-point number between 0.0 and 100.0 as temperature"""
    return random.randint(0, 100) / float(random.randint(1, 5))


def get_random_humidity():
    """ get a random integer between 0 and 100 as relative humidity"""
    return random.randint(0, 100)


if len(sys.argv) < 4:
    print("usage:")
    print("  python3 example-client.py [dev|demo|prod] <UUID> <ubirch-auth-token>")
    sys.exit(0)

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])
auth = sys.argv[3]

# create a keystore for the device
keystore = ubirch.KeyStore(uuid.hex + ".jks", "test-keystore")

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)
protocol.load(uuid)
# create an instance of the ubirch API
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

# register the devices identity
if not api.is_identity_registered(uuid):
    key_registration = protocol.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
    r = api.register_identity(key_registration)
    if r.status_code == codes.ok:
        logger.info("{}: public key registered".format(uuid))
    else:
        logger.error("{}: registration failed".format(uuid))
    logger.debug("registered: {}: {}".format(r.status_code, r.content))

# create a message like being sent to the customer backend
temp = get_random_temperature()
hum = get_random_humidity()

# include an ID and timestamp in the data message to ensure a unique hash
message = {
    'uuid': str(uuid),
    'timestamp': int(time.time()),
    'data': {
        'T': "{:.3f}".format(temp),  # convert floats to strings with a constant number of decimal places
        "H": "{:d}".format(hum)
    },
    'msg_type': 1,
}

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# calculate the hash of the message
message_hash = hashlib.sha256(serialized).digest()

# send the message to data service
logger.info("sending data: {}".format(message))
r = api.send_data(uuid, serialized)
logger.info("response: {}: {}".format(r.status_code, r.content))

# create a new protocol message with the hash of the message
upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)

# send protocol message to verification service
logger.info("sending UPP: {}".format(binascii.hexlify(upp)))
r = api.send(uuid, upp)
logger.info("response: {}: {}".format(r.status_code, binascii.hexlify(r.content)))

# verify that hash exists in backend
logger.info("verifying hash with backend [quick check]")
retries = 3
while True:
    time.sleep(0.2)
    r = api.verify(message_hash, quick=True)
    if r.status_code == 200 or retries == 0: break
    logger.info("Hash could not be verified yet. Retry...")
    retries -= 1
logger.info("verification status code: {}: {}".format(r.status_code, r.content))

# save last signature
protocol.persist(uuid)

# # deregister the devices public key at the key service
# if api.is_identity_registered(uuid):
#     vk = keystore.find_verifying_key(uuid)
#     sk = keystore.find_signing_key(uuid)
#
#     key_deregistration = str.encode(json.dumps({
#         "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
#         "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
#     }))
#     r = api.deregister_identity(key_deregistration)
#     if r.status_code == codes.ok:
#         logger.info("deregistered public key for identity: {}".format(uuid))
#     else:
#         logger.error("deregistration failed: {}".format(uuid))
#     logger.debug("deregistered: {}: {}".format(r.status_code, r.content))
