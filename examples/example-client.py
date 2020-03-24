import base64
import binascii
import hashlib
import json
import logging
import os
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


def pack_data_message(uuid: UUID, data: dict) -> (bytes, bytes):
    """
    Generate a message for the ubirch data service.
    :param data: a map containing the data to be sent
    :return: a msgpack formatted array with the device UUID, message type, timestamp, data and hash
    :return: the hash of the data message
    """
    msg_type = 1

    message = {
        'uuid': str(uuid),
        'msg_type': msg_type,
        'timestamp': int(time.time()),
        'data': data
    }

    # create a compact rendering of the message to ensure determinism when creating the hash
    serialized = json.dumps(message, separators=(',', ':'), sort_keys=True).encode()

    # calculate hash of message
    message_hash = hashlib.sha512(serialized).digest()

    # append hash to message
    message.update({'hash': binascii.b2a_base64(message_hash).decode().rstrip('\n')})

    # return serialized message and hash
    return json.dumps(message, separators=(',', ':'), sort_keys=True).encode(), message_hash


auth = os.getenv("UBIRCH_AUTH")
if len(sys.argv) < 2 or auth is None:
    print("usage:")
    print("  export UBIRCH_AUTH=<ubirch-authorization-token>")
    print("  python3 example-client.py [dev|demo|prod] <UUID>")
    sys.exit(0)

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])

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
        logger.info("{}: identity registered".format(uuid))
    else:
        logger.error("{}: registration failed".format(uuid))
    logger.debug("registered: {}: {}".format(r.status_code, r.content))

# create a payload message like being sent to the customer backend
payload = {
    "ts": int(time.time()),
    "v": random.randint(0, 100)
}

# create a data message for the ubirch data service
message, message_hash = pack_data_message(uuid, {'v': payload})

# send data to data service
logger.info("sending data: {}".format(message))
r = api.send_data(uuid, message)
logger.info("response: {}: {}".format(r.status_code, r.content))

# create a new protocol message with the hashed message
upp = protocol.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)

# send protocol message to verification service
logger.info("sending UPP: {}".format(binascii.hexlify(upp)))
r = api.send(uuid, upp)
logger.info("response: {}: {}".format(r.status_code, binascii.hexlify(r.content)))

# verify that hash exists in backend
logger.info("verifying hash with backend [quick check]")
i = 0
while True:
    time.sleep(0.1)
    r = api.verify(message_hash, quick=True)
    if r.status_code == 200 or i == 10: break
    logger.info("Hash could not be verified yet. Retry...")
    i += 1
logger.info("verified: {}: {}".format(r.status_code, r.content))

# save last signature
protocol.persist(uuid)

# deregister the devices identity
if api.is_identity_registered(uuid):
    vk = keystore.find_verifying_key(uuid)
    sk = keystore.find_signing_key(uuid)

    key_deregistration = str.encode(json.dumps({
        "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
        "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
    }))
    r = api.deregister_identity(key_deregistration)
    if r.status_code == codes.ok:
        logger.info("deregistered identity: {}".format(uuid))
    else:
        logger.error("deregistration failed: {}".format(uuid))
    logger.debug("deregistered: {}: {}".format(r.status_code, r.content))
