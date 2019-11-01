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
from datetime import datetime
from uuid import UUID

import requests

import ubirch

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store
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
        except:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


########################################################################


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
# create an instance of the ubirch API
api = ubirch.API(uuid, auth, env=env)

# register the devices identity
if not api.is_identity_registered(uuid):
    # TODO include this in API
    pubKeyInfo = keystore.get_certificate(uuid)
    # create a json key registration request
    pubKeyInfo['hwDeviceId'] = str(uuid)
    pubKeyInfo['pubKey'] = base64.b64encode(pubKeyInfo['pubKey']).decode()
    pubKeyInfo['pubKeyId'] = base64.b64encode(pubKeyInfo['pubKeyId']).decode()
    pubKeyInfo['created'] = str(datetime.utcfromtimestamp(pubKeyInfo['created']).isoformat() + ".000Z")
    pubKeyInfo['validNotAfter'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotAfter']).isoformat() + ".000Z")
    pubKeyInfo['validNotBefore'] = str(datetime.utcfromtimestamp(pubKeyInfo['validNotBefore']).isoformat() + ".000Z")

    signable_json = json.dumps(pubKeyInfo, separators=(',', ':')).encode()
    # logger.info(signable_json.decode())
    signed_message = protocol._sign(uuid, signable_json)
    signature = base64.b64encode(signed_message).decode()
    pubKeyRegMsg = {'pubKeyInfo': pubKeyInfo, 'signature': signature}
    pubKeyRegMsgJson = json.dumps(pubKeyRegMsg).encode()

    r = api.register_identity(pubKeyRegMsgJson)
    if r.status_code == requests.codes.ok:
        logger.info("registered new identity: {}".format(uuid))
    else:
        logger.error("device registration failed: {}".format(uuid))
    logger.debug("registered: {}: {}".format(r.status_code, r.content))

# create a payload message like being sent to the customer backend
payload = {
    "ts": int(time.time()),
    "v": random.randint(0, 100)
}

# # create a compact rendering of the payload to ensure determinism when creating the hash
# encoded = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()

# send data to the ubirch data service
logger.info("sending data: {}".format(payload))
r, message = api.data_send_mpack(payload)
logger.info("message: {}".format(binascii.hexlify(message)))
logger.info("response: {}: {}".format(r.status_code, r.content))

# create a new protocol message with the hashed message
message_hash = hashlib.sha512(message).digest()
upp = protocol.message_chained(uuid, 0x00, message_hash)
logger.info("sending UPP: {}".format(binascii.hexlify(upp)))
r = api.send(upp)
logger.info("response: {}: {}".format(r.status_code, binascii.hexlify(r.content)))

logger.info("verifying hash with backend -> quick check")
for i in range(3):
    r = api.verify(message_hash, quick=True)
    if r.status_code == 200 or i == 2: break
    logger.info("Hash couldn't be verified yet. Retry...")
    time.sleep(0.5)

logger.info("verified: {}: {}".format(r.status_code, r.content))

logger.info("verifying hash with backend -> chain check")
for i in range(3):
    r = api.verify(message_hash)
    if r.status_code == 200 or i == 2: break
    logger.info("Hash couldn't be verified yet. Retry...")
    time.sleep(0.5)

logger.info("verified: {}: {}".format(r.status_code, r.content))

protocol.persist(uuid)

# # deregister the devices identity
# if api.is_identity_registered(uuid):
#     vk = keystore.find_verifying_key(uuid)
#     sk = keystore.find_signing_key(uuid)
#
#     key_deregistration = str.encode(json.dumps({
#         "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
#         "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
#     }))
#     r = api.deregister_identity(key_deregistration)
#     if r.status_code == requests.codes.ok:
#         logger.info("deregistered identity: {}".format(uuid))
#     else:
#         logger.error("deregistration failed: {}".format(uuid))
#     logger.debug("deregistered: {}: {}".format(r.status_code, r.content))
