import base64
import json
import logging
import sys
from uuid import UUID

from requests import codes

import ubirch

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store
        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


########################################################################


if len(sys.argv) < 4:
    print("usage:")
    print("  python3 example-client.py [dev|demo|prod] <UUID> <ubirch-auth-token>")
    sys.exit(0)

env = sys.argv[1]
uuid = UUID(hex=sys.argv[2])
auth = sys.argv[3]

# create a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# create an instance of the protocol with signature saving
protocol = Proto(keystore, uuid)
# create an instance of the ubirch API
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

# register the devices identity
if not api.is_identity_registered(uuid):
    cert = keystore.get_certificate(uuid)
    cert_dump = json.dumps(cert, separators=(',', ':')).encode()
    signature = protocol._sign(uuid, cert_dump)
    key_registration = {"pubKeyInfo": cert, "signature": base64.b64encode(signature).decode()}

    r = api.register_identity(json.dumps(key_registration).encode())
    if r.status_code == codes.ok:
        logger.info("{}: public key registered".format(uuid))
    else:
        logger.error("{}: registration failed".format(uuid))
        sys.exit(1)

old_key_id = uuid
prevPubKeyId = base64.b64encode(keystore.find_verifying_key(old_key_id).to_bytes()).decode()

# create a new key
new_key_id = UUID("22222222222222222222222222222222")
if not keystore.exists_signing_key(new_key_id):
    keystore.create_ed25519_keypair(new_key_id)

new_cert = keystore.get_certificate(new_key_id, prevPubKeyId=prevPubKeyId)
new_cert["hwDeviceId"] = str(uuid)
new_cert_dump = json.dumps(new_cert, separators=(',', ':')).encode()

new_signature = protocol._sign(new_key_id, new_cert_dump)

old_signature = protocol._sign(old_key_id, new_cert_dump)

key_registration = {"pubKeyInfo": new_cert, "signature": base64.b64encode(new_signature).decode(),
                    "prevSignature": base64.b64encode(old_signature).decode()}
logger.info(json.dumps(key_registration))

r = api.register_identity(json.dumps(key_registration).encode())
if r.status_code == codes.ok:
    logger.info("{}: public key updated".format(uuid))

    keystore.insert_ed25519_keypair(uuid=uuid, vk=keystore.find_verifying_key(new_key_id),
                                    sk=keystore.find_signing_key(new_key_id))

else:
    logger.error("{}: key update failed".format(uuid))
