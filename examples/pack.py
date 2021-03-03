import binascii
import hashlib
import json
import logging
import pickle
import secrets
import sys
import time
from uuid import UUID

import ubirch

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self._ks = key_store

    def load(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.debug("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except:
            logger.warning("no existing saved signatures")
            pass

    def persist(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self._ks.find_signing_key(uuid).sign(message)


########################################################################

if len(sys.argv) < 2:
    print("usage:")
    print("  python3 ./pack.py <UUID>")
    print("  e.g.: python3 ./pack.py 56bd9b85-6c6e-4a24-bf71-f2ac2de10183")
    sys.exit(0)

uuid = UUID(hex=sys.argv[1])

# create a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

logger.info("public key [base64]: {}".format(
    binascii.b2a_base64(keystore.find_verifying_key(uuid).to_bytes()).decode().rstrip('\n')))

# create an instance of the protocol with signature saving
protocol = Proto(keystore)
protocol.load(uuid)

# include an ID and timestamp in the data message to ensure a unique hash
message = {
    "uuid": str(uuid),
    "timestamp": int(time.time()),
    "data": "{:d}".format(secrets.randbits(16))
}

# create a compact rendering of the message to ensure determinism when creating the hash
serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

# calculate the hash of the message
message_hash = hashlib.sha512(serialized).digest()

# create a new chained protocol message with the hash of the message
upp = protocol.message_chained(uuid, 0x00, message_hash)
logger.info("UPP: {}".format(binascii.hexlify(upp).decode()))

# store signature persistently for chaining
protocol.persist(uuid)
