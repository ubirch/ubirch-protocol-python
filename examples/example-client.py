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
from requests import codes, Response

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

DEFAULT_UBIRCH_ENV = "prod"
UBIRCH_PUBKEYS = {
    "dev": VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding="hex"), # NOTE: this environment is not reliable
    "demo": VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding="hex"),
    "prod": VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding="hex")
}
UBIRCH_UUIDS = {
    "dev": UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff"), # NOTE: this environment is not reliable
    "demo": UUID(hex="07104235-1892-4020-9042-00003c94b60b"),
    "prod": UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
}

# create a global logger
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    """ implement the ubirch-protocol, including creating and saving signatures """

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID, env: str = DEFAULT_UBIRCH_ENV) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not self.__ks.exists_signing_key(uuid):
            self.__ks.create_ed25519_keypair(uuid)

        # check env
        if env not in UBIRCH_PUBKEYS.keys():
            raise ValueError("Invalid ubirch env! Must be one of {}".format(list(UBIRCH_PUBKEYS.keys())))

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(UBIRCH_UUIDS[env]):
            self.__ks.insert_ed25519_verifying_key(UBIRCH_UUIDS[env], UBIRCH_PUBKEYS[env])

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


class UbirchClient:
    """ an example implementation for the ubirch-client in Python """

    def __init__(self, uuid: UUID, auth: str, env: str = DEFAULT_UBIRCH_ENV):
        self.env = env
        self.uuid = uuid
        self.auth = auth

        # create a keystore for the device
        self.keystore = ubirch.KeyStore("demo-device.jks", "keystore")

        # create an instance of the protocol with signature saving
        self.protocol = Proto(self.keystore, self.uuid, self.env)

        # create an instance of the UBIRCH API and set the auth token
        self.api = ubirch.API(env=self.env)
        self.api.set_authentication(self.uuid, self.auth)

        # register the pubkey if needed
        self.checkRegisterPubkey()

        # a variable to store the current upp
        self.currentUPP = None
        self.currentSig = None

    def run(self, data: dict):
        """ create and send a ubirch protocol message; verify the response """
        # create the upp
        self.currentUPP = self.createUPP(data)
        _, self.currentSig = self.protocol.upp_msgpack_split_signature(self.currentUPP)

        logging.info("Created UPP: %s" % str(self.currentUPP.hex()))

        # send the upp and handle the response
        resp = self.sendUPP(self.currentUPP)
        
        self.handleBackendResponse(resp)
        
        # the handle function is expected to sys.exit() on any kind of error - assume success
        logging.info("Successfully sent the UPP and verified the response!")

        # save last signatures
        self.protocol.persist(self.uuid)

    def checkRegisterPubkey(self):
        """ checks if the key is registered at the ubirch backend and registers it if necessary """
        # register the public key at the UBIRCH key service
        if not self.api.is_identity_registered(self.uuid):
            # get the certificate and create the registration message
            certificate = self.keystore.get_certificate(self.uuid)
            key_registration = self.protocol.message_signed(self.uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)

            # send the registration message
            r = self.api.register_identity(key_registration)

            # check for success
            if r.status_code == codes.ok:
                logger.info("{}: public key registered".format(self.uuid))
            else:
                logger.error("{}: registration failed".format(self.uuid))
                
                raise Exception("Failed to register the public key!")

    def createUPP(self, message: dict) -> bytes:
        """ creates an UPP from a given message """
        # create a compact rendering of the message to ensure determinism when creating the hash
        serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

        # hash the message
        messageHash = hashlib.sha512(serialized).digest()
        logger.info("message hash: {}".format(binascii.b2a_base64(messageHash).decode().rstrip("\n")))

        # create a new chained protocol message with the message hash
        return self.protocol.message_chained(self.uuid, UBIRCH_PROTOCOL_TYPE_BIN, messageHash)

    def sendUPP(self, upp: bytes) -> Response:
        """ sends a UPP to the ubirch backend and returns the response object """
        # send chained protocol message to UBIRCH authentication service
        return self.api.send(self.uuid, upp)

    def handleBackendResponse(self, response: Response) -> bool:
        """ handles the response object returned by sendUPP """
        # check the http status code
        #
        #   200: OK; try to verify the UPP
        #   XYZ: ERR; log the error and exit
        if response.status_code != codes.ok:
            logger.error("Sending UPP failed! response: ({}) {}".format(response.status_code,
                                                                        binascii.hexlify(response.content).decode()))
            
            raise(Exception("Exiting due to failure sending the UPP to the backend!"))

        logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(response.content).decode()))

        # verify that the response came from the backend
        if self.protocol.verfiy_signature(UBIRCH_UUIDS[self.env], response.content) == True:
            logger.info("Backend response signature successfully verified!")
        else:
            logger.error("Backend response signature verification FAILED!")
            
            raise(Exception("Exiting due to failed signature verification!"))

        # unpack the received upp to get its previous signature
        unpacked = self.protocol.unpack_upp(response.content)
        prevSig = unpacked[self.protocol.get_unpacked_index(unpacked[0], ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_PREV_SIG)]

        # verfiy that the response contains the signature of our upp
        if self.currentSig != prevSig:
            logger.error("The previous signature in the response UPP doesn't match the signature of our UPP!")
            logger.error("Previous signature in the response UPP: %s" % str(prevSig.hex()))
            logger.error("Actual signature of our UPP: %s" % str(self.currentSig.hex()))
            
            raise(Exception("Exiting due to a non-matching signature in the response UPP!"))
        else:
            logger.info("Matching previous signature!")


def get_message(uuid: UUID) -> dict:
    """ creates a unique example JSON data message """
    # create a message like being sent to the customer backend
    # include an ID and timestamp in the data message to ensure a unique hash
    return {
        "id": str(uuid),
        "ts": int(time.time()),
        "data": "{:d}".format(random.randint(0, 100))
    }


# initialize/"run" the Main class
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("usage:")
        print("  python3 example-client.py <UUID> <ubirch-auth-token> [ubirch-env]")
        sys.exit(1)

    # extract cli arguments
    env = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_UBIRCH_ENV
    uuid = UUID(hex=sys.argv[1])
    auth = sys.argv[2]

    client = UbirchClient(uuid=uuid, auth=auth, env=env)

    data = get_message(uuid)

    logger.info("Created an example data message: %s" % str(data))

    # todo >> send data message to data service / cloud / customer backend here <<

    try:
        client.run(data)
    except Exception as e:
        logger.exception(e)

        sys.exit(1)
