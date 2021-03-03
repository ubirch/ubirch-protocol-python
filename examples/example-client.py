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
    "dev": "a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66",
    "demo": "39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251",
    "prod": "ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690"
}
UBIRCH_UUIDS = {
    "dev": "9d3c78ff-22f3-4441-a5d1-85c636d486ff",
    "demo": "07104235-1892-4020-9042-00003c94b60b",
    "prod": "10b2e1a4-56b3-4fff-9ada-cc8c20f93016"
}


# create a global logger
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    """ implement the uBirch-protocol, including creating and saving signatures """
    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID, env: str = "prod") -> None:
        super().__init__()
        self.__ks = key_store
        self.deviceUUID = uuid

        # check env
        if not env in ["dev", "demo", "prod"]:
            raise ValueError("Inavlid uBirch-Env! Must be one of 'dev', 'demo' or 'prod'")

        # get the uBirch pubkey and uuid for the given stage
        self.uBirchPubkey = VerifyingKey(UBIRCH_PUBKEYS[env], encoding="hex")
        self.uBirchUUID = UUID(hex=UBIRCH_UUIDS[env])

        # check if the device already has keys or generate a new pair
        if not self.__ks.exists_signing_key(uuid):
            self.__ks.create_ed25519_keypair(uuid)

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(self.uBirchUUID):
            self.__ks.insert_ed25519_verifying_key(self.uBirchUUID, self.uBirchPubkey)

        # load last signature for device
        self.load()

        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def persist(self):
        signatures = self.get_saved_signatures()
        with open(self.deviceUUID.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load(self):
        try:
            with open(self.deviceUUID.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.info("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, _, message: bytes) -> bytes:
        return self.__ks.find_signing_key(self.deviceUUID).sign(message)

    def _verify(self, _, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(self.deviceUUID).verify(signature, message)


class Main:
    """ an example implementation for the uBirch-Client in Python """
    def __init__(self):
        if len(sys.argv) < 3:
            print("usage:")
            print("  python3 example-client.py <UUID> <ubirch-auth-token> [ubirch-env]")
            
            sys.exit(1)

        # extract cli arguments
        self.env = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_UBIRCH_ENV
        self.uuid = UUID(hex=sys.argv[1])
        self.auth = sys.argv[2]

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

    def run(self):
        """ generate and send a message; verify the reponse """
        # create the message
        message = self.createMessage()

        logger.info("Created an example message: %s" % str(message))

        # create the upp
        upp = self.createUPP(message)

        logging.info("Created UPP: %s" % str(upp.hex()))

        # send the upp and handle the response
        resp = self.sendUPP(upp)
        self.handleBackendResponse(resp)

        # the handle function is expected to sys.exit() on any kind of error - assume success
        logging.info("Successfully sent the UPP and verified the response!")

        # save last signature
        self.protocol.persist()

    def checkRegisterPubkey(self):
        """ checks if the key is registered at the uBirch backend and registers it if necessary """
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
                sys.exit(1)

    def createMessage(self) -> dict:
        """ creates a unique example message """
        # create a message like being sent to the customer backend
        # include an ID and timestamp in the data message to ensure a unique hash
        return {
            "id": str(self.uuid),
            "ts": int(time.time()),
            "data": "{:d}".format(random.randint(0, 100))
        }

    def createUPP(self, message : dict) -> bytearray:
        """ creates an UPP from a given message """
        # create a compact rendering of the message to ensure determinism when creating the hash
        serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

        # hash the message
        messageHash = hashlib.sha256(serialized).digest()
        logger.info("message hash: {}".format(binascii.b2a_base64(messageHash).decode().rstrip("\n")))

        # create a new chained protocol message with the message hash
        upp = self.protocol.message_chained(self.uuid, UBIRCH_PROTOCOL_TYPE_BIN, messageHash)

        # set currentUPP
        self.currentUPP = upp

        return upp

    def sendUPP(self, upp : bytearray) -> Response:
        """ sends a UPP to the uBirch backend and returns the response object """
        # send chained protocol message to UBIRCH authentication service
        return self.api.send(self.uuid, upp)

    def handleBackendResponse(self, response : Response):
        """ handles the resonse object returned by sendUPP """
        # check the http status code
        #
        #   200: OK; try to verify the UPP
        #   XYZ: ERR; log the error and exit
        if response.status_code != codes.ok:
            logger.error("Sending UPP failed! response: ({}) {}".format(response.status_code, binascii.hexlify(response.content).decode()))
            sys.exit(1)

        logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(response.content).decode()))

        # unpack the UPP
        try:
            unpackedUPP = self.protocol.unpack_upp(response.content)
        except Exception as e:
            logger.error("Error unpacking the response UPP: '%s'" % str(response.content))
            logger.exception(e)

            sys.exit(1)

        # get the index of the signature and previous signature
        sigIndex     = self.protocol.get_unpacked_index(unpackedUPP[0], ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_SIG)
        prevSigIndex = self.protocol.get_unpacked_index(unpackedUPP[0], ubirch.ubirch_protocol.UNPACKED_UPP_FIELD_PREV_SIG)

        # check if a valid index for the signature was returned
        if sigIndex == -1:
            logger.error("The message returned by the backend doesn't contain a signature!")
            sys.exit(1)

        # verify that the response came from the backend
        try:
            self.protocol.verfiy_signature(response.content)
            logger.info("Backend response signature successfully verified!")
        except Exception as e:
            logger.error("Backend response signature verification FAILED!")
            logger.exception(e)
            sys.exit(1)

        # check if a valid index for the previous signature was returned
        if prevSigIndex == -1:
            logger.error("The message returned by the backend doesn't contain a previous signature!")
            sys.exit(1)
        
        # unpack the previously sent upp; assume that it is a valid chained upp
        unpackedPrevUpp = self.protocol.unpack_upp(self.currentUPP)

        # verfiy that the response contains the signature of our upp
        if unpackedPrevUpp[sigIndex] != unpackedUPP[prevSigIndex]:
            logger.error("The previous signature in the response UPP doesn't match the signature of our UPP!")
            logger.error("Previous signature in the response UPP: %s" % str(unpackedUPP[prevSigIndex].hex()))
            logger.error("Actual signature of our UPP: %s" % str(unpackedPrevUpp[prevSigIndex].hex()))
            sys.exit(1)
        else:
            logger.info("Matching previous signature!")


# initialize/"run" the Main class
if __name__ == "__main__":
    m = Main()
    m.run()