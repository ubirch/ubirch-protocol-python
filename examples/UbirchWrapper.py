import binascii
import hashlib
import json
import logging
import pickle
import ecdsa
import ed25519
from uuid import UUID

from requests import codes, Response

import ubirch
from ubirch.ubirch_protocol import UNPACKED_UPP_FIELD_PREV_SIG, UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

UBIRCH_PUBKEYS_ED = {
    "dev": ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding="hex"),
    # NOTE: this environment is not reliable
    "demo": ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding="hex"),
    "prod": ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding="hex")
}

UBIRCH_PUBKEYS_EC = {
    "dev": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "2e753c064bc671940fcb98165542fe3c70340cff5d53ad47f0304ef2166f4f223b9572251b5fe8aee54c4fb812da79590caf501beba0911b7fcd3add2eb0180c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),  # NOTE: this environment is not reliable
    "demo": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "c66fa222898146347741dbcb26b184d4e06cddb01ff04238f457e006b891937ea7e115185fed2c9ab60af2d66497a2e1aedf65ce38941ab5c68a3468544f948c"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
    "prod": ecdsa.VerifyingKey.from_string(binascii.unhexlify(
        "a49758a0937437741314c0558d955089ed61860ba64154f2da45fd23b9178d2ca8225e3410e6bd317db848100004157bc55d88162d4a58c9c2d5a2ce22f3908d"
    ), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256),
}

UBIRCH_UUIDS = {
    "dev": UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff"),  # NOTE: this environment is not reliable
    "demo": UUID(hex="07104235-1892-4020-9042-00003c94b60b"),
    "prod": UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
}

# create a global logger
logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    """!
    Implement the ubirch-protocol, including creating and saving signatures.
    Actually a wrapper around 'ubirch.Protocol' to be accessible using the ubirch.KeyStore.
    Most of the functions are called from inside ubirch.Protocol.
    For that reason _sign() and _verify() are overloaded and implemented here.
    """

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID, env: str, key_type: str) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not self.__ks.exists_signing_key(uuid):
            # check the key type before creating new keys
            if key_type == "ed25519":
                logger.info("generating new keypair with ed25519 algorithm")

                self.__ks.create_ed25519_keypair(uuid)
            elif key_type == "ecdsa":
                logger.info("generating new keypair with ecdsa algorithm")

                self.__ks.create_ecdsa_keypair(uuid)
            else:
                raise ValueError("unknown key type")

        # figure out, which key type is used, which is relevant for the backend response verification
        temp_vk = self.__ks.find_verifying_key(uuid)
        if isinstance(temp_vk, ed25519.VerifyingKey):
            temp_key_type = "ed25519"
        elif isinstance(temp_vk, ecdsa.VerifyingKey):
            temp_key_type = "ecdsa"

        # check env
        if env not in UBIRCH_PUBKEYS_ED.keys():
            raise ValueError("Invalid ubirch env! Must be one of {}".format(list(UBIRCH_PUBKEYS_ED.keys())))

        # check if the keystore has the same key_type for the device UUID and the backend response
        if temp_key_type == "ecdsa":
            if self.__ks._ks.entries.get(UBIRCH_UUIDS[env].hex, None) != None:
                # suffix-less pubkey found, delete it
                self.__ks._ks.entries.pop(UBIRCH_UUIDS[env].hex)

            self.__ks.insert_ecdsa_verifying_key(UBIRCH_UUIDS[env], UBIRCH_PUBKEYS_EC[env])
        elif temp_key_type == "ed25519":
            if self.__ks._ks.entries.get(UBIRCH_UUIDS[env].hex + '_ecd', None) != None:
                # suffix-less pubkey found, delete it
                self.__ks._ks.entries.pop(UBIRCH_UUIDS[env].hex + '_ecd')

            self.__ks.insert_ed25519_verifying_key(UBIRCH_UUIDS[env], UBIRCH_PUBKEYS_ED[env])

        # load last signature for device
        self.load(uuid)

        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def persist(self, uuid: UUID):

        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    #===== The functions below are called from inside ubirch.Protocol ====#
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
        signing_key = self.__ks.find_signing_key(uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest()
        else:
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa!"))

        return signing_key.sign(final_message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            final_message = message
        elif isinstance(verifying_key, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest()
        else:
            raise (ValueError("Verifying Key is neither ed25519, nor ecdsa!"))

        return verifying_key.verify(signature, final_message)


class UbirchClient:
    """!
    An example implementation for the ubirch-client in Python.
    Actually another wrapper. Around 'Proto' defined above.
    Keystore and API to be added directly after init.
    """

    def __init__(self, uuid: UUID, auth: str, key_type:str="ed25519", env:str="demo", keystore_name:str = None, keystore_password:str = None):
        """!
        Depending on the arguments passed all uBirch modules will be initialized:
          If keystore credentials are given create Keystore, Proto and API
        """

        # Initialize a UbirchClient where default setting is ed25519 key type and demo environment
        self.env = env
        self.uuid = uuid
        self.auth = auth
        self.key_type = key_type

        self.savedCurrentSig = None
        # a variable to store the current signature

        if keystore_name is not None and keystore_password is not None:

            self.keystore = ubirch.KeyStore(keystore_name, keystore_password)
            # create a keystore for the device

            self.protocol = Proto(self.keystore, self.uuid, self.env, key_type=self.key_type)
            # create an instance of the protocol with signature saving

            self.api = ubirch.API(env=self.env)
            self.api.set_authentication(self.uuid, self.auth)
            # create an instance of the UBIRCH API and set the auth token

    def checkRegisterPubkey(self):
        """
        Check if the public key is registered at the ubirch key service and register it if necessary
        Calls handleRegistrationResponse()
        """
        if not self.api.is_identity_registered(self.uuid):

            certificate = self.keystore.get_certificate(self.uuid)
            key_registration = self.protocol.message_signed(self.uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
            # get the certificate and create the registration message

            response = self.api.register_identity(key_registration)
            self.handleResponseToRegistration(response)
            # send the registration message and catch any errors that could have come up

    def handleRegistrationResponse(self, response: Response):
        """! Check for success """
        if response.status_code == codes.ok:
            logger.info("{}: public key registered".format(self.uuid))
        else:
            logger.error("{}: registration failed".format(self.uuid))

            raise Exception("Failed to register the public key!")

    def serializeMessage(self, message: dict)  -> bytes:
        """! Serialize a JSON object to bytes """
        serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
        # create a compact rendering of the message to ensure determinism when creating the hash
        # serializes JSON like this '{"T": 11.2, "H": 35.8, "S": "OK", "ts":"1652452008"}'

        return serialized

    def extractCurrentSignature(self, currentUPP) -> bytes:
        """! Extract the signature from a UPP """
        _, currentSig = self.protocol.upp_msgpack_split_signature(currentUPP)
        logger.info("current signature: {}".format(currentSig))

        return currentSig

    def createUPP(self, message: dict) -> bytes:
        """!
        Create a UPP from a given message
        Calls serializeAndCreateHash() and extractCurrentSignature()
        """
        serialized = self.serializeMessage(message)
        # Serializes a JSON object to bytes

        messageHash = hashlib.sha512(serialized).digest()
        logger.info("message hash: {}".format(binascii.b2a_base64(messageHash).decode().rstrip("\n")))
        # Hash the message using SHA512

        currentUPP = self.protocol.message_chained(self.uuid, UBIRCH_PROTOCOL_TYPE_BIN, messageHash)
        logger.info("created UPP: {}".format(currentUPP.hex()))
        # create a new chained protocol message with the message hash

        self.savedCurrentSig = self.extractCurrentSignature(currentUPP)
        # extract the signature and save it for verification later

        return currentUPP

    def handleMessageResponse(self, response: Response):
        """! Handles the response object returned by sendUPP """
        # check the http status code
        #
        #   200: OK; try to verify the UPP
        #   XYZ: ERR; log the error and exit

        if response.status_code != codes.ok:
            logger.error("Sending UPP failed! response: ({}) {}".format(response.status_code,
                                                                        binascii.hexlify(response.content).decode()))
            raise (Exception("Exiting due to failure sending the UPP to the backend or authentication errors!"))

        logger.info("UPP successfully sent. response: {}".format(binascii.hexlify(response.content).decode()))

    def verifyResponseSender(self, response: Response):
        """! Verify that the response came from the backend """
        if self.protocol.verfiy_signature(UBIRCH_UUIDS[self.env], response.content) == True:
            logger.info("Backend response signature successfully verified!")
        else:
            logger.error("Backend response signature verification FAILED!")

            raise (Exception("Exiting due to failed signature verification!"))

    def extractPreviousSignature(self, response: Response) -> bytes:
        """! Unpack the received upp to get its previous signature """
        unpacked = self.protocol.unpack_upp(response.content)
        signature_index = self.protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)
        previousSignature = unpacked[signature_index]

        return previousSignature

    def assertSignatureCorrect(self, previousSignature, currentSignature=None) -> bool:
        """! Verify that the response contains the signature of our upp """
        if currentSignature == None: # If currentSignature isn't given fall back on saved signature in self.savedCurrentSig
            if self.savedCurrentSig == None:
                logger.error("Argument Error! No current signature given")

                raise (Exception("Exiting due to missing current signature"))
            else:
                currentSignature = self.savedCurrentSig

        if currentSignature != previousSignature:
            logger.error("The previous signature in the response UPP doesn't match the signature of our UPP!")
            logger.error("Previous signature in the response UPP: %s" % str(previousSignature.hex()))
            logger.error("Actual signature of our UPP: %s" % str(currentSignature.hex()))

            raise (Exception("Exiting due to a non-matching signature in the response UPP!"))
        else:
            logger.info("Sent UPP is correctly chained! The previous signature in the response UPP is the same as the sent UPPs Signature")
            return True

