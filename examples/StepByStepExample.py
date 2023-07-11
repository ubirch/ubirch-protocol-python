import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UNPACKED_UPP_FIELD_PREV_SIG
from ubirch.ubirch_backend_keys import EDDSA_TYPE, ECDSA_TYPE 

import time, json, pickle, hashlib, binascii, ecdsa, ed25519, sys, uuid
from requests import codes


DEFAULT_KEY_TYPE = "ed25519"
DEFAULT_ENV = "demo"


class Proto(ubirch.Protocol):
    """!
    This class is a wrapper for the ubirch.Protocol class.
    It adds functionality for handling keys with different algorithms 
    and persitent signature handling via pickle. 
    """    
    def __init__(self, keystore: ubirch.KeyStore, key_type: str, env : str, ident_uuid: uuid.UUID):
        super().__init__()
        self.__ks = keystore
        self.load_saved_signatures(ident_uuid)

        # check the key type and set the corresponding hash algorithm
        if key_type == ECDSA_TYPE:
            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(ident_uuid):
                print("Generating new keypair with ecdsa algorithm")
                self.__ks.create_ecdsa_keypair(ident_uuid)

            # make sure there is no ed25519 verifying key for the backend
            self.__ks.delete_ed25519_verifying_key(ubirch.get_backend_uuid(env))

            # insert the ecdsa verifying key for the backend
            self.__ks.insert_ecdsa_verifying_key(ubirch.get_backend_uuid(env),
                                                 ubirch.get_backend_verifying_key(env, ECDSA_TYPE))
            
            # select the hash algorithm for the signature
            self.hash_algo = hashlib.sha256
        
        elif key_type == EDDSA_TYPE:
            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(ident_uuid):
                print("Generating new keypair with ed25519 algorithm")
                self.__ks.create_ed25519_keypair(ident_uuid)

            # make sure there is no ecdsa verifying key for the backend
            self.__ks.delete_ecdsa_verifying_key(ubirch.get_backend_uuid(env))

            # insert the ed25519 verifying key for the backend
            self.__ks.insert_ed25519_verifying_key(ubirch.get_backend_uuid(env),
                                                   ubirch.get_backend_verifying_key(env, EDDSA_TYPE))
            
            # select the hash algorithm for the signature
            self.hash_algo = hashlib.sha512


    def _sign(self, ident_uuid: uuid.UUID, message: bytes):
        signing_key = self.__ks.find_signing_key(ident_uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            return signing_key.sign(message)

        elif isinstance(signing_key, ed25519.SigningKey):
            hashed_message = hashlib.sha512(message).digest()
            return signing_key.sign(hashed_message)

        else:
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa! It's: " + str(type(signing_key))))

    def _verify(self, ident_uuid: uuid.UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(ident_uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            return verifying_key.verify(signature, message)

        elif isinstance(verifying_key, ed25519.VerifyingKey):
            hashed_message = hashlib.sha512(message).digest()
            return verifying_key.verify(signature, hashed_message)

        else:
            raise (ValueError("Verifying Key is neither ed25519, nor ecdsa! It's: " + str(type(verifying_key))))

    def persist_signatures(self, ident_uuid: uuid.UUID):
        """! persist the latest signatures to a file """
        signatures = self.get_saved_signatures()
        with open(ident_uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load_saved_signatures(self, ident_uuid: uuid.UUID):
        """! load the latest signatures from a file """
        try:
            with open(ident_uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                print("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError or EOFError:
            print("no existing saved signatures")
            pass


def usage_exit():
    """! print usage and exit """
    print(
            "Usage: python StepByStepExample.py <Keystore Path> <Keystore Password> <UUID> <Authentication Token> [uBirch Environment] [Crypto Algorithm]\n\n"
            "       Keystore Path           Path to the Keystore. If it doesn't exist yet, it will be created.\n"
            "       Keystore Password       Password for the Keystore.\n"
            "       UUID                    UUID of the device, i.e. '01234567-1234-2345-3456-0123456789abc' \n"
            "       Authentication Token    Authentication token to be used for the uBirch backend.\n"
            "       uBirch Environment      The uBirch Environment to be used. 'dev', 'demo' or 'prod'. Optional, default is '" + DEFAULT_ENV + "'\n"
            "       Crypto Algorithm        The crypto algorithm to be used. 'ed25519' or 'ecdsa'. Optional, default is '" + DEFAULT_KEY_TYPE + "'\n"
        )

    sys.exit(-1)


if __name__ == "__main__":
    # check command line parameters
    if len(sys.argv) < 5:
        usage_exit()

    keystore_path = sys.argv[1]
    keystore_pass = sys.argv[2]
    ident_uuid : uuid.UUID = uuid.UUID(hex=sys.argv[3])
    auth_token = sys.argv[4]
    
    # check whether the environment is provided
    if len(sys.argv) > 5:
        ubirch_env = sys.argv[5].lower()

        if not ubirch_env in ubirch.get_backend_environemts():
            print(f"Error: Provided uBirch environment '{ubirch_env}' is not valid! Must be one of {ubirch.get_backend_environemts()}!")

            usage_exit()
    else:
        ubirch_env = DEFAULT_ENV.lower()

    # check whether the key type is provided
    if len(sys.argv) > 6:
        key_type = sys.argv[6].lower()

        if not key_type in [EDDSA_TYPE, ECDSA_TYPE]:
            print(f"Error: Provided key type '{key_type}' is not valid! Must be one of {[EDDSA_TYPE, ECDSA_TYPE]}!")

            usage_exit()
    else:   
        key_type = DEFAULT_KEY_TYPE.lower()

    # ========== Initialize all Ubirch components ========== #
    # open or create a keystore for the device
    # note: you can use your own key management tool instead
    keystore = ubirch.KeyStore(keystore_path, keystore_pass)

    # create an instance of the protocol with signature saving
    protocol = Proto(keystore, key_type, ubirch_env, ident_uuid)

    # create an instance of the UBIRCH API and set the auth token
    api = ubirch.API(env=ubirch_env)
    api.set_authentication(ident_uuid, auth_token)

    print("Initializing uBirch protocol with the following parameters:")
    print("  - UUID: {}".format(ident_uuid))
    print("  - Authentication Token: {}".format(auth_token))
    print("  - uBirch Environment: {}".format(ubirch_env))
    print("  - Crypto Algorithm: {}".format(key_type))

    #======================== 'Register' device ========================#
    # check if the public key is registered at the Ubirch key service and register it if necessary
    if not api.is_identity_registered(ident_uuid):
        print("Device is not registered yet. Registering now...")
        # get the certificate and create the registration message
        certificate = keystore.get_certificate(ident_uuid)
        key_registration = protocol.message_signed(ident_uuid, UBIRCH_PROTOCOL_TYPE_REG, certificate)
        print("Registration message: {}".format(binascii.hexlify(key_registration)))

        # send the registration message and catch any errors that could have come up
        response = api.register_identity(key_registration)

        print("Registration response: ({}) {}".format(response.status_code, response.content))
        if response.status_code != codes.ok:
            raise Exception("Registration failed!")
    else:
        print("Device is already registered.")

    #======================== 'Generate' data ========================#
    data = {
        "timestamp": time.time(),
        "temperature": 11.2,
        "humidity": 35.8,
        "status": "OK"
    }

    #=========== Create and send a Ubirch protocol packet ==========#
    # Create a compact rendering of the message to ensure determinism when creating the hash
    serialized = json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    print(f"Serialized message: {serialized}")

    # Hash the message using the configured hash algorithm
    hashed_data = protocol.hash_algo(serialized).digest()
    print("Message hash (base64): {}".format(binascii.b2a_base64(hashed_data).decode().rstrip("\n")))

    # Create a new chained protocol message with the message hash
    # UBIRCH_PROTOCOL_TYPE_BIN is the type-code of a standard binary message: '0x00'
    message_UPP = protocol.message_chained(ident_uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_BIN, hashed_data)
    print("Message UPP (hex): {}".format(binascii.hexlify(message_UPP)))

    # send the message to the Ubirch authentication service and catch any errors that could have come up
    response = api.send(ident_uuid, message_UPP)

    if response.status_code != codes.ok:
        raise Exception("Sending UPP failed!")
    else:
        print("Sending UPP successful!")
 
    print("Response code: ({})".format(response.status_code))
    print("Response UPP (hex):{}".format(binascii.hexlify(response.content)))
 
    # ================== Response UPP verification ==================#
    #= Verify that the response came from the backend =#
    if protocol.verify_signature(ubirch.get_backend_uuid(ubirch_env), response.content) == True:
        print("Backend response signature successfully verified!")
    else:
        raise Exception("Backend response signature verification FAILED!")

    #= Verify that the UPP is correctly chained. =#
    # The previous signature in the response UPP has to be the same as the sent UPPs Signature
    _, signature_message_UPP = protocol.upp_msgpack_split_signature(message_UPP)

    # unpack the received upp to get its previous signature
    unpacked = protocol.unpack_upp(response.content)
    signature_index = protocol.get_unpacked_index(unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)
    previous_signature_in_UPP = unpacked[signature_index]

    if signature_message_UPP == previous_signature_in_UPP:
        print("Sent UPP is correctly chained! The previous signature in the response UPP is the same as the sent UPPs signature")
    else:
        raise Exception("The previous signature in the response UPP doesn't match the signature of our UPP!")

    # save last signatures to a .sig file
    protocol.persist_signatures(ident_uuid)

    # the handle, verification and assert functions raise Errors on any kind of error - save to assume success
    print("[✓] Successfully sent the UPP and verified the response!")
