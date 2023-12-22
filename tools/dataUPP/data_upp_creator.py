"""
Script to create a data-UPP from a dataset
"""

import binascii
import base64
import json
import logging
import pickle
import sys
import ed25519
import ecdsa
import hashlib
import argparse
from uuid import UUID

import ubirch

from ubirch.ubirch_protocol import UNPACKED_UPP_FIELD_PAYLOAD, UNPACKED_UPP_FIELD_TYPE


DEFAULT_TYPE     = "0x00"  # binary/unknown type
DEFAULT_VERSION  = "0x23"  # chained upp
DEFAULT_KS       = "devices.jks"
DEFAULT_KS_PWD   = "keystore"
DEFAULT_KEYREG   = "False"
DEFAULT_HASH     = "sha512"
DEFAULT_ISJSON   = "False"
DEFAULT_OUTPUT   = "upp.bin"
DEFAULT_ECDSA    = "False"

logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.DEBUG)
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
        signing_key = self._ks.find_signing_key(uuid)
        
        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return signing_key.sign(final_message)
    
    def pack_upp(self, msg: any) -> bytes:
        return self._serialize(msg)
        
########################################################################


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.data : str = None
        self.version : int = None
        self.version_str : str = None
        self.type : int = None
        self.type_str : str = None
        self.hash : str = None
        self.uuid : UUID = None
        self.uuid_str : str = None
        self.keystore : ubirch.KeyStore = None
        self.keystore_path : str = None
        self.keystore_pass : str
        self.output : str = None
        self.isjson_str : str = None
        self.isjson : bool = None
        self.keyreg_str : str = None
        self.keyreg : bool = None
        self.payload : bytes = None
        self.ecdsa_str : str = None
        self.ecdsa : bool = None

        self.hasher : object = None
        self.proto : Proto = None
        self.upp : bytes = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Create a Data uBirch Protocol Package (Data-UPP)",
            epilog="Note that when using chained UPPs (--version 0x23), this tool will try to load/save signatures to UUID.sig, where UUID will be replaced with the actual UUID. "
                   "Make sure that the UUID.sig file is in your current working directory if you try to continue a UPP chain using this tool."
                   "Also beware that you will only be able to access the contents of a keystore when you use the same password you used when creating it. Otherwise all contents are lost. "
                   "When --hash off is set, contents of the DATA argument will be copied into the payload field of the UPP. Normally used for special messages (e.g. key registration). "
                   "For more information on possible values for --type and --version see https://github.com/ubirch/ubirch-protocol."
        )

        self.argparser.add_argument("uuid", metavar="UUID", type=str,
            help="UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183"
        )
        self.argparser.add_argument("data", metavar="DATA", type=str,
            help="data to be packed into the UPP or hashed; e.g.: {\"t\": 23.4, \"ts\": 1624624140}"
        )
        self.argparser.add_argument("--version", "-v", metavar="VERSION", type=str, default=DEFAULT_VERSION,
            help="version of the UPP; 0x21 (unsigned; NOT IMPLEMENTED), 0x22 (signed) or 0x23 (chained) (default: %s)" % DEFAULT_VERSION
        )
        self.argparser.add_argument("--type", "-t", metavar="TYPE", type=str, default=DEFAULT_TYPE,
            help="type of the UPP (0 < type < 256); e.g.: 0x00 (unknown), 0x32 (msgpack), 0x53 (generic), ... (default and recommended: %s)" % DEFAULT_TYPE
        )
        self.argparser.add_argument("--ks", "-k", metavar="KS", type=str, default=DEFAULT_KS,
            help="keystore file path; e.g.: test.jks (default: %s)" % DEFAULT_KS
        )
        self.argparser.add_argument("--kspwd", "-p", metavar="KSPWD", type=str, default=DEFAULT_KS_PWD,
            help="keystore password; e.g.: secret (default: %s)" % DEFAULT_KS_PWD
        )
        self.argparser.add_argument("--keyreg", "-r", metavar="KEYREG", type=str, default=DEFAULT_KEYREG,
            help="generate a key registration UPP (data and --hash will be ignored); e.g.: true, false (default: %s)" % DEFAULT_KEYREG
        )
        self.argparser.add_argument("--hash", metavar="HASH", type=str, default=DEFAULT_HASH,
            help="hash algorithm for hashing the data; sha256, sha512 or off (disable hashing), ... (default and recommended: %s)" % DEFAULT_HASH
        )
        self.argparser.add_argument("--isjson", "-j", metavar="ISJSON", type=str, default=DEFAULT_ISJSON,
            help="tells the script to treat the input data as json and serialize it (see docs/DevTools.md for more information); true or false (default: %s)" % DEFAULT_ISJSON
        )
        self.argparser.add_argument("--output", "-o", metavar="OUTPUT", type=str, default=DEFAULT_OUTPUT,
            help="file to write the generated UPP to (aside from standard output); e.g. upp.bin (default: %s)" % DEFAULT_OUTPUT
        )
        self.argparser.add_argument("--ecdsa", "-c", metavar="ECDSA", type=str, default=DEFAULT_ECDSA,
            help="if set to true, the script will generate a ECDSA key (NIST256p, SHA256) instead of an ED25519 key in case no key was found for the UUID in the given keystore (default: %s)" % DEFAULT_ECDSA
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.data = self.args.data
        self.uuid_str = self.args.uuid
        self.version_str = self.args.version
        self.type_str = self.args.type
        self.keyreg_str = self.args.keyreg
        self.hash = self.args.hash
        self.isjson_str = self.args.isjson
        self.keystore_path = self.args.ks
        self.keystore_pass = self.args.kspwd
        self.output = self.args.output
        self.ecdsa_str = self.args.ecdsa

        # get the keyreg value
        if self.keyreg_str.lower() in ["1", "yes", "y", "true"]:
            self.keyreg = True
        else:
            self.keyreg = False

        # check the --hash argument
        if self.hash.lower() == "sha512":
            self.hasher = hashlib.sha512
        elif self.hash.lower() == "sha256":
            self.hasher = hashlib.sha256
        elif self.hash.lower() == "off":
            self.hasher = None
        else:
            logger.error("Invalid value for --hash: \"%s\" is not supported!" % self.hash)

            return False

        # check the uuid argument
        try:
            self.uuid = UUID(self.uuid_str)
        except ValueError as e:
            logger.error("Invalud UUID input string: \"%s\"!" % self.uuid_str)
            logger.exception(e)

            return False

        # check the version argument
        self.version = int(self.version_str, base=16 if "x" in self.version_str else 10)

        if self.version not in [0x22, 0x23]:
            logger.error("Unsupported value for the --version argument: \"0x%x\" (%d)" % (self.version, self.version))

            return False

        # check if the value for type is in range
        self.type = int(self.type_str, base=16 if "x" in self.type_str else 10)

        if not (0 <= self.type < 256):
            logger.error("Value for --type is out of range: \"0x%x\" (%d)" % (self.type, self.type))

            return False

        # get the isjson value
        if self.isjson_str.lower() in ["1", "yes", "y", "true"]:
            self.isjson = True
        else:
            self.isjson = False

        # get the bool for ecdsa
        if self.ecdsa_str.lower() in ["1", "yes", "y", "true"]:
            self.ecdsa = True
        else:
            self.ecdsa = False

        # success
        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore(self.keystore_path, self.keystore_pass)

            # check if the device already has keys or generate a new pair
            if not self.keystore.exists_signing_key(self.uuid):
                logger.info("No keys found for \"%s\" in \"%s\" - generating a keypair" % (self.uuid_str, self.keystore_path))

                if self.ecdsa == True:
                    logger.info("Generating a ECDSA keypair instead of ED25519!")
                    self.keystore.create_ecdsa_keypair(self.uuid)
                else:
                    self.keystore.create_ed25519_keypair(self.uuid)

            vk = self.keystore.find_verifying_key(self.uuid)

            if type(vk) == ubirch.ubirch_ks.ecdsa.VerifyingKey:
                vk_b = vk.to_string()
                k_t = "ECDSA"
            else:
                vk_b = vk.to_bytes()
                k_t = "ED25519"

            logger.info("Public/Verifying key for UUID: \"%s\" algortihm is:\"%s\", is [hex]: \"%s\" and [base64]: \"%s\"" %
                (self.uuid_str, k_t, binascii.hexlify(vk_b).decode(),  base64.b64encode(vk_b).decode()))
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def init_proto(self) -> bool:
        try:
            self.proto = Proto(self.keystore)
            self.proto.load(self.uuid)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def prepare_payload(self) -> bool:
        try:
            if self.hasher == None:
                self.payload = self.data.encode()

                logger.info("UPP payload (raw data): \"%s\"" % self.payload)
            else:
                if self.isjson == True:
                    # load the string as json and put it back into a string, serealizing it
                    self.data = json.loads(self.data)
                    self.data = json.dumps(self.data, separators=(',', ':'), sort_keys=True, ensure_ascii=False)

                    logger.info("Serialized data JSON: \"%s\"" % self.data)

                self.payload = self.hasher(self.data.encode()).digest()

                logger.info("UPP payload (%s hash of the data) [base64]: \"%s\"" % (self.hash, base64.b64encode(self.payload).decode().rstrip("\n")))
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def create_upp(self) -> bool:
        try:
            if self.keyreg == True:
                # generate a key registration upp
                logger.info("Generating a key registration UPP for UUID \"%s\"" % self.uuid_str)

                self.upp = self.proto.message_signed(self.uuid, ubirch.ubirch_protocol.UBIRCH_PROTOCOL_TYPE_REG, self.keystore.get_certificate(self.uuid))
                pass
            else:
                if self.version == 0x22:
                    logger.info("Generating a unchained signed UPP for UUID \"%s\"" % self.uuid_str)

                    self.upp = self.proto.message_signed(self.uuid, self.type, self.payload)
                elif self.version == 0x23:
                    logger.info("Generating a chained signed UPP for UUID \"%s\"" % self.uuid_str)

                    self.upp = self.proto.message_chained(self.uuid, self.type, self.payload)

                    # save the new signature
                    self.proto.persist(self.uuid)
                else:
                    # shouldnt get here/unsupported versions are caught in process_args()
                    raise(ValueError("Unsupported UPP version"))
                
            logger.info("packed UPP [hex]: \"%s\"" % binascii.hexlify(self.upp).decode())
        except Exception as e:
            logger.exception(e)

            return False

        return True
    
    def create_data_upp(self) -> bool:
        try:
            # unpack the upp
            upp_unpacked = self.proto.unpack_upp(self.upp)

            # determine the index of the payload field
            payload_index = self.proto.get_unpacked_index(upp_unpacked[0], UNPACKED_UPP_FIELD_PAYLOAD)
            # replace the hash with the data
            upp_unpacked[payload_index] = self.data.encode()

            # determine the index of the type field
            type_index = self.proto.get_unpacked_index(upp_unpacked[0], UNPACKED_UPP_FIELD_TYPE)
            # replace the type with 0x70
            upp_unpacked[type_index] = 0x70

            # pack the upp again
            self.upp = self.proto.pack_upp(upp_unpacked)

        except Exception as e:
            logger.exception(e)

            return False

        return True

    def show_store_data_upp(self) -> bool:
        try:
            logger.info("data-UPP [hex]: \"%s\"" % binascii.hexlify(self.upp).decode())

            # try to write the upp
            with open(self.output, "wb") as file:
                file.write(self.upp)

            logger.info("data-UPP written to \"%s\"" % self.output)

        except Exception as e:
            logger.exception(e)

            return False

        return True

    def run(self) -> int:
        # process all raw argument values
        if self.process_args() != True:
            logger.error("Errors occured during argument processing - exiting!\n")

            self.argparser.print_usage()

            return 1

        # initialize the keystore
        if self.init_keystore() != True:
            logger.error("Errors occured while initializing the uBirch Keystore - exiting!\n")

            self.argparser.print_usage()

            return 1

        # initialize the uBirch protocol
        if self.init_proto() != True:
            logger.error("Errors occured while initializing the uBirch protocol - exiting!\n")

            self.argparser.print_usage()

            return 1

        # prepare the UPP payload
        if self.prepare_payload() != True:
            logger.error("Errors occured while preparing the UPP payload - exiting!\n")

            self.argparser.print_usage()

            return 1

        # create the UPP
        if self.create_upp() != True:
            logger.error("Errors occured while creating the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1
        
        # replace the hash with the data
        if self.create_data_upp() != True:
            logger.error("Errors occured while creating the data UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        # show and store the UPP
        if self.show_store_data_upp() != True:
            logger.error("Erros occured while showing/storing the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())

