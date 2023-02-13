import sys
import logging
import argparse
import msgpack
import binascii
import uuid
import ed25519
import ecdsa
import hashlib

import ubirch


DEFAULT_INPUT = "/dev/stdin"
DEFAULT_ISHEX = "false"
DEFAULT_ISECD = "false"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    # UUIDs paired with public keys of uBirch Niomon on all stages
    UUID_DEV = uuid.UUID(hex="9d3c78ff-22f3-4441-a5d1-85c636d486ff")
    PUB_DEV = ed25519.VerifyingKey("a2403b92bc9add365b3cd12ff120d020647f84ea6983f98bc4c87e0f4be8cd66", encoding='hex')
    UUID_DEMO = uuid.UUID(hex="07104235-1892-4020-9042-00003c94b60b")
    PUB_DEMO = ed25519.VerifyingKey("39ff77632b034d0eba6d219c2ff192e9f24916c9a02672acb49fd05118aad251", encoding='hex')
    UUID_PROD = uuid.UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = ed25519.VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, ks : ubirch.KeyStore):
        super().__init__()

        self.ks : ubirch.KeyStore = ks

        # insert all keys defined above into the keystore
        if not self.ks.exists_verifying_key(self.UUID_DEV):
            self.ks.insert_ed25519_verifying_key(self.UUID_DEV, self.PUB_DEV)
        if not self.ks.exists_verifying_key(self.UUID_DEMO):
            self.ks.insert_ed25519_verifying_key(self.UUID_DEMO, self.PUB_DEMO)
        if not self.ks.exists_verifying_key(self.UUID_PROD):
            self.ks.insert_ed25519_verifying_key(self.UUID_PROD, self.PUB_PROD)

    def _verify(self, uuid: uuid.UUID, message: bytes, signature: bytes):
        verifying_key = self.ks.find_verifying_key(uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            final_message = message
        elif isinstance(verifying_key, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest()
        else:
            raise(ValueError("Verifying Key is neither ed25519, nor ecdsa!"))

        return verifying_key.verify(signature, final_message)


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.vk_str : str = None
        self.vk : ed25519.VerifyingKey = None
        self.vk_uuid : uuid.UUID = None
        self.vk_uuid_str : str = None

        self.input : str = None

        self.keystore : ubirch.KeyStore = None
        self.proto : ubirch.Protocol = None

        self.upp : bytes = None
        self.upp_uuid : uuid.UUID = None
        self.upp_uuid_str : str = None

        self.ishex : bool = None
        self.ishex_str : str = None
        self.isecd : bool = None
        self.isecd_str : str = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Check if a UPP is valid/properly signed",
            epilog="Note that when trying to verify a UPP sent by the uBirch backend (Niomon) a verifying key doesn't have to be provided via the -k option."
                   "Instead, this script will try to pick the correct stage key based on the UUID which is contained in the UPP, identifying the creator."
                   "If the UUID doesn't match any Niomon stage and no key was specified using -k, an error message will be printed."
        )

        self.argparser.add_argument("--verifying-key", "-k", metavar="VK", type=str, default="AUTO",
            help="key to be used for verification; any verifying key in hex like \"b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068\""
        )
        self.argparser.add_argument("--verifying-key-uuid", "-u", metavar="UUID", type=str, default="EMPTY",
            help="the UUID for the key supplied via -k (only needed when -k is specified); e.g.: 6eac4d0b-16e6-4508-8c46-22e7451ea5a1"
        )
        self.argparser.add_argument("--ishex", "-x", metavar="ISHEX", type=str, default=DEFAULT_ISHEX,
            help="Sets whether the UPP input data is a hex string or binary; e.g. true, false (default: %s)" % DEFAULT_ISHEX
        )
        self.argparser.add_argument("--isecd", "-c", metavar="ISECD", type=str, default=DEFAULT_ISECD,
            help="Sets whether the key provided with -k is a ECDSA NIST256p SHA256 key (true) or a ED25519 key (false) (default: %s)" % DEFAULT_ISECD
        )
        self.argparser.add_argument("--input", "-i", metavar="INPUT", type=str, default=DEFAULT_INPUT,
            help="UPP input file path; e.g. upp.bin or /dev/stdin (default: %s)" % DEFAULT_INPUT
        )
        
        return 

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.vk_str = self.args.verifying_key
        self.vk_uuid_str = self.args.verifying_key_uuid
        self.input = self.args.input
        self.ishex_str = self.args.ishex
        self.isecd_str = self.args.isecd

        # get the ishex value
        if self.ishex_str.lower() in ["1", "yes", "y", "true"]:
            self.ishex = True
        else:
            self.ishex = False

        # get the isecd value
        if self.isecd_str.lower() in ["1", "yes", "y", "true"]:
            self.isecd = True
        else:
            self.isecd = False

        return True

    def read_upp(self) -> bool:
        # read the UPP from the input path
        try:
            logger.info("Reading the input UPP from \"%s\"" % self.input)

            with open(self.input, "rb") as fd:
                self.upp = fd.read()

                # check whether hex decoding is needed
                if self.ishex == True:
                    self.upp = binascii.unhexlify(self.upp)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore("-- temporary --", None)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def check_cli_vk(self) -> bool:
        # check if a verifying key was supplied
        if self.vk_str != "AUTO":
            # check if a uuid was supplied
            if self.vk_uuid_str == "EMPTY":
                logger.error("--verifying-key-uuid/-u must be specified when --verifying-key/-k is specified!")

                return False

            # load the uuid
            try:
                self.vk_uuid = uuid.UUID(hex=self.vk_uuid_str)
            except Exception as e:
                logger.error("Invalid UUID supplied via --verifying-key-uuid/-u: \"%s\"" % self.vk_uuid_str)
                logger.exception(e)

                return False

            # check the keytype, load it and insert it into the keystore
            try:
                if self.isecd == False:
                    logger.info("Loading the key as ED25519 verifying key")

                    self.vk = ed25519.VerifyingKey(self.vk_str, encoding="hex")
                    self.keystore.insert_ed25519_verifying_key(self.vk_uuid, self.vk)
                else:
                    logger.info("Loading the key as ECDSA NIST256p SHA256 verifying key")

                    self.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(self.vk_str), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
                    self.keystore.insert_ecdsa_verifying_key(self.vk_uuid, self.vk)
            except Exception as e:
                logger.error("Error loading the verifying key and inserting it into the keystore")
                logger.exception(e)

                return False

            logger.info("Inserted \"%s\": \"%s\" (UUID/VK) into the keystore" % (self.vk_uuid_str, self.vk_str))


        return True

    def get_upp_uuid(self) -> bool:
        try:
            # unpack the upp
            unpacked = msgpack.unpackb(self.upp)
            
            # get the uuid
            self.upp_uuid = uuid.UUID(bytes=unpacked[1])
            self.upp_uuid_str =str(self.upp_uuid)

            logger.info("UUID of the UPP creator: \"%s\"" % self.upp_uuid_str)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def init_proto(self) -> bool:
        try:
            self.proto = Proto(self.keystore)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def verify_upp(self) -> bool:
        try:
            if self.proto.verify_signature(self.upp_uuid, self.upp) == True:
                logger.info("Signature verified - the UPP is valid!")
            else:
                logger.info("The signature does not match - the UPP is invalid!")
        except KeyError:
            logger.error("No verifying key found for UUID \"%s\" - can't verify the UPP!" % self.upp_uuid_str)

            return False
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def run(self):
        # process all args
        if self.process_args() != True:
            logger.error("Errors occured during argument processing - exiting!\n")

            self.argparser.print_usage()

            return 1

        # read the upp
        if self.read_upp() != True:
            logger.error("Errors occured while reading the UPP from \"%s\" - exiting!\n" % self.input)

            self.argparser.print_usage()

            return 1

        # initialize the keystore
        if self.init_keystore() != True:
            logger.error("Errors occured while initializing the keystore - exiting!\n")

            self.argparser.print_usage()

            return 1

        # check/insert the cli-provided verifying key
        if self.check_cli_vk() != True:
            logger.error("Errorc occured while inserting the verifying key into the keystore - exiting!\n")

            self.argparser.print_usage()

            return 1

        # get the uuid
        if self.get_upp_uuid() != True:
            logger.error("Errors occured while extracting the UUID from the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        # initialize the Protocol
        if self.init_proto() != True:
            logger.error("Erros occured while initializing the Protocol - exiting!\n")

            self.argparser.print_usage()

            return 1

        # try to verify the message
        if self.verify_upp() != True:
            logger.error("Errors occured while verifying the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


if __name__ == "__main__":
    sys.exit(Main().run())