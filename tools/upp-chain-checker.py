import sys
import logging
import argparse
import binascii
import uuid
import ed25519
import ecdsa
import json
import hashlib

import ubirch
from ubirch.ubirch_protocol import UNPACKED_UPP_FIELD_UUID, UNPACKED_UPP_FIELD_PREV_SIG, UNPACKED_UPP_FIELD_SIG


DEFAULT_ISJSON = "false"
DEFAULT_ISHEX  = "false"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    def __init__(self, ks : ubirch.KeyStore):
        super().__init__()

        self.ks : ubirch.KeyStore = ks

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
        self.vk : ed25519.VerifyingKey or ecdsa.VerifyingKey = None
        self.vk_uuid : uuid.UUID = None
        self.vk_uuid_str : str = None

        self.input : str = None

        self.keystore : ubirch.KeyStore = None
        self.proto : ubirch.Protocol = None

        self.upps : [bytes] = None
        self.upp_uuid : uuid.UUID = None
        self.upp_uuid_str : str = None

        self.isjson : bool = None
        self.isjson_str : str = None

        self.ishex : bool = None
        self.ishex_str : str = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Check if a sequence of chained UPPs is valid/properly signed and correctly chained",
            epilog="The JSON file (when using --is-json true) es expected to contain a single field called \"upps\", which is a list of "
                   "hex-encoded UPPs. Otherwise (--is-json false). If --is-hex is true, it expects a sequence of hex-encoded UPPs "
                   "separated by newlines. The third (default) scenario is that the script expects a sequence of binary UPPs separated "
                   "by newlines.\n\nIf --is-json true is set, --is-hex will be ignored."
        )

        self.argparser.add_argument("inputfile", metavar="INPUTFILE", type=str,
            help="Input file path; e.g. upp_list.bin, upp_list.json or /dev/stdin"
        )
        self.argparser.add_argument("verifying_key", metavar="VK", type=str,
            help="key to be used for verification; any verifying key in hex like \"b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068\""
        )
        self.argparser.add_argument("verifying_key_uuid", metavar="UUID", type=str,
            help="the UUID for the verifying key; e.g.: 6eac4d0b-16e6-4508-8c46-22e7451ea5a1"
        )
        self.argparser.add_argument("--is-json", "-j", metavar="ISJSON", type=str, default=DEFAULT_ISJSON,
            help="If true, the script expects a JSON file for INPUTFILE (see below); e.g. true, false (default: %s)" % DEFAULT_ISHEX
        )
        self.argparser.add_argument("--is-hex", "-x", metavar="ISHEX", type=str, default=DEFAULT_ISHEX,
            help="If true, the script expects hex-encoded UPPs from the input file; e.g. true, false (default: %s)" % DEFAULT_ISHEX
        )
        
        return 

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.vk_str = self.args.verifying_key
        self.vk_uuid_str = self.args.verifying_key_uuid
        self.input = self.args.inputfile
        self.ishex_str = self.args.is_hex
        self.isjson_str = self.args.is_json

        # check the VK
        try:
            # get the key type from the key length
            if len(self.vk_str) == 128:
                logger.info("Determined the key to be ECDSA")

                self.vk = ecdsa.VerifyingKey.from_string(binascii.unhexlify(self.vk_str), curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
            else:
                logger.info("Determined the key to be ED25519")

                self.vk = ed25519.VerifyingKey(self.vk_str, encoding="hex")
        except Exception as e:
            logger.error("Invalid verifying key: \"%s\"" % self.vk_str)
            logger.exception(e)

            return False

        # check the UUID
        try:
            self.vk_uuid = uuid.UUID(hex=self.vk_uuid_str)
        except Exception as e:
            logger.error("Invalid UUID: \"%s\"" % self.vk_uuid_str)
            logger.exception(e)

            return False

        # get the ishex value
        if self.ishex_str.lower() in ["1", "yes", "y", "true"]:
            self.ishex = True
        else:
            self.ishex = False

        # get the ishex value
        if self.isjson_str.lower() in ["1", "yes", "y", "true"]:
            self.isjson = True
        else:
            self.isjson = False

        return True

    def read_upps(self) -> bool:
        # check whether json is enabled or not
        if self.isjson == True:
            try:
                # read the json file and get the upps from the contained list
                logger.info("Reading the input UPP json from \"%s\"" % self.input)

                with open(self.input, "rb") as fd:
                    input_json : dict = json.load(fd)

                # get the upps field
                upps_hex = input_json.get("upps")
                
                if upps_hex == None or type(upps_hex) != list:
                    raise Exception("input json must contain a \"upps\" filed which must be a list of hex-encoded UPPs!")

                # decode the hex-upps
                self.upps = list(map(lambda x: binascii.unhexlify(x), upps_hex))
            except Exception as e:
                logger.exception(e)

                return False
        else:
            # read the UPP from the input path
            try:
                logger.info("Reading the input UPPs from \"%s\"" % self.input)

                with open(self.input, "rb") as fd:
                    upp_list_raw = fd.read().splitlines()

                    # check whether hex decoding is needed
                    if self.ishex == True:
                        self.upps = list(map(lambda x: binascii.unhexlify(x), upp_list_raw))
                    else:
                        self.upps = upp_list_raw
            except Exception as e:
                logger.exception(e)

                return False

        logger.info("Read %d UPPs" % len(self.upps))

        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore("-- temporary --", None)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def check_cli_vk(self) -> bool:
        try:
            if self.vk != None:
                if isinstance(self.vk, ed25519.VerifyingKey):
                    self.keystore.insert_ed25519_verifying_key(self.vk_uuid, self.vk)
                else:
                    self.keystore.insert_ecdsa_verifying_key(self.vk_uuid, self.vk)

                logger.info("Inserted \"%s\": \"%s\" (UUID/VK) into the keystore" % (self.vk_uuid_str, self.vk_str))
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

    def verify_upps(self) -> bool:
        # store the signature of the last checked upp
        prev_sig = None

        try:
            for i in range(0, len(self.upps)):
                # check the signature
                if self.proto.verify_signature(self.vk_uuid, self.upps[i]) == False:
                    raise Exception("The signature cannot be verified with the given VK - the UPP is invalid - Aborting at UPP %d" % (i + 1))

                    

                # unpack the upp
                upp_unpacked = self.proto.unpack_upp(self.upps[i])

                # check whether the UUID matches with the given vk_uuid
                uuid_index = self.proto.get_unpacked_index(upp_unpacked[0], UNPACKED_UPP_FIELD_UUID)

                if upp_unpacked[uuid_index] != self.vk_uuid.bytes:
                    raise Exception("The UUID contained in UPP %s doesn't match the VK-UUID (%s vs. %s) - Aborting at UPP %d" %
                        (i + 1, uuid.UUID(bytes=upp_unpacked[uuid_index]), self.vk_uuid_str, i + 1)
                    )

                # check whether a prevsig check should be done
                if prev_sig != None:
                    # get the index of the previous signature
                    prevsig_index = self.proto.get_unpacked_index(upp_unpacked[0], UNPACKED_UPP_FIELD_PREV_SIG)

                    # check the return value - -1 means, that the UPP is not chained/doesn't contain a prevsig
                    if prevsig_index == -1:
                        raise Exception("UPP %d is NOT a chained UPP/doesn't contain a prevsig - Aborting at UPP %d" % (i + 1, i + 1))

                    # compare the signatures
                    if prev_sig != upp_unpacked[prevsig_index]:
                        raise Exception("The prevsig of UPP %d doesn't match the sig of UPP %d - Aborting at UPP %d" % (i + 1, i, i + 1))

                # set the new prevsig
                sig_index = self.proto.get_unpacked_index(upp_unpacked[0], UNPACKED_UPP_FIELD_SIG)

                if sig_index == -1:
                    raise Exception("UPP %d is NEITHER chained NOR signed/doesn't contain a signature - Aborting at UPP %d" % (i + 1, i + 1))

                prev_sig = upp_unpacked[sig_index]

            logger.info("All signatures verified and prevsigs compared - the UPP chain is valid!")
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
        if self.read_upps() != True:
            logger.error("Errors occured while reading the UPPs from \"%s\" - exiting!\n" % self.input)

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

        # initialize the Protocol
        if self.init_proto() != True:
            logger.error("Erros occured while initializing the Protocol - exiting!\n")

            self.argparser.print_usage()

            return 1

        # try to verify the message
        if self.verify_upps() != True:
            logger.error("Errors occured while verifying the UPPs - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


if __name__ == "__main__":
    sys.exit(Main().run())