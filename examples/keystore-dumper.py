import sys
import time
import argparse
import logging
import binascii
import uuid

import ubirch


DEFAULT_SHOW_SIGN = "False"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.keystore_path : str = None
        self.keystore_pass : str = None
        self.show_sign_str : str = None
        self.show_sign : bool = None

        self.keystore : ubirch.KeyStore = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Dump the contents of a keystore (.jks)",
            epilog=""
        )

        self.argparser.add_argument("keystore", metavar="KEYSTORE", type=str,
            help="keystore file path; e.g.: test.jks"
        )
        self.argparser.add_argument("keystore_pass", metavar="KEYSTORE_PASS", type=str,
            help="keystore password; e.g.: secret"
        )
        self.argparser.add_argument("--show-sk", "-s", metavar="SHOW_SIGNING_KET", type=str, default=DEFAULT_SHOW_SIGN,
            help="enables/disables showing of signing keys; e.g.: true, false (default: %s)" % DEFAULT_SHOW_SIGN
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.keystore_path = self.args.keystore
        self.keystore_pass = self.args.keystore_pass
        self.show_sign_str = self.args.show_sk

        # get the bool for show sk
        if self.show_sign_str.lower() in ["1", "yes", "y", "true"]:
            self.show_sign = True
        else:
            self.show_sign = False
        
        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore(self.keystore_path, self.keystore_pass)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def dump_keystore(self) -> bool:
        verifying_keys = self.keystore._ks.certs
        signing_keys = self.keystore._ks.private_keys

        # go trough the list of verifiying keys and print information for each entry
        for vk_uuid in verifying_keys.keys():
            if self.show_sign == True:
                t = signing_keys.get("pke_" + vk_uuid)

                sk = binascii.hexlify(t.pkey).decode() if t != None else "N / A"
            else:
                sk = "█" * 128

            print("=" * 134)
            print("UUID: %s" % str(uuid.UUID(hex=vk_uuid)))
            print(" VK : %s" % binascii.hexlify(verifying_keys[vk_uuid].cert).decode())
            print(" SK : %s" % sk)
            print("=" * 134)

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

        if self.dump_keystore() != True:
            logger.error("Errors occured while dumping the uBirch Keystore - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
