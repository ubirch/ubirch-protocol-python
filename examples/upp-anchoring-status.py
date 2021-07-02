import sys
import time
import argparse
import logging
import msgpack
import uuid
import base64
import json
import requests


VERIFICATION_SERVICE = "https://verify.%s.ubirch.com/api/upp/verify/anchor"

DEFAULT_ISHASH = "False"
DEFAULT_ENV    = "dev"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.input : str = None
        self.env : str = None
        self.ishash_str : str = None
        self.ishash : bool = None

        self.upp : bytes = None
        self.hash : str = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Requests the verification/anchoring of a UPP from the uBirch backend",
            epilog="When --ishash/-i is set to true, the input argument is treated as a base64 payload hash. "
                   "Otherwise, it is expected to be some kind of path to read a UPP from. "
                   "This can be a file path or also /dev/stdin if the UPP is piped to this program via standard input."
        )

        self.argparser.add_argument("input", metavar="INPUT", type=str,
            help="input hash or upp path (depends on --ishash)"
        )
        self.argparser.add_argument("--ishash", "-i", metavar="ISHASH", type=str, default=DEFAULT_ISHASH,
            help="sets if INPUT is being treated as a hash or upp path; true or false (default: %s)" % DEFAULT_ISHASH
        )
        self.argparser.add_argument("--env", "-e", metavar="ENV", type=str, default=DEFAULT_ENV,
            help="the environment to operate in; dev, demo or prod (default: %s)" % DEFAULT_ENV
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.input = self.args.input
        self.ishash_str = self.args.ishash
        self.env = self.args.env

        # get the bool for ishash
        if self.ishash_str.lower() in ["1", "yes", "y", "true"]:
            self.ishash = True
        else:
            self.ishash = False
        
        return True

    def read_upp(self) -> bool:
        # read the UPP from the input path
        try:
            logger.info("Reading the input UPP from \"%s\"" % self.input)

            with open(self.input, "rb") as fd:
                self.upp = fd.read()
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def get_hash_from_upp(self) -> bool:
        try:
            unpacked = msgpack.unpackb(self.upp)

            # check if this upp is signed (0x21 == unsigned)
            if unpacked[0] == 0x21:
                # unsigned - no signature at the end
                self.hash = unpacked[-1]
            else:
                # signed - signature at the end
                self.hash = unpacked[-2]

            logger.info("Extracted UPP hash: \"%s\"" % base64.b64encode(self.hash).decode())
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def get_hash_from_input(self) -> bool:
        try:
            self.hash = base64.b64decode(self.input)

            logger.info("Extracted hash from input: \"%s\"" % base64.b64encode(self.hash).decode())
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def get_status(self) -> bool:
        try:
            url = VERIFICATION_SERVICE % self.env

            logger.info("Requesting anchoring information from: \"%s\"" % url)

            r = requests.post(
                url=url,
                headers={'Accept': 'application/json', 'Content-Type': 'text/plain'},
                data=base64.b64encode(self.hash).decode().rstrip("\n")
            )

            if r.status_code == 200:
                logger.info("The UPP is known to the uBirch backend! (code: %d)" % r.status_code)

                jobj = json.loads(r.content)

                print("Curr. UPP: \"%s\"" % jobj.get("upp", "-- no curr. upp information --"))
                print("Prev. UPP: \"%s\"" % jobj.get("prev", "-- no prev. upp information --"))

                if jobj.get("anchors") in [None, []]:
                    logger.info("The UPP has NOT been anchored into any blockchains yet! Please retry later")
                else:
                    logger.info("The UPP has been fully anchored!")

                    print(jobj.get("anchors"))
            elif r.status_code == 404:
                logger.info("The UPP is NOT known to the uBirch backend! (code: %d)" % r.status_code)
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

        # check if the input data is the hash
        if self.ishash == True:
            # the hash can be extracted from the input parameter directly
            if self.get_hash_from_input() != True:
                logger.error("Errors occured while getting the hash from the input parameter - exiting!\n")

                self.argparser.print_usage()

                return 1
        else:
            # the hash can be extracted from an upp which has to be read from a file
            if self.read_upp() != True:
                logger.error("Errors occured while reading the UPP from \"%s\" - exiting!\n" % self.input)

                self.argparser.print_usage()

                return 1

            if self.get_hash_from_upp() != True:
                logger.error("Errors occured while extracting the hash from the UPP - exiting!\n")

                self.argparser.print_usage()

                return 1

        # get the anchoring status
        if self.get_status() != True:
            logger.error("Errors occured while requesting the anchoring status - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
