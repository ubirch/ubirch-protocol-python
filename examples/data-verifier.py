
# import hashlib
# import json

# import requests

# VERIFICATION_SERVICE = "https://verify.prod.ubirch.com/api/upp/verify/anchor"

# with open("data_to_verify.json") as f:
#     message = json.load(f)

# # create a compact rendering of the message to ensure determinism when creating the hash
# serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
# print("rendered data:\n\t{}\n".format(serialized.decode()))

# # calculate hash of message
# data_hash = hashlib.sha256(serialized).digest()
# print("hash [base64]:\n\t{}\n".format(base64.b64encode(data_hash).decode()))

# # verify existence of the hash in the UBIRCH backend
# r = requests.post(url=VERIFICATION_SERVICE,
#                   headers={'Accept': 'application/json', 'Content-Type': 'text/plain'},
#                   data=base64.b64encode(data_hash).decode().rstrip('\n'))

# if 200 <= r.status_code < 300:
#     print("verification successful:\n\t{}\n".format(r.content.decode()))
# else:
#     print("verification FAIL: ({})\n\tdata hash could not be verified\n".format(r.status_code))

import sys
import argparse
import base64
import logging
import json
import hashlib
import requests


VERIFICATION_SERVICE = "https://verify.%s.ubirch.com/api/upp/verify/anchor"

DEFAULT_ISPATH = "False"
DEFAULT_ENV    = "dev"
DEFAULT_ISJSON = "True"
DEFAULT_HASH   = "sha256"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.input : str = None
        self.env : str = None
        self.ispath_str : str = None
        self.ispath : bool = None
        self.isjson_str : str = None
        self.isjson : bool = None
        self.hashalg : str = None

        self.ishash : bool = False
        self.hasher : object = None

        self.data : bytes = None
        self.hash : str = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Check if the hash of given input data is known to the uBirch backend (verify it)",
            epilog="When --ispath/-i is set to true, the input data is treated as a file path to read the "
                   "actual input data from. When setting --hash/-a to off, the input argument is expected "
                   "to be a valid base64 encoded hash."
        )

        self.argparser.add_argument("input", metavar="INPUT", type=str,
            help="input data or data file path (depends on --ispath)"
        )
        self.argparser.add_argument("--ispath", "-i", metavar="ISHASH", type=str, default=DEFAULT_ISPATH,
            help="sets if INPUT is being treated as data or data file path; true or false (default: %s)" % DEFAULT_ISPATH
        )
        self.argparser.add_argument("--env", "-e", metavar="ENV", type=str, default=DEFAULT_ENV,
            help="the environment to operate in; dev, demo or prod (default: %s)" % DEFAULT_ENV
        )
        self.argparser.add_argument("--isjson", "-j", metavar="ISJSON", type=str, default=DEFAULT_ISJSON,
            help="tells the script to treat the input data as json and serealize it (see EXAMPLES.md for more information); true or false (default: %s)" % DEFAULT_ISJSON
        )
        self.argparser.add_argument("--hash", "-a", metavar="HASH", type=str, default=DEFAULT_HASH,
            help="sets the hash algorithm to use; sha256, sha512 or OFF to treat the input data as hash (default: %s)" % DEFAULT_HASH
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.input = self.args.input
        self.ispath_str = self.args.ispath
        self.isjson_str = self.args.isjson
        self.env = self.args.env
        self.hashalg = self.args.hash

        # check the value for --hash
        if self.hashalg.lower() == "off":
            self.ishash = True
        elif self.hashalg.lower() == "sha256":
            self.hasher = hashlib.sha256()
            self.ishash = False
        elif self.hashalg.lower() == "sha512":
            self.hasher = hashlib.sha512()
            self.ishash = False
        else:
            logger.error("the value for --hash/-a must be \"sha256\", \"sha512\" or \"off\"; \"%s\" is invalid!" % self.hashalg)

            return False

        # check the value for --env
        if self.env not in ["prod", "demo", "dev"]:
            logger.error("the value for --env/-e must be \"prod\", \"demo\" or \"dev\"; \"%s\" is invalid!" % self.env)

            return False

        # get the bool for ispath
        if self.ispath_str.lower() in ["1", "yes", "y", "true"]:
            self.ispath = True
        else:
            self.ispath = False
        
        # get the bool for isjson
        if self.isjson_str.lower() in ["1", "yes", "y", "true"]:
            self.isjson = True
        else:
            self.isjson = False

        return True

    def read_data(self) -> bool:
        # read data from the input path
        try:
            logger.info("Reading the input data from \"%s\"" % self.input)

            with open(self.input, "rb") as fd:
                self.data = fd.read()
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def serialize_json(self) -> bool:
        try:
            # load the string as json and put it back into a string, serealizing it
            self.data = json.loads(self.data)
            self.data = json.dumps(self.data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()

            logger.info("Serialized JSON: \"%s\"" % self.data.decode())
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def get_hash_from_data(self) -> bool:
        try:
            # calculate the hash
            self.hasher.update(self.data)

            self.hash = self.hasher.digest()
            self.hash = base64.b64encode(self.hash).decode().rstrip("\n")

            logger.info("Calculated hash: \"%s\"" % self.hash)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def get_hash_from_input(self) -> bool:
        self.hash = self.input

        return True

    def get_status(self) -> bool:
        try:
            url = VERIFICATION_SERVICE % self.env

            logger.info("Requesting anchoring information from: \"%s\"" % url)

            r = requests.post(
                url=url,
                headers={'Accept': 'application/json', 'Content-Type': 'text/plain'},
                data=self.hash
            )

            if r.status_code == 200:
                logger.info("The hash is known to the uBirch backend! (code: %d)" % r.status_code)

                jobj = json.loads(r.content)

                print("Curr. UPP: \"%s\"" % jobj.get("upp", "-- no curr. upp information --"))
                print("Prev. UPP: \"%s\"" % jobj.get("prev", "-- no prev. upp information --"))

                if jobj.get("anchors") in [None, []]:
                    logger.info("The corresponding UPP has NOT been anchored into any blockchains yet! Please retry later")
                else:
                    logger.info("The corresponding UPP has been fully anchored!")

                    print(jobj.get("anchors"))
            elif r.status_code == 404:
                logger.info("The hash is NOT known to the uBirch backend! (code: %d)" % r.status_code)
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
            # check if the input is a path or the actual data
            if self.ispath == True:
                # read the data from the given path/file
                if self.read_data() != True:
                    logger.error("Errors occured while reading data from \"%s\" - exiting!\n" % self.input)

                    self.argparser.print_usage()

                    return 1
            else:
                self.data = self.input

            # check if the input data is json/should be serialized
            if self.isjson == True:
                if self.serialize_json() != True:
                    logger.error("Error occured while serealizing the JSON data - exiting!\n")

                    self.argparser.print_usage()

                    return 1

            # calculate the hash
            if self.get_hash_from_data() != True:
                logger.error("Error calculating the hash - exiting!\n")

                self.argparser.print_usage()

                return 1

        # get the anchoring status
        if self.get_status() != True:
            logger.error("Errors occured while requesting the anchring status - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
