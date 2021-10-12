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
DEFAULT_NOSEND = "False"
DEFAULT_ISHL    = "False"


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
        self.nosend_str : str = None
        self.nosend : bool = None
        self.ishl_str : str = None
        self.ishl : bool = None
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
        self.argparser.add_argument("--ispath", "-i", metavar="ISPATH", type=str, default=DEFAULT_ISPATH,
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
        self.argparser.add_argument("--no-send", "-n", metavar="NOSEND", type=str, default=DEFAULT_NOSEND,
            help="if set to true, the script will only generate the hash of the input data without sending it; true or false (default: %s)" % DEFAULT_NOSEND
        )
        self.argparser.add_argument("--ishl", "-l", metavar="ISHASHLINK", type=str, default=DEFAULT_ISHL,
            help="implied --isjson to be true; if set to true, the script will look for a hashlink list in the json object and use it to decide which fields to hash; true or false (default: %s)" % DEFAULT_ISHL
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
        self.nosend_str = self.args.no_send
        self.ishl_str = self.args.ishl

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

        # get the bool for nosend
        if self.nosend_str.lower() in ["1", "yes", "y", "true"]:
            self.nosend = True
        else:
            self.nosend = False

        # get the bool for ishl
        if self.ishl_str.lower() in ["1", "yes", "y", "true"]:
            self.ishl = True
        else:
            self.ishl = False

        # check if ishl is true
        if (self.ishl == True and self.isjson == False):
            logger.warning("Overwriting '--isjson false' because --ishl is true")

            self.isjson = True

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

    def _getValueFromDict(self, keyPath : list, currentObj : dict) -> object:
        """ this function gets an object from the config object: config[path[0]][path[1]][path[n]] """
        if len(keyPath) == 0 or not currentObj:
            return currentObj
        elif type(currentObj) == list and type(keyPath[0]) == int:
            return self._getValueFromDict(keyPath[1:], currentObj[keyPath[0]])
        elif type(currentObj) != dict:
            return None
        else:
            return self._getValueFromDict(keyPath[1:], currentObj.get(keyPath[0]))

    def _addValueToDict(self, keyPath : list, value : object) -> dict:
        if len(keyPath) == 0:
            return {}
        elif len(keyPath) == 1:
            return {
                keyPath[0]: value
            }
        else:
            return {
                keyPath[0]: self._addValueToDict(keyPath[1:], value)
            }

    def extract_relevant_fields(self) -> bool:
        try:
            # load the string as data
            dataDict = json.loads(self.data)

            newDict = {}

            # check whether the hashlink array exists
            if dataDict.get("hashLink") != None and type(dataDict.get("hashLink")) == list:
                for hl in dataDict.get("hashLink"):
                    v = self._getValueFromDict(hl.split("."), dataDict)

                    if v == None:
                        logger.error("Hashlink array contains entries that aren't present in the JSON: %s" % hl)

                        return False

                    newDict.update(self._addValueToDict(hl.split("."), v))
            else:
                logger.warning("No hashLink array found in data but hashlink is enabled")

                newDict = dataDict

            # write back the filtered data
            self.data = json.dumps(newDict)
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
            self.hasher.update(self.data if type(self.data) == bytes else self.data.encode())

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

            # check if hashlink is enabled
            if self.ishl:
                if self.extract_relevant_fields() != True:
                    logger.error("Error occured while getting relevant fields from the JSON data - exiting!\n")

                    self.argparser.print_usage()

                    return 1

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

        if self.nosend == False:
            # get the anchoring status
            if self.get_status() != True:
                logger.error("Errors occured while requesting the anchring status - exiting!\n")

                self.argparser.print_usage()

                return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
