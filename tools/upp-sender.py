import sys
import logging
import argparse
import msgpack
import requests
import binascii
import uuid

import ubirch


DEFAULT_ENV    = "dev"
DEFAULT_INPUT  = "upp.bin"
DEFAULT_OUTPUT = "response_upp.bin"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.uuid_str : str = None
        self.uuid : uuid.UUID = None
        self.auth : str = None
        self.env : str = None
        self.input : str = None

        self.iskeyreg : bool = False

        self.upp : bytes = None
        self.api : ubirch.API = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Send a uBirch Protocol Package (UPP) to uBirch Niomon",
            epilog=""
        )

        self.argparser.add_argument("uuid", metavar="UUID", type=str,
            help="UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183"
        )
        self.argparser.add_argument("auth", metavar="AUTH", type=str,
            help="uBirch device authentication token"
        )
        self.argparser.add_argument("--env", "-e", metavar="ENV", type=str, default=DEFAULT_ENV,
            help="environment to operate in; dev, demo or prod (default: %s)" % DEFAULT_ENV
        )
        self.argparser.add_argument("--input", "-i", metavar="INPUT", type=str, default=DEFAULT_INPUT,
            help="UPP input file path; e.g. upp.bin or /dev/stdin (default: %s)" % DEFAULT_INPUT
        )
        self.argparser.add_argument("--output", "-o", metavar="OUTPUT", type=str, default=DEFAULT_OUTPUT,
            help="response UPP output file path (ignored for key registration UPPs); e.g. response_upp.bin (default: %s)" % DEFAULT_OUTPUT
        )
        
        return 

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.uuid_str = self.args.uuid
        self.auth = self.args.auth
        self.env = self.args.env
        self.input = self.args.input
        self.output = self.args.output

        # process the uuid
        try:
            self.uuid = uuid.UUID(hex=self.uuid_str)
        except Exception as e:
            logger.error("Invalid UUID: \"%s\"" % self.uuid_str)
            logger.exception(e)

            return False

        # validate env
        if self.env.lower() not in ["dev", "demo", "prod"]:
            logger.error("Invalid value for --env: \"%s\"!" % self.env)

            return False

        return True

    def read_upp(self) -> bool:
        # read the UPP from the input path
        try:
            logger.info("Reading the input UPP for \"%s\" from \"%s\"" % (self.uuid_str, self.input))

            with open(self.input, "rb") as file:
                self.upp = file.read()
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def check_is_keyreg(self) -> bool:
        # check if the UPP is a key registration UPP
        try:
            if msgpack.unpackb(self.upp)[2] == 1:
                logger.info("The UPP is a key registration UPP - disabling identity registration check")

                self.iskeyreg = True
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def init_api(self) -> bool:
        try:
            logger.info("Configuring the API to use the '%s' environment!" % self.env)

            # initialize the uBirch api
            self.api = ubirch.API(env=self.env, debug=True)
            self.api.set_authentication(self.uuid, self.auth)

            if self.iskeyreg == False:
                # check if the UUID is registered
                if not self.api.is_identity_registered(self.uuid):

                    logger.error("The identity for \"%s\" is not yet registered; please send a key registration UPP first" % self.uuid_str)

                    return False
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def send_upp(self) -> bool:
        # niomon not accepting a UPP is not considered an error; so the return value will still be True
        # this choice was made because this tool is meant for playing around/debugging etc.

        try:
            # check which API function should be used
            if self.iskeyreg:
                r = self.api.register_identity(self.upp)

                if r.status_code == requests.codes.ok:
                    logger.info("The key resgistration message for \"%s\" was accepted" % self.uuid_str)
                    logger.info(r.content)
                else:
                    logger.error("The key resgistration message for \"%s\" was not accepted; code: %d" % (self.uuid_str, r.status_code))
                    logger.error(binascii.hexlify(r.content).decode())
            else:
                r = self.api.send(self.uuid, self.upp)

                # set the response
                self.response_upp = r.content

                if r.status_code == requests.codes.ok:
                    logger.info("The UPP for \"%s\" was accepted" % self.uuid_str)
                    logger.info(binascii.hexlify(r.content).decode())
                else:
                    logger.error("The UPP for \"%s\" was not accepted; code: %d" % (self.uuid_str, r.status_code))
                    logger.error(binascii.hexlify(r.content).decode())

                    if r.status_code == 401:
                        logger.error("The UPP was rejected because of an authentication error! (Missing header/Invalid auth token)")
                    elif r.status_code == 403:
                        logger.error("The UPP wa rejected because of an verification error!")
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def store_response_upp(self) -> bool:
        try:
            with open(self.output, "wb") as file:
                file.write(self.response_upp)

                logger.info("The response UPP has been written to \"%s\"" % self.output)
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

        # check if it is a key registration upp (return value is not the result but err code)
        if self.check_is_keyreg() != True:
            logger.error("Errors occured while checking if the UPP is a key registration UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        # initialize the api
        if self.init_api() != True:
            logger.error("Errors occured while initializing the uBirch API - exiting!\n")

            self.argparser.print_usage()

            return 1

        # send the upp
        if self.send_upp() != True:
            logger.error("Errors occured while sending the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        if self.iskeyreg == False:
            # store the response upp
            if self.store_response_upp() != True:
                logger.error("Erros occured while storing the response UPP to \"%s\" - exiting!" % self.output)

                self.argparser.print_usage()

                return 1

        return 0


if __name__ == "__main__":
    sys.exit(Main().run())
