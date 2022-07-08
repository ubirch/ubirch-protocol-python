import sys
import logging
import argparse
import msgpack
import requests
import binascii
import uuid

import ubirch


DEFAULT_ENV = "dev"


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

        self.api : ubirch.API = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Send some data to the uBirch Simple Data Service",
            epilog="Note that the input data should follow this pattern: "
                   "{\"timestamp\": TIMESTAMP, \"uuid\": \"UUID\", \"msg_type\": 0, \"data\": DATA, \"hash\": \"UPP_HASH\"}. "
                   "For more information take a look at the EXAMPLES.md file."
        )

        self.argparser.add_argument("uuid", metavar="UUID", type=str,
            help="UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183"
        )
        self.argparser.add_argument("auth", metavar="AUTH", type=str,
            help="uBirch device authentication token, e.g.: 12345678-1234-1234-1234-123456789abc (this is NOT the UUID)"
        )
        self.argparser.add_argument("--env", "-e", metavar="ENV", type=str, default=DEFAULT_ENV,
            help="environment to operate in; dev, demo or prod (default: %s)" % DEFAULT_ENV
        )
        self.argparser.add_argument("input", metavar="INPUT", type=str,
            help="data to be sent to the simple data service"
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

    def init_api(self) -> bool:
        try:
            # initialize the uBirch api
            self.api = ubirch.API(env=self.env, debug=True)
            self.api.set_authentication(self.uuid, self.auth)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def send_data(self) -> bool:
        try:
            r = self.api.send_data(self.uuid, self.input.encode())

            # check the response
            if r.status_code == 200:
                logger.info("Successfully sent all data to the Simple Data Service! (%d)" % r.status_code)
            else:
                logger.error("Failed to send data to the Simple Data Service! (%d)" % r.status_code)
                logger.error(r.content)
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

        # initialize the api
        if self.init_api() != True:
            logger.error("Errors occured while initializing the uBirch API - exiting!\n")

            self.argparser.print_usage()

            return 1

        # send data
        if self.send_data() != True:
            logger.error("Errors occured while sending data to the simple data service - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


if __name__ == "__main__":
    sys.exit(Main().run())