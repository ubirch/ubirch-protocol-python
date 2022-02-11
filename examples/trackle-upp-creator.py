import binascii
import hashlib
import json
import logging
import pickle
import sys
import time
import random
import msgpack
import argparse
import time
from uuid import UUID

import ubirch

DEFAULT_KS       = "devices.jks"
DEFAULT_KS_PWD   = "keystore"
DEFAULT_OUTPUT   = "upp.bin"
DEFAULT_NOSTDOUT = "False"

logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
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
        return self._ks.find_signing_key(uuid).sign(message)
########################################################################


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.hash : str = None
        self.uuid : UUID = None
        self.uuid_str : str = None
        self.keystore_path : str = None
        self.keystore_pass : str
        self.output : str = None
        self.nostdout_str : str = None
        self.nostdout : bool = None
        self.payload : bytes = None
        self.valnum : int = None
        self.valrangeA : int = None
        self.valrangeB : int = None
        self.valspacing: int = None

        self.keystore : ubirch.KeyStore = None
        self.keystore_pass : str = None
        self.proto : Proto = None
        self.payload : bytes = None
        self.upp : bytes = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(description="Create a Trackle uBirch Protocol Package (UPP)", epilog="Note that data values will be randomly generated in the given range. Don't use it as actual data.")

        self.argparser.add_argument("uuid", metavar="UUID", type=str,
            help="UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183"
        )
        self.argparser.add_argument("num_values", metavar="NUM_VALUES", type=str,
            help="Number of data values to put into the payload field; e.g. 3, 5, 200"
        )
        self.argparser.add_argument("value_range_a", metavar="VALUE_RANGE_A", type=str,
            help="Lower bound for values to be generated; e.g. 3500, 3700, 3000"
        )
        self.argparser.add_argument("value_range_b", metavar="VALUE_RANGE_B", type=str,
            help="Upper bound for values to be generated; e.g. 3800, 3900, 4200"
        )
        self.argparser.add_argument("val_spacing_ms", metavar="VAL_SPACING_MS", type=str,
            help="Timely spacing of the values in milliseconds; e.g. 60, 120, 30"
        )
        self.argparser.add_argument("--ks", "-k", metavar="KS", type=str, default=DEFAULT_KS,
            help="keystore file path; e.g.: test.jks (default: %s)" % DEFAULT_KS
        )
        self.argparser.add_argument("--kspwd", "-p", metavar="KSPWD", type=str, default=DEFAULT_KS_PWD,
            help="keystore password; e.g.: secret (default: %s)" % DEFAULT_KS_PWD
        )
        self.argparser.add_argument("--output", "-o", metavar="OUTPUT", type=str, default=DEFAULT_OUTPUT,
            help="file to write the generated UPP to (aside from standard output); e.g. upp.bin (default: %s)" % DEFAULT_OUTPUT
        )
        self.argparser.add_argument("--nostdout", "-n", metavar="nostdout", type=str, default=DEFAULT_NOSTDOUT,
            help="do not output anything to stdout (except warnings and errors); can be combined with --output /dev/stdout; e.g.: true, false (default: %s)" % DEFAULT_NOSTDOUT
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.uuid_str = self.args.uuid
        self.keystore_path = self.args.ks
        self.keystore_pass = self.args.kspwd
        self.output = self.args.output
        self.nostdout_str = self.args.nostdout
        self.valnum = int(self.args.num_values)
        self.valrangeA = int(self.args.value_range_a)
        self.valrangeB = int(self.args.value_range_b)
        self.valspacing = int(self.args.val_spacing_ms)

        # check the uuid argument
        try:
            self.uuid = UUID(self.uuid_str)
        except ValueError as e:
            logger.error("Invalid UUID input string: \"%s\"!" % self.uuid_str)
            logger.exception(e)

            return False

        # get the nostdout value
        if self.nostdout_str.lower() in ["1", "yes", "y", "true"]:
            self.nostdout = True
        else:
            self.nostdout = False

        # success
        return True

    def check_msgpack_ver(self) -> bool:
        if msgpack.version != (0,6,2):
            logger.warning("Trackle uses an old MsgPack version which has different header lengths than the current one! This script has only been tested to generate verifyable Trackle-UPPs with MsgPack version 0.6.2!")
            logger.warning("Run 'pip install --user msgpack==0.6.2' to install the version known to work (this might termporarily break compability with other programs)!")
            logger.warning("Current msgpack version: %s. Press enter to continue" % str(msgpack.version))

            input()

        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore(self.keystore_path, self.keystore_pass)

            # check if the device already has keys or generate a new pair
            if not self.keystore.exists_signing_key(self.uuid):
                if self.nostdout == False:
                    logger.info("No keys found for \"%s\" in \"%s\" - generating a keypair" % (self.uuid_str, self.keystore_path))

                self.keystore.create_ed25519_keypair(self.uuid)

            if self.nostdout == False:
                logger.info("Public/Verifying key for \"%s\" [base64]: \"%s\"" %
                    (self.uuid_str, binascii.b2a_base64(self.keystore.find_verifying_key(self.uuid).to_bytes(), newline=False).decode()))
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
            firsttime = int(time.time())

            values = {}

            for i in range(0, self.valnum):
                values["%.10s" % int(firsttime + i * self.valspacing/1000)] = random.randint(self.valrangeA, self.valrangeB)

            self.payload = [
                'v1.0.2-PROD-20180326103205 (v5.6.6)',
                self.valnum,
                3,
                values,
                {
                    'i': self.valspacing,
                    'max': self.valrangeA,
                    'il': self.valspacing * 2,
                    'min': self.valrangeB
                }
            ]
            if self.nostdout == False:
                logger.info("UPP payload (raw data): \"%s\"" % self.payload)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def serialize(self, msg) -> bytes:
        return msgpack.packb(msg)

    def create_upp(self) -> bool:
        try:
            if self.nostdout == False:
                logger.info("Generating a chained signed UPP for UUID \"%s\"" % self.uuid_str)

            # trackle UPPs have an old UPP version which is not supported by the normal uBirch protocol lib;
            # the message creation needs to be implemented here
            prevsig = self.proto._signatures.get(self.uuid, b'\0' * 64)

            msg = [
                0x13,               # chained uppV1
                self.uuid.bytes,
                prevsig,
                0x55,               # trackle upp type
                self.payload,
                0
            ]

            # serialize the partial upp and sign it
            serialized = self.serialize(msg)[0:-1]
            signature = self.proto._sign(self.uuid, self.proto._hash(serialized))
            
            # replace last element in array with the signature
            msg[-1] = signature

            # serialize the whole upp
            self.upp = self.serialize(msg)

            # store the new signature
            self.proto._signatures[self.uuid] = signature
            self.proto.persist(self.uuid)
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def show_store_upp(self) -> bool:
        try:
            if self.nostdout == False:
                logger.info("UPP [hex]: \"%s\"" % binascii.hexlify(self.upp).decode())

            # try to write the upp
            with open(self.output, "wb") as fd:
                fd.write(self.upp)

            if self.nostdout == False:
                logger.info("UPP written to \"%s\"" % self.output)
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

        # check the msgpack version
        if self.check_msgpack_ver() != True:
            logger.error("Errors occured while checking the msgpack version - exiting!\n")

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

        # show and store the UPP
        if self.show_store_upp() != True:
            logger.error("Erros occured while showing/storing the UPP - exiting!\n")

            self.argparser.print_usage()

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
