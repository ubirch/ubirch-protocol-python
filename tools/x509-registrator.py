import logging
import sys
import argparse
import requests
import ecdsa
import OpenSSL
from uuid import UUID

import ubirch


UBIRCH_REGISTRY_ENDPOINT = "https://identity.%s.ubirch.com/api/certs/v1/cert/register"


DEFAULT_OUTPUT = "x509.cert"
DEFAULT_NOSEND = "False"
DEFAULT_READ_CERT_FROM_OUPUT = "False"
DEFAULT_VALIDITY_TIME = "%d" % (365 * 24 * 60 * 60)

X509_DEFAULT_COUNTRY = "DE"
X509_DEFAULT_STATE = "Berlin"
X509_DEFAULT_TOWN = "Berlin"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None


        self.uuid : UUID = None
        self.uuid_str : str = None
        self.keystore_path : str = None
        self.keystore_pass : str
        self.output : str = None
        self.nosend_str : str = None
        self.nosend : bool = None
        self.validity_time_str : str = None
        self.validity_time : int = None
        self.readfromoutput_str : str = None
        self.readfromoutput : bool = None
        self.env : str = None

        self.vk : ecdsa.VerifyingKey = None
        self.sk : ecdsa.SigningKey = None

        self.keystore : ubirch.KeyStore = None
        self.keystore_pass : str = None

        self.x509_cert : OpenSSL.crypto.X509 = None
        self.x509_cert_str : str = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Create a X.509 certificate for a keypair and register it.",
            epilog="This tool only supports ECDSA Keypairs with the NIST256p curve and Sha256 as hash function! If no keypair is found for the given UUID in the given keystore, a new keypair will be created and stored."
        )
        self.argparser.add_argument("env", metavar="ENV", type=str,
            help="the uBirch environment to work on; one of 'dev', 'demo' or 'prod'"
        )
        self.argparser.add_argument("keystore", metavar="KEYSTORE", type=str,
            help="keystore file path; e.g.: test.jks"
        )
        self.argparser.add_argument("keystore_pass", metavar="KEYSTORE_PASS", type=str,
            help="keystore password; e.g.: secret"
        )
        self.argparser.add_argument("uuid", metavar="UUID", type=str,
            help="UUID to work with; e.g.: 56bd9b85-6c6e-4a24-bf71-f2ac2de10183"
        )
        self.argparser.add_argument("--output", "-o", metavar="OUTPUT", type=str, default=DEFAULT_OUTPUT,
            help="path that sets where the X.509 certificate will be written to; e.g.: x509.cert (default: %s)" % DEFAULT_OUTPUT
        )
        self.argparser.add_argument("--nosend", "-n", metavar="NOSEND", type=str, default=DEFAULT_NOSEND,
            help="disables sending of the generated X.509 if set to 'true'; e.g.: 'true', 'false' (default: %s)" % DEFAULT_NOSEND
        )
        self.argparser.add_argument("--validity-time", "-t", metavar="VALIDITY_TIME", type=str, default=DEFAULT_VALIDITY_TIME,
            help="determines how long the key shall be valid (in seconds); e.g.: 36000 for 10 hours (default: %s)" % DEFAULT_VALIDITY_TIME
        )
        self.argparser.add_argument("--read-cert-from-output", "-r", metavar="READ_CERT_FROM_OUTPUT", type=str, default=DEFAULT_READ_CERT_FROM_OUPUT,
            help="if set to 'true', no certificate will be generated but one will be read from the set output file; e.g.: 'true', 'false' (default: %s)" % DEFAULT_READ_CERT_FROM_OUPUT
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.uuid_str = self.args.uuid
        self.keystore_path = self.args.keystore
        self.keystore_pass = self.args.keystore_pass
        self.nosend_str = self.args.nosend
        self.output = self.args.output
        self.readfromoutput_str = self.args.read_cert_from_output
        self.validity_time_str = self.args.validity_time
        self.env = self.args.env

        # check the uuid argument
        try:
            self.uuid = UUID(self.uuid_str)
        except ValueError as e:
            logger.error("Invalud UUID input string: \"%s\"!" % self.uuid_str)
            logger.exception(e)

            return False

        # get the validity time
        try:
            self.validity_time = int(self.validity_time_str)
        except Exception as e:
            logger.error("Can't convert validity time value '%s' to int!" % self.validity_time_str)
            logger.exception(e)
            
            return False

        # get the nostdout value
        if self.nosend_str.lower() in ["1", "yes", "y", "true"]:
            self.nosend = True
        else:
            self.nosend = False

        # get the readfromoutput value
        if self.readfromoutput_str.lower() in ["1", "yes", "y", "true"]:
            self.readfromoutput = True
        else:
            self.readfromoutput = False

        # success
        return True

    def init_keystore(self) -> bool:
        try:
            self.keystore = ubirch.KeyStore(self.keystore_path, self.keystore_pass)

            # check if the device already has keys or generate a new pair
            if not self.keystore.exists_signing_key(self.uuid):
                logger.info("No keys found for \"%s\" in \"%s\" - generating a ECDSA keypair" % (self.uuid_str, self.keystore_path))

                self.keystore.create_ecdsa_keypair(self.uuid)

            self.sk = self.keystore.find_signing_key(self.uuid)
            self.vk = self.keystore.find_verifying_key(self.uuid)

            if type(self.vk) != ubirch.ubirch_ks.ecdsa.VerifyingKey:
                raise(NotImplementedError("X.509 certificate generation is currently only implemented for ECDSA keys!"))
        except Exception as e:
            logger.exception(e)

            return False

        return True

    def read_x509_cert(self) -> bool:
        logger.info("Reading the X.509 certificate from '%s'" % self.output)

        try:
            with open(self.output, "r") as file:
                self.x509_cert_str = file.read()

            logger.info("Read certificate:\n%s" % self.x509_cert_str)
        except Exception as e:
            logger.error("Error reading the certificate!")
            logger.exception(e)

        return True

    def create_x509_cert(self) -> bool:
        logger.info("Creating a X.509 certificate for '%s' with a validity time of %d seconds" % (self.uuid_str, self.validity_time))

        choice = input("Enter 'YES' to continue: ")

        if choice != 'YES':
            logger.error("Aborting ...")

            return False

        try:
            # dump the private key in PEM format
            sk_pem : bytes = self.sk.to_pem()

            # load the PEM into OpenSLL
            pkey : OpenSSL.crypto.PKey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, sk_pem)

            # create the cert
            self.x509_cert = OpenSSL.crypto.X509()

            self.x509_cert.get_subject().C = X509_DEFAULT_COUNTRY
            self.x509_cert.get_subject().ST = X509_DEFAULT_STATE
            self.x509_cert.get_subject().L = X509_DEFAULT_TOWN
            self.x509_cert.get_subject().CN = self.uuid_str
            self.x509_cert.gmtime_adj_notBefore(0)
            self.x509_cert.gmtime_adj_notAfter(self.validity_time)
            self.x509_cert.set_issuer(self.x509_cert.get_subject())
            self.x509_cert.set_pubkey(pkey)
            self.x509_cert.sign(pkey, 'sha256')

            self.x509_cert_str : bytes = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509_cert)
            self.x509_cert_str = self.x509_cert_str.decode("utf8").replace("\\n", "\n")

            logger.info("Generated certificate:\n%s" % self.x509_cert_str)
        except Exception as e:
            logger.error("Error generating the X.509 certificate!")
            logger.exception(e)

        return True

    def store_x509_cert(self) -> bool:
        logger.info("Writing the certificate to '%s' ..." % self.output)

        try:
            with open(self.output, "w+") as file:
                file.write(self.x509_cert_str)
        except Exception as e:
            logger.error("Error storing the certificate!")
            logger.exception(e)

            return False

        return True

    def send_x509_cert(self) -> bool:
        logger.info("Sending the certificate to '%s' ..." % (UBIRCH_REGISTRY_ENDPOINT % self.env))

        try:
            # send the cert
            r = requests.post(
                (UBIRCH_REGISTRY_ENDPOINT % self.env), data=self.x509_cert_str,
                headers={
                    'accept': 'application/json',
                    'content-type': 'application/json'
                }
            )

            # log the response
            logger.info("Backend response:\n%s" % str(r.content))

            # check if the request was successfull
            if r.status_code == 200:
                logger.info("Certificate accepted by the backend!")
            else:
                logger.error("Certificate rejected by the backend! Code: %d" % r.status_code)

                return False
        except Exception as e:
            logger.error("Error sending the certificate to the backend!")
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

        # check if the cert should just be read
        if self.readfromoutput == True:
            if self.read_x509_cert() != True:
                logger.error("Errors occured while reading the certificate - exiting!\n")

                self.argparser.print_usage()

                return 1
        else:
            # create the cert
            if self.create_x509_cert() != True:
                logger.error("Errors occured while generating the certificate - exiting!\n")

                self.argparser.print_usage()

                return 1

            if self.store_x509_cert() != True:
                logger.error("Errors occured while storing the certificate - exiting!\n")

                self.argparser.print_usage()

                return 1

        # check whether the cert should be sent
        if self.nosend != True:
            # send the cert
            if self.send_x509_cert() != True:
                logger.error("Errors occured while sending the certificate the uBirch - exiting!\n")

                self.argparser.print_usage()

                return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
