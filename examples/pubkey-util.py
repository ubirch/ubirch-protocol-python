import sys
import logging
import argparse
import requests
import uuid
import ed25519
import binascii
import json
import base64
import msgpack

import ubirch


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()

# put_key use msgpack
PUT_KEY_USE_MSGPACK_DEFAULT="false"

# commands
PUT_NEW_KEY_CMD = "put_new_key"
GET_DEV_KEYS_CMD = "get_dev_keys"
GET_KEY_INFO_CMD = "get_key_info"
DELETE_KEY_CMD = "delete_key"
REVOKE_KEY_CMD = "revoke_key"

# URLs and paths
UBIRCH_ID_SERVICE = "https://identity.%s.ubirch.com/api/keyService/v1/pubkey"
GET_DEVICE_KEYS_PATH = "/current/hardwareId/%s" # completed with the uuid
GET_KEY_INFO_PATH = "/%s" # completed with the pubkeyId (equal to pubkey) in b64
REVOKE_KEY_PATH = "/revoke"
PUT_KEY_MSGPACK_PATH = "/mpack"

# body formats
DEL_PUBKEY_FMT = '{'\
    '"publicKey":"%s",'\
    '"signature":"%s"'\
'}'

REVOKE_PUBKEY_FMT = '{'\
    '"publicKey":"%s",'\
    '"signature":"%s"'\
'}'

PUT_PUBKEY_UPDATE_FMT_OUTER = '{'\
    '"pubKeyInfo":%s,'\
    '"prevSignature":"%s",'\
    '"signature":"%s"'\
'}'
PUT_PUBKEY_UPDATE_FMT_INNER = '{'\
    '"algorithm":"%s",'\
    '"created":"%s",'\
    '"hwDeviceId":"%s",'\
    '"pubKey":"%s",'\
    '"pubKeyId":"%s",'\
    '"prevPubKeyId":"%s",'\
    '"validNotAfter":"%s",'\
    '"validNotBefore":"%s"'\
'}'

PUT_NEW_PUBKEY_FMT_OUTER = '{'\
    '"pubKeyInfo":%s,'\
    '"signature":"%s"'\
'}'
PUT_NEW_PUBKEY_FMT_INNER = '{'\
    '"algorithm":"%s",'\
    '"created":"%s",'\
    '"hwDeviceId":"%s",'\
    '"pubKey":"%s",'\
    '"pubKeyId":"%s",'\
    '"validNotAfter":"%s",'\
    '"validNotBefore":"%s"'\
'}'


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.get_dev_keys_parser : argparse.ArgumentParser = None
        self.get_key_info_parser : argparse.ArgumentParser = None
        self.put_new_key_parser : argparse.ArgumentParser = None
        self.del_key_parser : argparse.ArgumentParser = None
        self.revoke_key_parser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        self.cmd_str : str = None               # store the command string
        self.base_url : str = None              # store the complete url (incl. env)

        # not every variable is needed for every command; still, all are listed here for clarity
        self.uuid_str : str = None              # for get_dev_keys, put_new_key, delete_key and revoke_key
        self.uuid : uuid.UUID = None            # for get_dev_keys, put_new_key, delete_key and revoke_key
        self.pubkey_str : str = None            # for put_new_key, delete_key, revoke_key, get_key_info
        self.pubkey_b64 : bytes = None          # for put_new_key, delete_key, rewoke_key, get_key_info
        self.prvkey_str : str = None            # for put_new_key, delete_key, revoke_key
        self.old_pubkey_str : str = None        # for put_new_key (when updating)
        self.old_prvkey_str : str = None        # for put_new_key (when updating)
        self.old_pubkey_b64 : bytes = None      # for put_new_key (when updating)
        self.key_created_at : str = None        # for put_new_key
        self.key_valid_not_after : str = None   # for put_new_key
        self.key_valid_not_before : str = None  # for put_new_key
        self.use_msgpack_str : str = None       # for put_new_key
        self.use_msgpack : bool = None          # for put_new_key

        # the privkey needs to be loaded as actual key (not string) for some operations
        self.prvkey : ed25519.SigningKey = None
        self.old_prvkey : ed25519.SigningKey = None

        self.upp : bytes = None
        self.api : ubirch.API = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="A tool to perform pubkey operations with the uBirch Identity Service",
            epilog="Choose an environment + command and use the '--help'/'-h' option to see a command-specific help message; e.g.: python %s dev revoke_key -h. Note that for many operations (like putting a new PubKey), only the PrivKey is needed. That is because in case of ED25519 keys, the PubKey can be generated out of the PrivKey, because the PrivKey is generally regarded to as a seed for the keypair."
        )

        # set up the main parameters
        self.argparser.add_argument("env", metavar="<ENV>", type=str,
            help="Environment to work on. Must be one of 'dev', 'demo' or 'prod'. Case insensitive."
        )
        self.argparser.add_argument("--debug", "-d", type=str, default="false",
            help="Enables/Disables debug logging. When enabled, all HTTP bodies will be printed before sending; 'true'/'false' (Default: 'false')"
        )

        # generate a subparser group; the dest parameter is needed so that the program knows
        # which subparser was triggered later on
        subparsers = self.argparser.add_subparsers(help="Command to execute.", dest="cmd", required=True)

        # set up conditional parameters for each command/operation
        # subparser + arguments for the get_dev_keys operation
        self.get_dev_keys_parser = subparsers.add_parser(GET_DEV_KEYS_CMD, help="Get PubKeys registered for a given device.")
        self.get_dev_keys_parser.add_argument("uuid", metavar="UUID", type=str,
            help="The device UUID to get the keys for. E.g.: f99de1c4-3859-5326-a155-5696f00686d9"
        )

        # subparser + arguments for the get_key_info operation
        self.get_key_info_parser = subparsers.add_parser(GET_KEY_INFO_CMD, help="Get information for a specific PubKey.")
        self.get_key_info_parser.add_argument("pubkey", metavar="PUBKEY_HEX", type=str,
            help="ED25519 Pubkey to retrieve information for in HEX"
        )

        # subparser + arguments for the put_new_key operation
        self.put_new_key_parser = subparsers.add_parser(PUT_NEW_KEY_CMD, help="Register a new PubKey.")
        self.put_new_key_parser.add_argument("uuid", metavar="UUID", type=str,
            help="The device UUID to register a key for. E.g.: f99de1c4-3859-5326-a155-5696f00686d9"
        )
        self.put_new_key_parser.add_argument("prvkey", metavar="PRIVKEY_HEX", type=str,
            help="The ED25519 PrivKey corresponding to the PubKey in HEX."
        )
        self.put_new_key_parser.add_argument("created", metavar="CREATED", type=str,
            help="Date at which the PubKey was created; (format: 2020-12-30T11:11:11.000Z)"
        )
        self.put_new_key_parser.add_argument("validNotBefore", metavar="VALID_NOT_BEFORE", type=str,
            help="Date at which the PubKey will become valid; (format: 2020-12-30T22:22:22.000Z)."
        )
        self.put_new_key_parser.add_argument("validNotAfter", metavar="VALID_NOT_AFTER", type=str,
            help="Date at which the PubKey will become invalid; (format: 2030-02-02T02:02:02.000Z)."
        )
        self.put_new_key_parser.add_argument("--update", "-u", metavar="OLD_PRIVKEY_HEX", type=str, default=None,
            help="Old private key to sign the keypair update in HEX. Only needed if there already is a PubKey registered."
        )
        self.put_new_key_parser.add_argument("--msgpack", "-m", metavar="MSGPACK", type=str, default=PUT_KEY_USE_MSGPACK_DEFAULT,
            help="NOT IMPLEMENTED! Enables/Disables usage of MsgPack instead of Json. Can't be used for key updates (-u); true or false (default: %s)" % PUT_KEY_USE_MSGPACK_DEFAULT
        )

        # subparser + arguments for the delete_key operation
        self.del_key_parser = subparsers.add_parser(DELETE_KEY_CMD, help="Delete a registered PubKey.")
        self.del_key_parser.add_argument("prvkey", metavar="PRIVKEY_HEX", type=str,
            help="ED25519 PrivKey in HEX corresponding to the PubKey to be deleted."
        )

        # subparser + arguments for the revoke_key operation
        self.revoke_key_parser = subparsers.add_parser(REVOKE_KEY_CMD, help="Revoke a registered PubKey.")
        self.revoke_key_parser.add_argument("prvkey", metavar="PRIVKEY_HEX", type=str,
            help="ED25519 PrivKey in HEX corresponding to the PubKey to be revoked."
        )
       
        return 

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # the env argument is needed for every command - get it
        self.env = self.args.env
        self.cmd_str = self.args.cmd

        if self.args.debug.lower() in ["1", "yes", "y", "true"]:
            logger.level = logging.DEBUG

            logging.debug("Log level set to debug!")

        # format the url
        self.base_url = UBIRCH_ID_SERVICE % self.env

        if self.env.lower() not in ["dev", "demo", "prod"]:
            logger.error("Invalid value for env: \"%s\"!" % self.env)

            return False

        # load the UUID if needed
        if self.cmd_str in [GET_DEV_KEYS_CMD, PUT_NEW_KEY_CMD]:
            try:
                self.uuid_str = self.args.uuid
                self.uuid = uuid.UUID(hex=self.uuid_str)
            except Exception as e:
                logger.error("Invalid UUID: \"%s\"" % self.uuid_str)
                logger.exception(e)

                return False

        # set the pubkey str and encode it as b64 if needed
        if self.cmd_str in [GET_KEY_INFO_CMD]:
            self.pubkey_str = self.args.pubkey

            try:
                self.pubkey_b64 = base64.b64encode(binascii.unhexlify(self.pubkey_str)).decode("utf8").strip("\n")
            except Exception as e:
                logger.error("Error un-hexlifying the PubKey and encoding it in Base64!")
                logger.exception(e)

                return False

        # load the privkey if needed
        if self.cmd_str in [PUT_NEW_KEY_CMD, DELETE_KEY_CMD, REVOKE_KEY_CMD]:
            self.prvkey_str = self.args.prvkey

            # the prvkey needs to be loaded to be usable
            try:
                self.prvkey = ed25519.SigningKey(binascii.unhexlify(self.prvkey_str))
            except Exception as e:
                logger.error("Error loading the ED25519 private key!")
                logger.exception(e)

                return False

            logger.info("PrivKey loaded!")

            # get the pubkey
            self.pubkey_str = binascii.hexlify(self.prvkey.get_verifying_key().to_bytes()).decode("utf8")

            logger.info("PubKey extracted from the PrivKey: %s" % self.pubkey_str)

            # b64-encode the pubkey
            try:
                self.pubkey_b64 = base64.b64encode(binascii.unhexlify(self.pubkey_str)).decode("utf8").strip("\n")
            except Exception as e:
                logger.error("Error un-hexlifying the PubKey and encoding it in Base64!")
                logger.exception(e)

                return False

        # load the old privkey if needed
        if self.cmd_str in [PUT_NEW_KEY_CMD]:
            # can be none; used for detecting whether a key-update should be done
            # and also needed for the update itself
            self.old_prvkey_str = self.args.update

            # the old prvkey needs to be loaded to be usable to sign the update
            if self.old_prvkey_str != None:
                try:
                    self.old_prvkey = ed25519.SigningKey(binascii.unhexlify(self.old_prvkey_str))
                except Exception as e:
                    logger.error("Error loading the old ED25519 private key!")
                    logger.exception(e)

                    return False

                logger.info("Old PrivKey loaded!")

                # get the old pubkey from the privkey
                self.old_pubkey_str = binascii.hexlify(self.old_prvkey.get_verifying_key().to_bytes()).decode("utf8")

                logger.info("Old PubKey extracted from old PrivKey: %s" % self.old_pubkey_str)

                # b64-encode the old pubkey
                try:
                    self.old_pubkey_b64 = base64.b64encode(binascii.unhexlify(self.old_pubkey_str)).decode("utf8").strip("\n")
                except Exception as e:
                    logger.error("Error un-hexlifying the old PubKey and encoding it in Base64!")
                    logger.exception(e)

                    return False

            self.key_valid_not_before = self.args.validNotBefore
            self.key_valid_not_after = self.args.validNotAfter
            self.key_created_at = self.args.created
            self.use_msgpack_str = self.args.msgpack

            # extract the bool for the use-msgpack flag
            if self.use_msgpack_str.lower() in ["1", "yes", "y", "true"]:
                self.use_msgpack = True
            else:
                self.use_msgpack = False

        return True

    def usage(self):
        if self.cmd_str == PUT_NEW_KEY_CMD:
            self.put_new_key_parser.print_help()
        elif self.cmd_str == GET_KEY_INFO_CMD:
            self.get_key_info_parser.print_help()
        elif self.cmd_str == GET_DEV_KEYS_CMD:
            self.get_dev_keys_parser.print_help()
        elif self.cmd_str == "del_key":
            self.del_key_parser.print_help()
        elif self.cmd_str == REVOKE_KEY_CMD:
            self.revoke_key_parser.print_help()
        else:
            logger.error("Unknown cmd \"%s\"!" % self.cmd_str)

            self.argparser.print_help()

    def handle_http_response(self, r : requests.Response) -> bool:
        # check the reponse code
        if r.status_code != 200:
            logger.error("Received NOT-OK HTTP response code %d!" % r.status_code)
            logger.error("Status message: %s" % r.content)

            return 1

        logger.info("Success! (HTTP) 200)")

        # format the response json and print it
        formatted = json.dumps(json.loads(r.content.decode("utf8")), indent=4)

        logger.info("HTTP response:\n" + formatted)

        return 0

    # signs the pubkey from .pubkey_str with .prvkey and returns the signature in base64
    def sign_data_b64(self, data : bytes, use_old_priv=False) -> bytes:
        # sign the pubkey (RAW, NOT B64)
        try:
            if use_old_priv == True:
                signed = self.old_prvkey.sign(data)
            else:
                signed = self.prvkey.sign(data)
        except Exception as e:
            logger.error("Error de-hexlifying and signing the PubKey!")
            logger.exception(e)

            return None

        # encode the signature in base64
        try:
            signed_b64 = base64.b64encode(signed).decode("utf8").strip("\n")
        except Exception as e:
            logger.error("Error B64-encoding the PubKey signature!")
            logger.exception(e)

            return None

        return signed_b64

    def run_get_dev_keys(self):
        url = self.base_url + (GET_DEVICE_KEYS_PATH % self.uuid_str)

        logger.info("Getting keys for %s from %s!" % (self.uuid_str, url))

        # send the request
        r = requests.get(
            url=url,
            headers={'Accept': 'application/json'}
        )

        # handle the reponse
        return self.handle_http_response(r)

    def run_get_key_info(self):
        url = self.base_url + (GET_KEY_INFO_PATH % self.pubkey_b64)

        logger.info("Getting information for the PubKey %s (B64) from %s" % (self.pubkey_b64, url))

        # send the request
        r = requests.get(
            url=url,
            headers={'Accept': 'application/json'}
        )

        # handle the response
        return self.handle_http_response(r)

    def run_put_new_key_json(self):
        url = self.base_url        

        # check if this is a key update
        if self.old_prvkey_str != None:
            # format the innter message
            inner_msg = PUT_PUBKEY_UPDATE_FMT_INNER % (
                "ECC_ED25519", self.key_created_at, self.uuid_str, self.pubkey_b64, self.pubkey_b64,
                self.old_pubkey_b64, self.key_valid_not_after, self.key_valid_not_before
            )

            # sign the inner message with both privkeys
            prevsig = self.sign_data_b64(bytes(inner_msg, "utf8"), use_old_priv=True)
            sig = self.sign_data_b64(bytes(inner_msg, "utf8"))


            print(inner_msg)

            # create the whole msg
            msg = PUT_PUBKEY_UPDATE_FMT_OUTER % (
                inner_msg, prevsig, sig
            )
        else:
            # format the innter message
            inner_msg = PUT_NEW_PUBKEY_FMT_INNER % (
                "ECC_ED25519", self.key_created_at, self.uuid_str, self.pubkey_b64,
                self.pubkey_b64, self.key_valid_not_after, self.key_valid_not_before
            )

            # sign the inner message with the privkey
            sig = self.sign_data_b64(bytes(inner_msg, "utf8"))

            # create the whole msg
            msg = PUT_NEW_PUBKEY_FMT_OUTER % (
                inner_msg, sig
            )

        # get user confirmation to register the key
        logger.info("Registering new PubKey %s (B64) at %s!" % (self.pubkey_b64, url))
        logger.debug("Data:\n" + msg)

        if input("Enter 'YES' to continue: ") != 'YES':
            logger.error("Aborting!")

            return 0

        # send the request
        r = requests.post(url, data=msg)

        # handle the response
        return self.handle_http_response(r)

    def run_put_new_key_msgpack(self):
        logger.error("NOT IMPLEMENTED YET. SEE 'upp-creator.py' FOR AN IMPLEMENTATION OF THIS FUNCTIONALITY.")

        return 0

    def run_put_new_key(self):
        # call the subfunction depending on the use-msgpack flag
        if self.use_msgpack == True:
            return self.run_put_new_key_msgpack()
        else:
            return self.run_put_new_key_json()

    def run_del_key(self):
        pubkey_sign_b64 = self.sign_data_b64(binascii.unhexlify(self.pubkey_str))

        if pubkey_sign_b64 == None:
            return 1

        # format the message
        msg = DEL_PUBKEY_FMT % (self.pubkey_b64, pubkey_sign_b64)

        # get the url
        url = self.base_url

        # get user confirmation to delete the key
        logger.info("Deleting PubKey %s (B64) at %s!" % (self.pubkey_b64, url))
        logger.debug("Data:\n" + msg)
        
        if input("Enter 'YES' to continue: ") != 'YES':
            logger.error("Aborting!")

            return 0

        # send the request
        r = requests.delete(url, data=msg)

        # handle the response
        return self.handle_http_response(r)

    def run_revoke_key(self):
        pubkey_sign_b64 = self.sign_data_b64(binascii.unhexlify(self.pubkey_str))

        if pubkey_sign_b64 == None:
            return 1

        # format the message
        msg = REVOKE_PUBKEY_FMT % (self.pubkey_b64, pubkey_sign_b64)

        # get the url
        url = self.base_url + REVOKE_KEY_PATH

        # get user confirmation to revoke the key
        logger.info("Revoking PubKey %s (B64) at %s!" % (self.pubkey_b64, url))
        logger.debug("Data:\n" + msg)
        
        if input("Enter 'YES' to continue: ") != 'YES':
            logger.error("Aborting!")

            return 0

        # send the request
        r = requests.delete(url, data=msg)

        # handle the response
        return self.handle_http_response(r)

        return 0

    def run(self):
        # process all args
        if self.process_args() != True:
            logger.error("Errors occured during argument processing - exiting!\n")

            self.usage()

            return 1

        # call the correct sub-run function
        if self.cmd_str == PUT_NEW_KEY_CMD:
            return self.run_put_new_key()
        elif self.cmd_str == GET_KEY_INFO_CMD:
            return self.run_get_key_info()
        elif self.cmd_str == GET_DEV_KEYS_CMD:
            return self.run_get_dev_keys()
        elif self.cmd_str == DELETE_KEY_CMD:
            return self.run_del_key()
        elif self.cmd_str == REVOKE_KEY_CMD:
            return self.run_revoke_key()
        else:
            logger.error("Unknown cmd \"%s\"!" % self.cmd_str)

            return 1

if __name__ == "__main__":
    sys.exit(Main().run())