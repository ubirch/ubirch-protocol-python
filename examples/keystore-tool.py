import sys
import time
import argparse
import logging
import binascii
import uuid
import ed25519
import ecdsa
import hashlib

import ubirch


DEFAULT_SHOW_SECRET = "False"
DEFAULT_ECDSA = "False"
COMMAND_GET = "get"
COMMAND_PUT = "put"
COMMAND_DEL = "del"


logging.basicConfig(format='%(asctime)s %(name)20.20s %(funcName)20.20s() %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()


class Main:
    def __init__(self):
        self.argparser : argparse.ArgumentParser = None
        self.get_argparser : argparse.ArgumentParser = None
        self.put_argparser : argparse.ArgumentParser = None
        self.args : argparse.Namespace = None

        # for all commands
        self.keystore_path : str = None
        self.keystore_pass : str = None
        self.uuid_str : str = None
        self.uuid : uuid.UUID = None
        self.cmd : str = None

        # for get
        self.show_sign_str : str = None
        self.show_sign : bool = None

        # for put
        self.pubkey_str : str = None
        self.pubkey : ed25519.VerifyingKey or ecdsa.VerifyingKey = None
        self.prvkey_str : str = None
        self.prvkey : ed25519.SigningKey or ecdsa.SigningKey = None
        self.ecdsa_str : str = None
        self.ecdsa : bool = None

        self.keystore : ubirch.KeyStore = None

        # initialize the argument parser
        self.setup_argparse()

        return

    def setup_argparse(self):
        self.argparser = argparse.ArgumentParser(
            description="Manipulate/View the contents of a keystore (.jks)",
            epilog="Only one entry per UUID is supported. Passing an non-existent KeyStore file as argument will lead to a new KeyStore being created. This new KeyStore will only be persistent if a write operation (-> key insertion) takes place."
        )

        self.argparser.add_argument("keystore", metavar="KEYSTORE", type=str,
            help="keystore file path; e.g.: test.jks"
        )
        self.argparser.add_argument("keystore_pass", metavar="KEYSTORE_PASS", type=str,
            help="keystore password; e.g.: secret"
        )

        # create subparsers
        subparsers = self.argparser.add_subparsers(help="Command to execute.", dest="cmd", required=True)

        # subparser for the get-command
        self.get_argparser = subparsers.add_parser(COMMAND_GET, help="Get entries from the KeyStore.")

        self.get_argparser.add_argument("--uuid", "-u", type=str, default=None,
            help="UUID to filter for. Only keys for this UUID will be returned; e.g.: f99de1c4-3859-5326-a155-5696f00686d9"
        )
        self.get_argparser.add_argument("--show-secret", "-s", type=str, default=DEFAULT_SHOW_SECRET,
            help="Enables/Disables showing of secret (signing/private) keys; e.g.: true/false (default: %s)" % DEFAULT_SHOW_SECRET
        )

        # subparser for the put-command
        self.put_argparser = subparsers.add_parser(COMMAND_PUT, help="Put a new entry into the KeyStore.")

        self.put_argparser.add_argument("uuid", metavar="UUID", type=str,
            help="The UUID the new keys belong to; e.g.: f99de1c4-3859-5326-a155-5696f00686d9"
        )
        self.put_argparser.add_argument("pubkey", metavar="PUBKEY", type=str,
            help="The HEX-encoded ED25519 PubKey; e.g.: 189595c87a972c55eb7348a310fa1ff479a895a1f226d189b5ad505b9d8c8bbf"
        )
        self.put_argparser.add_argument("privkey", metavar="PRIVKEY", type=str,
            help="The HEX-encoded ED25519 PrivKey; e.g.: 9c7c43e122ae51e08a86e9bb89fe340bd4c7bd6665bf2b40004d4012f1523575127f8ac54a971765126a866428a6c74d4747d1b68e189f0fa3528a73e3f59714"
        )
        self.put_argparser.add_argument("--ecdsa", "-e", type=str, default=DEFAULT_ECDSA,
            help="If set to 'true', the key is assumed to be an ECDSA key; e.g. 'true', 'false' (default: %s)" % DEFAULT_ECDSA
        )

        # subparser for the del-command
        self.del_argparser = subparsers.add_parser(COMMAND_DEL, help="Delete an entry from the KeyStore.")

        self.del_argparser.add_argument("uuid", metavar="UUID", type=str,
            help="The UUID to delete the keypair for (this is safe since each UUID can only occur once in the KeyStore); e.g.: f99de1c4-3859-5326-a155-5696f00686d9"
        )

    def process_args(self) -> bool:
        # parse cli arguments (exists on err)
        self.args = self.argparser.parse_args()

        # get all needed args
        self.keystore_path = self.args.keystore
        self.keystore_pass = self.args.keystore_pass
        self.cmd = self.args.cmd

        # for put
        if self.cmd == COMMAND_PUT:
            self.uuid_str = self.args.uuid
            self.pubkey_str = self.args.pubkey
            self.prvkey_str = self.args.privkey
            self.ecdsa_str = self.args.ecdsa

            # get the bool for ecdsa
            if self.ecdsa_str.lower() in ["1", "yes", "y", "true"]:
                self.ecdsa = True
            else:
                self.ecdsa = False

            # load the keypair
            try:
                unhex_pubkey = binascii.unhexlify(self.pubkey_str)

                if self.ecdsa == True:
                    self.pubkey = ecdsa.VerifyingKey.from_string(unhex_pubkey, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
                else:
                    self.pubkey = ed25519.VerifyingKey(unhex_pubkey)
            except Exception as e:
                logger.error("Error loading the PubKey!")
                logger.exception(e)

                return False

            try:
                unhex_prvkey = binascii.unhexlify(self.prvkey_str)

                if self.ecdsa == True:
                    self.prvkey = ecdsa.SigningKey.from_string(unhex_prvkey, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
                else:
                    self.prvkey = ed25519.SigningKey(unhex_prvkey)
            except Exception as e:
                logger.error("Error loading the PrivKey!")
                logger.exception(e)

                return False
        elif self.cmd == COMMAND_GET:
            # for get
            self.show_sign_str = self.args.show_secret
            self.uuid_str = self.args.uuid

            # get the bool for show sk
            if self.show_sign_str.lower() in ["1", "yes", "y", "true"]:
                self.show_sign = True
            else:
                self.show_sign = False
        elif self.cmd == COMMAND_DEL:
            # for del
            self.uuid_str = self.args.uuid
        else:
            logger.error("Unknown command \"%s\"!" % self.cmd)

            return False

        # load the uuid if specified
        if self.uuid_str != None:
            try:
                self.uuid = uuid.UUID(self.uuid_str)
            except Exception as e:
                logger.error("Error loading UUID: \"%s\"" % self.uuid_str)
                logger.exception(e)

                return False

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
        for vk_uuid_mod in verifying_keys.keys():
            # check if a filtering uuid is set; if it is, filter
            if self.uuid != None:
                if self.uuid.hex != vk_uuid:
                    continue

            # check the key type
            if vk_uuid_mod.find("_ecd") != -1:
                vk_uuid = vk_uuid_mod[:-4]

                ktype = "ECDSA NIST256p SHA256"
            else:
                vk_uuid = vk_uuid_mod

                ktype = "ED25519"

            # get/show the private if the flag is set
            if self.show_sign == True:
                t = signing_keys.get("pke_" + vk_uuid)

                sk = binascii.hexlify(t.pkey).decode() if t != None else "N / A"
            else:
                sk = "█" * 128

            print("=" * 134)
            print("UUID: %s" % str(uuid.UUID(hex=vk_uuid)))
            print(" VK : %s" % binascii.hexlify(verifying_keys[vk_uuid_mod].cert).decode())
            print(" SK : %s" % sk)
            print("TYPE: %s" % ktype)
            print("=" * 134)

        return True

    def put_keypair(self) -> bool:
        logger.info("Inserting keypair for %s with pubkey %s into %s!" % (self.uuid_str, self.pubkey_str, self.keystore_path))

        try:
            if self.ecdsa == True:
                self.keystore.insert_ecdsa_keypair(self.uuid, self.pubkey, self.prvkey)
            else:
                self.keystore.insert_ed25519_keypair(self.uuid, self.pubkey, self.prvkey)
        except Exception as e:
            logger.error("Error inserting the keypair into the KeyStore!")
            logger.exception(e)

        return True

    def del_keypair(self) -> bool:
        logger.warning("About to remove the keypair for UUID %s from %s! Enter 'YES' to continue" % (self.uuid_str, self.keystore_path))

        # get user confirmation to delete
        if input("> ") != 'YES':
            logger.error("Aborting!")

            # stopped the process by user-choice; not a "real" error
            return True

        # delete both the pubkey and the private key entries
        try:
            # direkt access to the entries variable is needed since .certs and .private_keys
            # are class properties which are only temporary (-> editing them has no effect)
            if self.keystore._ks.entries.get(self.uuid.hex, None) != None:
                # suffix-less pubkey found, delete it
                self.keystore._ks.entries.pop(self.uuid.hex)
            else:
                # check for ecdsa key
                if self.keystore._ks.entries.get(self.uuid.hex + '_ecd', None) != None:
                    self.keystore._ks.entries.pop(self.uuid.hex + '_ecd')
                else:
                    # key not found
                    raise(ValueError("No key found for UUID '%s'" % self.uuid_str))

            self.keystore._ks.entries.pop("pke_" + self.uuid.hex)
        except Exception as e:
            logger.error("Error deleting keys! No changes will be written!")
            logger.exception(e)

            return False

        # write changes
        self.keystore._ks.save(self.keystore._ks_file, self.keystore._ks_password)

        return True

    def run(self) -> int:
        # process all raw argument values
        if self.process_args() != True:
            logger.error("Errors occured during argument processing - exiting!\n")

            self.argparser.print_help()

            return 1

        # initialize the keystore
        if self.init_keystore() != True:
            logger.error("Errors occured while initializing the uBirch Keystore - exiting!\n")

            self.argparser.print_help()

            return 1

        if self.cmd == COMMAND_GET:
            if self.dump_keystore() != True:
                logger.error("Errors occured while dumping the uBirch Keystore - exiting!\n")

                self.get_argparser.print_help()

                return 1
        elif self.cmd == COMMAND_PUT:
            if self.put_keypair() != True:
                logger.error("Errors occured while puting a new keypair into the KeyStore - exiting!\n")

                self.put_argparser.print_help()

                return 1
        elif self.cmd == COMMAND_DEL:
            if self.del_keypair() != True:
                logger.error("Errors occured while deleting a keypair from the KeyStore - exiting!\n")

                self.del_argparser.print_help()

                return 1
        else:
            logger.error("Unknown command \"%s\" - exiting!\n" % self.cmd)

            return 1

        return 0


# initialize/start the main class
if __name__ == "__main__":
    sys.exit(Main().run())
