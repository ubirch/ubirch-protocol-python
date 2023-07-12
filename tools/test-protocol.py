#! /usr/bin/env python3
#
# Copyright (c) 2018 ubirch GmbH.
#
# @author Matthias L. Jugel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import configparser
import hashlib
import json
import logging
import pickle
import sys
import time
import ecdsa
import ed25519
import uuid

import requests
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN
from ubirch.ubirch_backend_keys import EDDSA_TYPE, ECDSA_TYPE 

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):
    """!
    This class is a wrapper for the ubirch.Protocol class.
    It adds functionality for handling keys with different algorithms 
    and persitent signature handling via pickle. 
    """    
    def __init__(self, keystore: ubirch.KeyStore, key_type: str, env : str, ident_uuid: uuid.UUID):
        super().__init__()
        self.__ks = keystore
        self.load_saved_signatures(ident_uuid)

        # check the key type and set the corresponding hash algorithm
        if key_type == ECDSA_TYPE:
            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(ident_uuid):
                logger.info("Generating new keypair with ecdsa algorithm")
                self.__ks.create_ecdsa_keypair(ident_uuid)

            # make sure there is no ed25519 verifying key for the backend
            self.__ks.delete_ed25519_verifying_key(ubirch.get_backend_uuid(env))

            # insert the ecdsa verifying key for the backend
            self.__ks.insert_ecdsa_verifying_key(ubirch.get_backend_uuid(env),
                                                 ubirch.get_backend_verifying_key(env, ECDSA_TYPE))
            
            # select the hash algorithm for the signature
            self.hash_algo = hashlib.sha256
        
        elif key_type == EDDSA_TYPE:
            # check if the device already has keys or generate a new pair
            if not self.__ks.exists_signing_key(ident_uuid):
                logger.info("Generating new keypair with ed25519 algorithm")
                self.__ks.create_ed25519_keypair(ident_uuid)

            # make sure there is no ecdsa verifying key for the backend
            self.__ks.delete_ecdsa_verifying_key(ubirch.get_backend_uuid(env))

            # insert the ed25519 verifying key for the backend
            self.__ks.insert_ed25519_verifying_key(ubirch.get_backend_uuid(env),
                                                   ubirch.get_backend_verifying_key(env, EDDSA_TYPE))
            
            # select the hash algorithm for the signature
            self.hash_algo = hashlib.sha512


    def _sign(self, ident_uuid: uuid.UUID, message: bytes):
        signing_key = self.__ks.find_signing_key(ident_uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            return signing_key.sign(message)

        elif isinstance(signing_key, ed25519.SigningKey):
            hashed_message = hashlib.sha512(message).digest()
            return signing_key.sign(hashed_message)

        else:
            raise (ValueError("Signing Key is neither ed25519, nor ecdsa! It's: " + str(type(signing_key))))

    def _verify(self, ident_uuid: uuid.UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(ident_uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            return verifying_key.verify(signature, message)

        elif isinstance(verifying_key, ed25519.VerifyingKey):
            hashed_message = hashlib.sha512(message).digest()
            return verifying_key.verify(signature, hashed_message)

        else:
            raise (ValueError("Verifying Key is neither ed25519, nor ecdsa! It's: " + str(type(verifying_key))))

    def persist_signatures(self, ident_uuid: uuid.UUID):
        """! persist the latest signatures to a file """
        signatures = self.get_saved_signatures()
        with open(ident_uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load_saved_signatures(self, ident_uuid: uuid.UUID):
        """! load the latest signatures from a file """
        try:
            with open(ident_uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.info(f"Loaded {len(signatures)} known signatures")
                self.set_saved_signatures(signatures)
        except FileNotFoundError or EOFError:
            logger.warning("no existing saved signatures")
            pass

########################################################################


# load configuration from storage
config = configparser.ConfigParser()
config.read('demo-device.ini')
if not config.has_section('device'):
    config.add_section('device')
    device_uuid = input("Enter your UUID:")
    config.set('device', 'uuid', device_uuid)
    auth = input("Enter your API authentication token:")
    config.set('device', 'auth', auth)
    config.set('device', 'env', 'prod')
    config.set('device', 'debug', 'False')
    config.set('device', 'groups', '')
    with open('demo-device.ini', "w") as f:
        config.write(f)

device_uuid = uuid.UUID(hex=config.get('device', 'uuid'))
auth = config.get('device', 'auth')
env = config.get('device', 'env', fallback=None)
debug = config.getboolean('device', 'debug', fallback=False)
groups = list(filter(None, config.get('device', 'groups', fallback="").split(",")))

logger.info("UUID : {}".format(device_uuid))
logger.info("AUTH : {}".format(auth))
logger.info("ENV  : {}".format(env))
logger.info("DEBUG: {}".format(debug))

# create a new device uuid and a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create new protocol
proto = Proto(keystore, EDDSA_TYPE, env, device_uuid)

# use the ubirch API to create a new device and send data using the ubirch-protocol
api = ubirch.API(env=env, debug=debug)
api.set_authentication(device_uuid, auth)
# register the devices identity
if not api.is_identity_registered(device_uuid):
    registration_message = proto.message_signed(device_uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(device_uuid))
    r = api.register_identity(registration_message)
    if r.status_code == requests.codes.ok:
        logger.info("registered new identity: {}".format(device_uuid))
    else:
        logger.error("device registration failed: {}".format(device_uuid))
    logger.debug(r.content)

for i in range(3):
    # create a message like being sent to the customer backend
    # include an ID and timestamp in the data message to ensure a unique hash
    message = {
        "id": str(device_uuid),
        "ts": int(time.time()),
        "n": i
    }

    # create a compact rendering of the message to ensure determinism when creating the hash
    serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    logger.info("message({}): {}".format(i, serialized.decode()))

    # hash the message
    message_hash = hashlib.sha512(serialized).digest()
    logger.info("message hash({}): {}".format(i, binascii.b2a_base64(message_hash, newline=False).decode()))

    # create a new chained protocol message with the message hash
    upp = proto.message_chained(device_uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)
    logger.info("UPP({}): {}".format(i, binascii.hexlify(upp).decode()))

    # send chained protocol message to UBIRCH authentication service
    r = api.send(device_uuid, upp)
    if r.status_code == codes.ok:
        logger.info("UPP sent. backend response: {}".format(binascii.hexlify(r.content).decode()))
    else:
        logger.error(
            "sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
        sys.exit(1)

    # verify the backend response
    try:
        verified = proto.verify_signature(ubirch.get_backend_uuid(env),r.content)
        logger.info("backend response signature verified")
    except Exception as e:
        logger.error("backend response signature verification failed! {}".format(repr(e)))
        sys.exit(1)

# save last signature
proto.persist_signatures(device_uuid)
