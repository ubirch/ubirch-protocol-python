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
from uuid import UUID

import requests
from ed25519 import VerifyingKey
from requests import codes

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG, UBIRCH_PROTOCOL_TYPE_BIN

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):
    UUID_PROD = UUID(hex="10b2e1a4-56b3-4fff-9ada-cc8c20f93016")
    PUB_PROD = VerifyingKey("ef8048ad06c0285af0177009381830c46cec025d01d86085e75a4f0041c2e690", encoding='hex')

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store

        # check if the device already has keys or generate a new pair
        if not keystore.exists_signing_key(uuid):
            keystore.create_ed25519_keypair(uuid)

        # check if the keystore already has the backend key for verification or insert verifying key
        if not self.__ks.exists_verifying_key(self.UUID_PROD):
            self.__ks.insert_ed25519_verifying_key(self.UUID_PROD, self.PUB_PROD)

        # load last signature for device
        self.load(uuid)

        logger.info("ubirch-protocol: device id: {}".format(uuid))

    def persist(self, uuid: UUID):
        signatures = self.get_saved_signatures()
        with open(uuid.hex + ".sig", "wb") as f:
            pickle.dump(signatures, f)

    def load(self, uuid: UUID):
        try:
            with open(uuid.hex + ".sig", "rb") as f:
                signatures = pickle.load(f)
                logger.info("loaded {} known signatures".format(len(signatures)))
                self.set_saved_signatures(signatures)
        except FileNotFoundError:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        return self.__ks.find_verifying_key(uuid).verify(signature, message)

########################################################################


# load configuration from storage
config = configparser.ConfigParser()
config.read('demo-device.ini')
if not config.has_section('device'):
    config.add_section('device')
    uuid = input("Enter your UUID:")
    config.set('device', 'uuid', uuid)
    auth = input("Enter your API authentication token:")
    config.set('device', 'auth', auth)
    config.set('device', 'env', 'prod')
    config.set('device', 'debug', 'False')
    config.set('device', 'groups', '')
    with open('demo-device.ini', "w") as f:
        config.write(f)

uuid = UUID(hex=config.get('device', 'uuid'))
auth = config.get('device', 'auth')
env = config.get('device', 'env', fallback=None)
debug = config.getboolean('device', 'debug', fallback=False)
groups = list(filter(None, config.get('device', 'groups', fallback="").split(",")))

logger.info("UUID : {}".format(uuid))
logger.info("AUTH : {}".format(auth))
logger.info("ENV  : {}".format(env))
logger.info("DEBUG: {}".format(debug))

# create a new device uuid and a keystore for the device
keystore = ubirch.KeyStore("demo-device.jks", "keystore")

# create new protocol
proto = Proto(keystore, uuid)

# use the ubirch API to create a new device and send data using the ubirch-protocol
api = ubirch.API(env=env, debug=debug)
api.set_authentication(uuid, auth)
# register the devices identity
if not api.is_identity_registered(uuid):
    registration_message = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
    r = api.register_identity(registration_message)
    if r.status_code == requests.codes.ok:
        logger.info("registered new identity: {}".format(uuid))
    else:
        logger.error("device registration failed: {}".format(uuid))
    logger.debug(r.content)

for i in range(3):
    # create a message like being sent to the customer backend
    # include an ID and timestamp in the data message to ensure a unique hash
    message = {
        "id": str(uuid),
        "ts": int(time.time()),
        "n": i
    }

    # create a compact rendering of the message to ensure determinism when creating the hash
    serialized = json.dumps(message, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode()
    logger.info("message({}): {}".format(i, serialized.decode()))

    # hash the message
    message_hash = hashlib.sha256(serialized).digest()
    logger.info("message hash({}): {}".format(i, binascii.b2a_base64(message_hash).decode().rstrip("\n")))

    # create a new chained protocol message with the message hash
    upp = proto.message_chained(uuid, UBIRCH_PROTOCOL_TYPE_BIN, message_hash)
    logger.info("UPP({}): {}".format(i, binascii.hexlify(upp).decode()))

    # send chained protocol message to UBIRCH authentication service
    r = api.send(uuid, upp)
    if r.status_code == codes.ok:
        logger.info("UPP sent. backend response: {}".format(binascii.hexlify(r.content).decode()))
    else:
        logger.error(
            "sending UPP failed! response: ({}) {}".format(r.status_code, binascii.hexlify(r.content).decode()))
        sys.exit(1)

    # verify the backend response
    try:
        proto.message_verify(r.content)
        logger.info("backend response signature verified")
    except Exception as e:
        logger.error("backend response signature verification failed! {}".format(repr(e)))
        sys.exit(1)

# save last signature
proto.persist(uuid)
