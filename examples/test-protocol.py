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

import atexit
import binascii
import configparser
import logging
import pickle
import time
from datetime import datetime
from uuid import UUID, uuid4

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


########################################################################
# Implement the ubirch-protocol with signing and saving the signatures
class Proto(ubirch.Protocol):

    def __init__(self, key_store: ubirch.KeyStore, uuid: UUID) -> None:
        super().__init__()
        self.__ks = key_store
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
        except:
            logger.warning("no existing saved signatures")
            pass

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        return self.__ks.find_signing_key(uuid).sign(message)


########################################################################

# load configuration from storage
config = configparser.ConfigParser()
config.read('demo-device.ini')
if not config.has_section('device'):
    config.add_section('device')
    config.set('device', 'uuid', str(uuid4()))
    auth = input("Enter your API authentication token:")
    config.set('device', 'auth', auth)
    config.set('device', 'env', 'demo')
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
keystore = ubirch.KeyStore(uuid.hex + ".jks", "test-keystore")

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# create new protocol
proto = Proto(keystore, uuid)

# use the ubirch API to create a new device and send data using the ubirch-protocol
api = ubirch.API(auth=auth, debug=debug, env=env)

# check if the device exists and delete if that is the case
if api.device_exists(uuid):
    logger.warning("device {} exists, deleting".format(str(uuid)))
    api.device_delete(uuid)
    time.sleep(2)

# create a new device on the backend
r = api.device_create({
    "deviceId": str(uuid),
    "deviceTypeKey": "genericSensor",
    "deviceName": str(uuid),
    "hwDeviceId": str(uuid),
    "tags": ["demo", "python-client"],
    "groups": groups,
    "deviceProperties": {
        "storesData": "true",
        "blockChain": "false"
    },
    "created": "{}Z".format(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3])
})
if r.status_code == 200:
    logger.info("created new device: {}".format(str(uuid)))
    logger.debug(r.content)
    time.sleep(2)
else:
    logger.error(r.content)
    raise Exception("new device creation failed")

# register the devices identity
if not api.is_identity_registered(uuid):
    registration_message = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
    r = api.register_identity(registration_message)
    if r.status_code == 200:
        logger.info("registered new identity: {}".format(uuid))
    else:
        logger.error("device registration failed: {}".format(uuid))
    logger.debug(r.content)

# send data packages

# message 1
msg = proto.message_chained(uuid, 0x53, {'ts': int(datetime.utcnow().timestamp()), 'v': 99})
logger.info(binascii.hexlify(msg))
r = api.send(msg)
logger.info("{}: {}".format(r.status_code, r.content))

# message 2 (chained to message 1)
msg = proto.message_chained(uuid, 0x53, {"ts": int(datetime.utcnow().timestamp()), "v": 100})
logger.info(binascii.hexlify(msg))
r = api.send(msg)
logger.info("{}: {}".format(r.status_code, r.content))

atexit.register(proto.persist, uuid)
