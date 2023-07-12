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

import base64
import json
import logging
import configparser
import uuid
import ecdsa
import ed25519
import hashlib

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
logger = logging.getLogger()


class Proto(ubirch.Protocol):
    def __init__(self, key_store: ubirch.KeyStore) -> None:
        super().__init__()
        self.__ks = key_store

    def _sign(self, device_uuid: uuid.UUID, message: bytes) -> bytes:
        signing_key = self.__ks.find_signing_key(device_uuid)
        
        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return signing_key.sign(final_message)


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

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(device_uuid):
    keystore.create_ed25519_keypair(device_uuid)

# get the keys
sk = keystore.find_signing_key(device_uuid)
vk = keystore.find_verifying_key(device_uuid)

# create protocol instance
proto = Proto(keystore)

# create API instance
api = ubirch.API(env=env)
api.set_authentication(device_uuid, auth)

# register public key
key_registration = proto.message_signed(device_uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(device_uuid))
r = api.register_identity(key_registration)
logger.info("registered: {}: {}".format(r.status_code, r.content))

# de-register public key
key_deregistration = str.encode(json.dumps({
    "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
    "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
}))
r = api.deregister_identity(key_deregistration)
logger.info("deregistered: {}: {}".format(r.status_code, r.content))
