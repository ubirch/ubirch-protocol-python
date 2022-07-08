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
import os
from uuid import UUID
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

    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        signing_key = self.__ks.find_signing_key(uuid)
        
        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return signing_key.sign(final_message)


if None in (os.getenv("UBIRCH_UUID"), os.getenv("UBIRCH_AUTH"), os.getenv("UBIRCH_ENV")):
    print("usage:")
    print("  export UBIRCH_UUID=<UUID>")
    print("  export UBIRCH_AUTH=<ubirch-authorization-token>")
    print("  export UBIRCH_ENV=[dev|demo|prod]")
    print("  PYTHONPATH=. python3 examples/test-identity.py")
    import sys

    sys.exit(0)

uuid = UUID(hex=os.getenv("UBIRCH_UUID"))
auth = os.getenv("UBIRCH_AUTH")
env = os.getenv("UBIRCH_ENV")

logger.info("UUID : {}".format(uuid))
logger.info("AUTH : {}".format(auth))
logger.info("ENV  : {}".format(env))

# create a keystore for the device
keystore = ubirch.KeyStore("test-identity.jks", "test-keystore")

# check if the device already has keys or generate a new pair
if not keystore.exists_signing_key(uuid):
    keystore.create_ed25519_keypair(uuid)

# get the keys
sk = keystore.find_signing_key(uuid)
vk = keystore.find_verifying_key(uuid)

# create protocol instance
proto = Proto(keystore)

# create API instance
api = ubirch.API(env=env)
api.set_authentication(uuid, auth)

# register public key
key_registration = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
r = api.register_identity(key_registration)
logger.info("registered: {}: {}".format(r.status_code, r.content))

# de-register public key
key_deregistration = str.encode(json.dumps({
    "publicKey": bytes.decode(base64.b64encode(vk.to_bytes())),
    "signature": bytes.decode(base64.b64encode(sk.sign(vk.to_bytes())))
}))
r = api.deregister_identity(key_deregistration)
logger.info("deregistered: {}: {}".format(r.status_code, r.content))
