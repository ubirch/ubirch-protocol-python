#! /usr/bin/env python3
#
# Copyright (c) 2018 ubirch GmbH.
#
# @author Christian Vandrei
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
import configparser
import json
import logging
import pickle
import ecdsa
import ed25519
import hashlib

import requests
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
        signing_key = self.__ks.find_signing_key(uuid)
        
        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Signing Key is neither ed25519, nor ecdsa!"))    
        
        return signing_key.sign(final_message)

    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        verifying_key = self.__ks.find_verifying_key(uuid)

        if isinstance(verifying_key, ecdsa.VerifyingKey):
            # no hashing required here
            final_message = message
        elif isinstance(verifying_key, ed25519.VerifyingKey):
            final_message = hashlib.sha512(message).digest() 
        else: 
            raise(ValueError("Verifying Key is neither ed25519, nor ecdsa!"))    
         
        return verifying_key.verify(signature, final_message)


########################################################################

# load configuration from storage
config_file = 'demo-web-of-trust.ini'
config = configparser.ConfigParser()
config.read(config_file)
if not config.has_section('misc'):
    config.add_section('misc')
    config.set('misc', 'env', 'demo')
    with open(config_file, "w") as f:
        config.write(f)
if not config.has_section('user1'):
    config.add_section('user1')
    config.set('user1', 'uuid', str(uuid4()))
    config.set('user1', 'deviceA', str(uuid4()))
    with open(config_file, "w") as f:
        config.write(f)
if not config.has_section('user2'):
    config.add_section('user2')
    config.set('user2', 'uuid', str(uuid4()))
    config.set('user2', 'deviceB', str(uuid4()))
    with open(config_file, "w") as f:
        config.write(f)

env = config.get('misc', 'env', fallback=None)
auth = None
user1_uuid = UUID(hex=config.get('user1', 'uuid'))
user1_deviceA = UUID(hex=config.get('user1', 'deviceA'))
user2_uuid = UUID(hex=config.get('user2', 'uuid'))
user2_deviceB = UUID(hex=config.get('user2', 'deviceB'))

logger.info("UUID (user1) : {}".format(user1_uuid))
logger.info("UUID (user1.deviceA) : {}".format(user1_deviceA))
logger.info("UUID (user2) : {}".format(user2_uuid))
logger.info("UUID (user2.deviceB) : {}".format(user2_deviceB))
logger.info("ENV  : {}".format(env))

keystore = ubirch.KeyStore("test-web-of-trust.jks", "test-keystore")

if not keystore.exists_signing_key(user1_uuid):
    keystore.create_ed25519_keypair(user1_uuid)
if not keystore.exists_signing_key(user1_deviceA):
    keystore.create_ed25519_keypair(user1_deviceA)
if not keystore.exists_signing_key(user2_uuid):
    keystore.create_ed25519_keypair(user2_uuid)
if not keystore.exists_signing_key(user2_deviceB):
    keystore.create_ed25519_keypair(user2_deviceB)

api = ubirch.API(env=env)
api.set_authentication(user1_uuid, auth)
api.set_authentication(user2_uuid, auth)


def upload_public_key(uuid: UUID, info_text: str):
    proto = Proto(keystore, uuid)
    if not api.is_identity_registered(uuid):
        registration_message = proto.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, keystore.get_certificate(uuid))
        r = api.register_identity(registration_message)
        if r.status_code == requests.codes.ok:
            logger.info(
                "public key upload successful: '{}' ({}): {}: {}".format(info_text, uuid, r.status_code, r.content))
        else:
            logger.info("register of '{}' ({}) failed: {}: {}".format(info_text, uuid, r.status_code, r.content))
        logger.debug(r.content)
    else:
        logger.info("already registered '{}' ({})".format(info_text, uuid))


def trust_key(from_uuid: UUID, to_uuid: UUID, trust_level=50):
    from_private_key = keystore.find_signing_key(from_uuid)
    from_public_key = keystore.find_verifying_key(from_uuid)
    from_public_key_base64 = base64.b64encode(from_public_key.to_bytes())

    to_public_key = keystore.find_verifying_key(to_uuid)
    to_public_key_base64 = base64.b64encode(to_public_key.to_bytes())

    trust_relation = {
        "created": "{}Z".format(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]),
        "sourcePublicKey": str(bytes.decode(from_public_key_base64)),
        "targetPublicKey": str(bytes.decode(to_public_key_base64)),
        "trustLevel": trust_level
    }
    compressed_json = json.dumps(trust_relation, separators=(',', ':'), sort_keys=True)
    signature = from_private_key.sign(str.encode(compressed_json))
    signed_trust = {
        "trustRelation": trust_relation,
        "signature": bytes.decode(base64.b64encode(signature))
    }

    r = api.trust_identity_json(signed_trust)
    if r.status_code == requests.codes.ok:
        logger.info("uploaded trust: {} --{}--> {}".format(from_uuid, trust_level, to_uuid))
    else:
        logger.error(
            "failed to upload trust: {} --{}--> {} ({} {})".format(from_uuid, trust_level, to_uuid, r.status_code,
                                                                   r.content))


def get_trusted(source_public_key: UUID, depth=3, min_trust_level=50) -> requests.Response:
    private_key = keystore.find_signing_key(source_public_key)
    public_key = keystore.find_verifying_key(source_public_key)
    public_key_base64 = base64.b64encode(public_key.to_bytes())

    find_trusted = {
        "depth": depth,
        "minTrustLevel": min_trust_level,
        "queryDate": "{}Z".format(datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]),
        "sourcePublicKey": str(bytes.decode(public_key_base64))
    }
    compressed_json = json.dumps(find_trusted, separators=(',', ':'), sort_keys=True)
    signature = private_key.sign(str.encode(compressed_json))
    signed_find_trusted = {
        "findTrusted": find_trusted,
        "signature": bytes.decode(base64.b64encode(signature))
    }

    r = api.get_trusted_identities_json(signed_find_trusted)
    if r.status_code == requests.codes.ok:
        logger.info(
            "found trusted: {} (depth={}, min_trust_level={}) -> {}".format(source_public_key, depth, min_trust_level,
                                                                            r.content))
        return r.content
    else:
        logger.error(
            "failed to find trusted: {} (depth={}, min_trust_level={}) ({} {})".format(source_public_key, depth,
                                                                                       min_trust_level, r.status_code,
                                                                                       r.content))
        return r.content


# upload public keys
upload_public_key(user1_uuid, "user1")
upload_public_key(user1_deviceA, "user1-deviceA")
upload_public_key(user2_uuid, "user2")
upload_public_key(user2_deviceB, "user2-deviceB")

# create web-of-trust
trust_key(user1_uuid, user1_deviceA, 100)
trust_key(user1_deviceA, user1_uuid, 100)

trust_key(user2_uuid, user2_deviceB, 100)
trust_key(user2_deviceB, user2_uuid, 100)

trust_key(user1_uuid, user2_uuid)
trust_key(user2_uuid, user1_uuid)

# search for trusted keys
source_key = user1_deviceA
logger.info("====== Find Trusted Keys: depth={}, minimum_trust={}".format(3, 50))
get_trusted(source_key)
logger.info("====== Find Trusted Keys: depth={}, minimum_trust={}".format(3, 60))
get_trusted(source_key, min_trust_level=60)
logger.info("====== Find Trusted Keys: depth={}, minimum_trust={}".format(2, 50))
get_trusted(source_key, depth=2)
