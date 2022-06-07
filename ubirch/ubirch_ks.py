##
# @file ubirch_ks.py
# ubirch key store
#
# @author Matthias L. Jugel
#
# @copyright Copyright (c) 2018 ubirch GmbH.
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
import hashlib
from datetime import datetime, timedelta
from logging import getLogger
from os import urandom
from uuid import UUID

import base64
import ecdsa
import ed25519
from jks import jks, AlgorithmIdentifier, rfc5208, TrustedCertEntry
from pyasn1.codec.ber import encoder

logger = getLogger(__name__)

EDDSA_OID = (1, 2, 1, 3, 101, 112)
ECDSA_OID = (1, 2, 840, 10045, 4, 3, 2)


class ED25519Certificate(TrustedCertEntry):
    """!
    A ED25519 Certificate
    """

    def __init__(self, alias: str, verifying_key: ed25519.VerifyingKey, **kwargs):
        """!
        Initialize a ED 25519 Certificate
        @param alias A name for this Certificate, mostly in form of a UUID
        @param verifying_key A ed25519.VerifyingKey that has been generated with ed25519.create_keypair()
        @param kwargs Give more Arguments to pass them on to the super class 'TrustedCertEntry'
        """
        super().__init__(**kwargs)
        self.alias = alias
        self.cert = verifying_key.to_bytes()
        self.timestamp = int(datetime.utcnow().timestamp())

class ECDSACertificate(TrustedCertEntry):
    """!
    A ECDSA Certificate
    """

    def __init__(self, alias: str, verifying_key: ecdsa.VerifyingKey, **kwargs):
        """!
        Initialize a ECDSA Certificate with an alias and a verifying key
        @param alias A name for this Certificate, mostly in form of a UUID
        @param verifying_key A ed25519.VerifyingKey that has been generated with ed25519.create_keypair()
        @param kwargs Give more Arguments to pass them on to the super class 'TrustedCertEntry'
        """
        super().__init__(**kwargs)
        self.alias = alias
        self.cert = verifying_key.to_string()
        self.timestamp = int(datetime.utcnow().timestamp())

class KeyStore(object):
    """!
    Assists at handling keys relevant for the ubirch protocol
    """

    def __init__(self, keystore_file: str, password: str) -> None:
        """!
        Initialize the KeyStore
        @param keystore_file The name of the keystore file
        @param password The password of the keystore file. Please use a strong password like generated here: https://passwords-generator.org/

        """
        super().__init__()
        self._ks_file = keystore_file
        self._ks_password = password
        self._load_keys()

    def _load_keys(self) -> None:
        """!
        Load or create new crypto-keys. The keys are stored in a local key store.
        """
        try:
            self._ks = jks.KeyStore.load(self._ks_file, self._ks_password)
        except FileNotFoundError:
            logger.warning("creating new key store: {}".format(self._ks_file))
            self._ks = jks.KeyStore.new("jks", [])

    def insert_ed25519_signing_key(self, uuid: UUID, sk: ed25519.SigningKey):
        """!
        Store an existing ED25519 signing key in the key store.
        @param uuid The UUID of the device
        @param sk A ed25519.SigningKey like generated from ed25519.create_keypair()
        """
        # encode the ED25519 private key as PKCS#8
        private_key_info = rfc5208.PrivateKeyInfo()
        private_key_info.setComponentByName('version', 'v1')
        a = AlgorithmIdentifier()
        a.setComponentByName('algorithm', EDDSA_OID)
        private_key_info.setComponentByName('privateKeyAlgorithm', a)
        private_key_info.setComponentByName('privateKey', sk.to_bytes())
        pkey_pkcs8 = encoder.encode(private_key_info)
        pke = jks.PrivateKeyEntry.new(alias=str(uuid.hex), certs=[], key=pkey_pkcs8)
        self._ks.entries['pke_' + uuid.hex] = pke

    def insert_ed25519_verifying_key(self, uuid: UUID, vk: ed25519.VerifyingKey):
        """!
        Store an existing ED25519 verifying key in the key store.
        @param uuid The UUID of the device
        @param vk A ed25519.VerifyingKey like generated from ed25519.create_keypair()
        """
        self._ks.entries[uuid.hex] = ED25519Certificate(uuid.hex, vk)

    def insert_ed25519_keypair(self, uuid: UUID, vk: ed25519.VerifyingKey, sk: ed25519.SigningKey) -> (
    ed25519.VerifyingKey, ed25519.SigningKey):
        """!
        Store an existing ED25519 key pair in the key store.
        @param uuid The UUID of the device
        @param vk A ed25519.VerifyingKey like generated from ed25519.create_keypair()
        @param sk A ed25519.SigningKey like generated from ed25519.create_keypair()
        @return The verifying key and the signing key
        """
        if uuid.hex in self._ks.entries or uuid.hex in self._ks.certs:
            raise Exception("uuid '{}' already exists in keystore".format(uuid.hex))

        self.insert_ed25519_verifying_key(uuid, vk)
        self.insert_ed25519_signing_key(uuid, sk)
        self._ks.save(self._ks_file, self._ks_password)
        logger.info("inserted new key pair for {}: {}".format(uuid.hex, bytes.decode(vk.to_ascii(encoding='hex'))))
        return vk, sk

    def create_ed25519_keypair(self, uuid: UUID) -> (ed25519.VerifyingKey, ed25519.SigningKey):
        """!
        Create a new ED25519 key pair and store it in key store.
        @param uuid The UUID of the device
        @return The verifying key and the signing key
        """
        sk, vk = ed25519.create_keypair(entropy=urandom)
        return self.insert_ed25519_keypair(uuid, vk, sk)

    def insert_ecdsa_signing_key(self, uuid, sk: ecdsa.SigningKey):
        """!
        Insert an existing ECDSA signing key.
        @param uuid The UUID of the device
        @param sk A ed25519.SigningKey like generated from ed25519.create_keypair()
        """
        # encode the ECDSA private key as PKCS#8
        private_key_info = rfc5208.PrivateKeyInfo()
        private_key_info.setComponentByName('version', 'v1')
        a = AlgorithmIdentifier()
        a.setComponentByName('algorithm', ECDSA_OID)
        private_key_info.setComponentByName('privateKeyAlgorithm', a)
        private_key_info.setComponentByName('privateKey', sk.to_string())
        pkey_pkcs8 = encoder.encode(private_key_info)
        pke = jks.PrivateKeyEntry.new(alias=str(uuid.hex), certs=[], key=pkey_pkcs8)
        self._ks.entries['pke_' + uuid.hex] = pke

    def insert_ecdsa_verifying_key(self, uuid, vk: ecdsa.VerifyingKey):
        # store verifying key in certificate store
        # ecdsa VKs are marked with a "_ecd" suffix
        self._ks.entries[uuid.hex + '_ecd'] = ECDSACertificate(uuid.hex, vk)

    def insert_ecdsa_keypair(self, uuid: UUID, vk: ecdsa.VerifyingKey, sk: ecdsa.SigningKey) -> (ecdsa.VerifyingKey, ecdsa.SigningKey):
        """! Insert an existing ECDSA key pair into the key store."""
        if uuid.hex in self._ks.entries or uuid.hex in self._ks.certs:
            raise Exception("uuid '{}' already exists in keystore".format(uuid.hex))

        self.insert_ecdsa_verifying_key(uuid, vk)
        self.insert_ecdsa_signing_key(uuid, sk)
        self._ks.save(self._ks_file, self._ks_password)
        #logger.info("inserted new key pair for {}: {}".format(uuid.hex, vk.to_string().decode()))
        return (vk, sk)

    def create_ecdsa_keypair(self, uuid: UUID, curve: ecdsa.curves.Curve = ecdsa.NIST256p, hashfunc=hashlib.sha256) -> (ecdsa.VerifyingKey, ecdsa.SigningKey):
        """! Create new ECDSA key pair and store in key store"""

        sk = ecdsa.SigningKey.generate(curve=curve, entropy=urandom, hashfunc=hashfunc)
        vk = sk.get_verifying_key()
        return self.insert_ecdsa_keypair(uuid, vk, sk)

    def exists_signing_key(self, uuid: UUID):
        """! Check whether this UUID has a signing key in the key store."""
        return 'pke_' + uuid.hex in self._ks.private_keys

    def exists_verifying_key(self, uuid: UUID):
        """! Check whether this UUID has a verifying key in the key store."""
        return uuid.hex in self._ks.certs or (uuid.hex + '_ecd') in self._ks.certs

    def find_signing_key(self, uuid: UUID) -> ed25519.SigningKey or ecdsa.SigningKey:
        """! Find the signing key for this UUID."""
        # try to find a matching sk for the uuid
        try:
            sk : PrivateKeyEntry = self._ks.private_keys['pke_' + uuid.hex]
        except KeyError as e:
            # there is no sk for the given uuid
            return None
        
        # check whether the entry is encrypted
        if sk.is_decrypted() == False:
            sk.decrypt(self._ks_password)

        # check the _OID to identify the key type
        if sk._algorithm_oid == EDDSA_OID:
            return ed25519.SigningKey(sk.pkey)
        elif sk._algorithm_oid == ECDSA_OID:
            # ==================================== IMPORTANT ====================================
            #   The used curve as well as the used hash function have to be explicitly set here
            #   to match the ones used in create_ecdsa_keypair(), otherwise the ._from_string()
            #   function will throw exceptions because of unexpected/wrong keystr lengths (...)
            # ===================================================================================
            return ecdsa.SigningKey.from_string(sk.pkey, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)
        else:
            raise Exception("stored key with unknown algorithm OID: '{}'".format(sk._algorithm_oid))

    def _find_cert(self, uuid: UUID) -> ECDSACertificate or ED25519Certificate:
        """! Find the stored cert for uuid """
        cert = None

        if self.exists_verifying_key(uuid) == True:
            # try to get the edd key first
            try:
                cert = ED25519Certificate(
                    self._ks.certs[uuid.hex].alias,

                    # the ED25519Certificate requires an ed25519.VerifyingKey
                    ed25519.VerifyingKey(self._ks.certs[uuid.hex].cert)
                )
            except KeyError:
                pass

            # no edd key found, try to get ecd
            try:
                cert = ECDSACertificate(
                    self._ks.certs[uuid.hex + '_ecd'].alias,

                    # the ECDSACertifcate requires an ecdsa.VerifyingKey
                    ecdsa.VerifyingKey.from_string(
                        self._ks.certs[uuid.hex + '_ecd'].cert,
                        hashfunc=hashlib.sha256, curve=ecdsa.NIST256p
                    )
                )
            except KeyError:
                pass

        return cert

    def find_verifying_key(self, uuid: UUID) -> ed25519.VerifyingKey or ecdsa.VerifyingKey:
        """! Find the verifying key for this UUID."""
        cert = self._find_cert(uuid)

        if type(cert) == ED25519Certificate:
            return ed25519.VerifyingKey(cert.cert)
        elif type(cert) == ECDSACertificate:
            return ecdsa.VerifyingKey.from_string(cert.cert, curve=ecdsa.NIST256p, hashfunc=hashlib.sha256)

        return None

    def get_certificate(self, uuid: UUID, validityInDays : int = 3650) -> dict or None:
        """! Get the public key info for key registration"""
        # try to find the cert
        cert = self._find_cert(uuid)

        if cert == None:
            return None

        # set the timestamps (validity = +10 years)
        # TODO set propper validity timestamp
        created = datetime.fromtimestamp(cert.timestamp)
        not_before = datetime.fromtimestamp(cert.timestamp)
        not_after = created + timedelta(days=validityInDays)
        
        # set the alogrithm
        if type(cert) == ED25519Certificate:
            algo = 'ECC_ED25519'
        elif type(cert) == ECDSACertificate:
            algo = 'ecdsa-p256v1'
        else:
            raise Exception("Unexpected certificate class %s" % str(cert.__class__))

        return {
            "algorithm": algo,
            "created": int(created.timestamp()),
            "hwDeviceId": uuid.bytes,
            "pubKey": cert.cert,
            "pubKeyId": cert.cert,
            "validNotAfter": int(not_after.timestamp()),
            "validNotBefore": int(not_before.timestamp())
        }
