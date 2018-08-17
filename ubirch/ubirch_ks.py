# ubirch key store
#
# @author Matthias L. Jugel
#
# Copyright (c) 2018 ubirch GmbH.
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

from datetime import datetime, timedelta
from logging import getLogger
from os import urandom
from uuid import UUID

import ed25519
from ed25519 import SigningKey, VerifyingKey
from jks import jks, AlgorithmIdentifier, rfc5208, TrustedCertEntry
from pyasn1.codec.ber import encoder

logger = getLogger(__name__)

ECC_ENCRYPTION_OID = (1, 2, 1, 3, 101, 112)


class ED25519Certificate(TrustedCertEntry):

    def __init__(self, alias: str, verifying_key: VerifyingKey, **kwargs):
        super().__init__(**kwargs)
        self.alias = alias
        self.cert = verifying_key.to_bytes()
        self.timestamp = int(datetime.utcnow().timestamp())


class KeyStore(object):
    """
    The ubirch key store handles the keys relevant for the ubirch protocol.
    """

    def __init__(self, keystore_file: str, password: str) -> None:
        """Initialize the ubirch-protocol for the device with the given UUID."""
        super().__init__()
        self._ks_file = keystore_file
        self._ks_password = password
        self._load_keys()

    def _load_keys(self) -> None:
        """Load or create new crypto-keys. The keys are stored in a local key store."""
        try:
            self._ks = jks.KeyStore.load(self._ks_file, self._ks_password)
        except FileNotFoundError:
            logger.warning("creating new key store: {}".format(self._ks_file))
            self._ks = jks.KeyStore.new("jks", [])

    def insert_ed25519_signing_key(self, uuid, sk: SigningKey):
        """Insert an existing ED25519 signing key."""
        # encode the ED25519 private key as PKCS#8
        private_key_info = rfc5208.PrivateKeyInfo()
        private_key_info.setComponentByName('version', 'v1')
        a = AlgorithmIdentifier()
        a.setComponentByName('algorithm', ECC_ENCRYPTION_OID)
        private_key_info.setComponentByName('privateKeyAlgorithm', a)
        private_key_info.setComponentByName('privateKey', sk.to_bytes())
        pkey_pkcs8 = encoder.encode(private_key_info)
        pke = jks.PrivateKeyEntry.new(alias=str(uuid.hex), certs=[], key=pkey_pkcs8)
        self._ks.entries['pke_' + uuid.hex] = pke

    def insert_ed25519_verifying_key(self, uuid, vk: VerifyingKey):
        # store verifying key in certificate store
        self._ks.entries[uuid.hex] = ED25519Certificate(uuid.hex, vk)

    def insert_ed25519_keypair(self, uuid: UUID, vk: VerifyingKey, sk: SigningKey) -> (VerifyingKey, SigningKey):
        """Insert an existing ED25519 key pair into the key store."""
        if uuid.hex in self._ks.entries or uuid.hex in self._ks.certs:
            raise Exception("uuid '{}' already exists in keystore".format(uuid.hex))

        self.insert_ed25519_verifying_key(uuid, vk)
        self.insert_ed25519_signing_key(uuid, sk)
        self._ks.save(self._ks_file, self._ks_password)
        logger.info("inserted new key pair for {}: {}".format(uuid.hex, bytes.decode(vk.to_ascii(encoding='hex'))))
        return (vk, sk)

    def create_ed25519_keypair(self, uuid: UUID) -> (VerifyingKey, SigningKey):
        """Create a new ED25519 key pair and store in key store."""
        sk, vk = ed25519.create_keypair(entropy=urandom)
        return self.insert_ed25519_keypair(uuid, vk, sk)

    def exists_signing_key(self, uuid: UUID):
        """Check whether this UUID has a signing key in the key store."""
        return 'pke_' + uuid.hex in self._ks.private_keys

    def exists_verifying_key(self, uuid: UUID):
        """Check whether this UUID has a verifying key in the key store."""
        return uuid.hex in self._ks.certs

    def find_signing_key(self, uuid: UUID) -> SigningKey:
        """Find the signing key for this UUID."""
        sk = self._ks.private_keys['pke_' + uuid.hex]
        return SigningKey(sk.pkey)

    def find_verifying_key(self, uuid: UUID) -> VerifyingKey:
        """Find the verifying key for this UUID."""
        cert = self._ks.certs[uuid.hex]
        return VerifyingKey(cert.cert)

    def get_certificate(self, uuid: UUID) -> dict or None:
        if not uuid.hex in self._ks.certs:
            return None

        cert = self._ks.certs[uuid.hex]
        vk = VerifyingKey(cert.cert)
        created = datetime.fromtimestamp(cert.timestamp)
        not_before = datetime.fromtimestamp(cert.timestamp)
        # TODO fix handling of key validity
        not_after = created + timedelta(days=365)
        return {
            "algorithm": 'ECC_ED25519',
            "created": int(created.timestamp()),
            "hwDeviceId": uuid.bytes,
            "pubKey": vk.to_bytes(),
            "pubKeyId": vk.to_bytes(),
            "validNotAfter": int(not_after.timestamp()),
            "validNotBefore": int(not_before.timestamp())
        }
