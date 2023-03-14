import base64
import json
import logging
import hashlib, binascii, ecdsa, ed25519
import sys
import uuid

from datetime import datetime
from uuid import UUID
from requests import codes, Response

import ubirch
from ubirch.ubirch_protocol import UBIRCH_PROTOCOL_TYPE_REG

# import pdb

ECDSA_TYPE = "ecdsa"
EDDSA_TYPE = "ed25519"

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.INFO)
logger = logging.getLogger()

env = "demo"


class Proto(ubirch.Protocol):

    def __init__(self, env: str) -> None:
        super().__init__()
        self.ks = ubirch.KeyStore("test_key_registration.jks", "test")
        self.api = ubirch.API(env=env)

    def initialize_key(self, uuid: UUID, key_type: str) -> None:

        # check if the device already has keys or generate a new pair
        if not self.ks.exists_signing_key(uuid):
            # check the key type before creating new keys
            if key_type == EDDSA_TYPE:
                self.ks.create_ed25519_keypair(uuid)
            elif key_type == ECDSA_TYPE:
                self.ks.create_ecdsa_keypair(uuid)
            else:
                raise ValueError("unknown key type")

        else:
            # if a key already exists, make sure the existing key has the expected type
            if key_type == EDDSA_TYPE:
                expected = ed25519.SigningKey
            elif key_type == ECDSA_TYPE:
                expected = ecdsa.SigningKey
            else:
                raise ValueError(f"unsupported key type {key_type}")

            if not isinstance(self.ks.find_signing_key(uuid), expected):
                raise ValueError(f"existing key for {uuid} is not from expected type {key_type}")

    def register_key_msgpack(self, uuid: UUID, key_type: str) -> Response:
        self.initialize_key(uuid, key_type)

        pub_key_info = self.ks.get_certificate(uuid)
        key_reg = self.message_signed(uuid, UBIRCH_PROTOCOL_TYPE_REG, pub_key_info)

        logger.info("register {} identity [msgpack]: {}".format(key_type, binascii.hexlify(key_reg)))

        return self.api.register_identity(key_reg)

    def get_signed_key_reg_json(self, uuid: UUID, key_info: dict) -> bytes:
        sorted_keyinfo = json.dumps(key_info, sort_keys=True, indent=None, separators=(",", ":"))

        key_reg = {
            "pubKeyInfo": key_info,
            "signature": base64.b64encode(
                self._sign(uuid, sorted_keyinfo.encode(), hashing=False)
            ).decode()
        }

        return json.dumps(key_reg, sort_keys=True, indent=None, separators=(",", ":")).encode()

    def register_key_json(self, uuid: UUID, key_type: str) -> Response:
        self.initialize_key(uuid, key_type)

        pub_key_info = self.ks.get_certificate(uuid)

        pub_key_info['hwDeviceId'] = str(uuid)
        pub_key_info['pubKey'] = base64.b64encode(pub_key_info['pubKey']).decode()
        pub_key_info['pubKeyId'] = base64.b64encode(pub_key_info['pubKeyId']).decode()
        pub_key_info['created'] = str(datetime.utcfromtimestamp(pub_key_info['created']).isoformat() + ".000Z")
        pub_key_info['validNotAfter'] = str(
            datetime.utcfromtimestamp(pub_key_info['validNotAfter']).isoformat() + ".000Z")
        pub_key_info['validNotBefore'] = str(
            datetime.utcfromtimestamp(pub_key_info['validNotBefore']).isoformat() + ".000Z")

        key_reg = self.get_signed_key_reg_json(uuid, pub_key_info)

        logger.info("register {} identity [json]: {}".format(key_type, key_reg))

        return self.api.register_identity(key_reg)

    def get_signed_key_deletion_json(self, uuid: UUID, pub_key: bytes or str) -> bytes:

        key_deletion = {
            "publicKey": base64.b64encode(bytes(pub_key)).decode(),
            "signature": base64.b64encode(
                self._sign(uuid, bytes(pub_key), hashing=False)
            ).decode()
        }

        return json.dumps(key_deletion, sort_keys=True, indent=None, separators=(",", ":")).encode()

    def deregister_key(self, uuid: UUID, key_type: str) -> Response:

        pub_key = self.ks._find_cert(uuid).cert

        key_deletion = self.get_signed_key_deletion_json(uuid, pub_key)

        logger.info("de-register {} identity [json]: {}".format(key_type, key_deletion))

        return self.api.deregister_identity(key_deletion)

    def _sign(self, uuid: UUID, message: bytes, hashing: bool = True) -> bytes:
        signing_key = self.ks.find_signing_key(uuid)

        if isinstance(signing_key, ecdsa.SigningKey):
            # no hashing required here
            final_message = message
        elif isinstance(signing_key, ed25519.SigningKey):
            if hashing:
                final_message = hashlib.sha512(message).digest()
            else:
                final_message = bytes(message)
        else:
            raise (ValueError(f"Signing Key is neither ed25519, nor ecdsa! {type(signing_key)}"))

        return signing_key.sign(final_message)


proto = Proto(env)

# register eddsa msgpack
uuid_msgpack_ed = uuid.uuid4()

r = proto.register_key_msgpack(uuid_msgpack_ed, EDDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: EDDSA msgpack registration OK".format(uuid_msgpack_ed))
else:
    logger.error("{}: EDDSA msgpack registration failed".format(uuid_msgpack_ed))
    print()
print()

r = proto.deregister_key(uuid_msgpack_ed, EDDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: EDDSA deletion OK".format(uuid_msgpack_ed))
else:
    logger.error("{}: EDDSA deletion failed".format(uuid_msgpack_ed))
    print()
print()

# register ecdsa msgpack
uuid_msgpack_ec = uuid.uuid4()

r = proto.register_key_msgpack(uuid_msgpack_ec, ECDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: ECDSA msgpack registration OK".format(uuid_msgpack_ec))
else:
    logger.error("{}: ECDSA msgpack registration failed".format(uuid_msgpack_ec))
    print()
print()

r = proto.deregister_key(uuid_msgpack_ec, ECDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: ECDSA deletion OK".format(uuid_msgpack_ec))
else:
    logger.error("{}: ECDSA deletion failed".format(uuid_msgpack_ec))
    print()
print()

# register eddsa json
uuid_json_ed = uuid.uuid4()

r = proto.register_key_json(uuid_json_ed, EDDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: EDDSA json registration OK".format(uuid_json_ed))
else:
    logger.error("{}: EDDSA json registration failed".format(uuid_json_ed))
    print()
print()

r = proto.deregister_key(uuid_json_ed, EDDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: EDDSA deletion OK".format(uuid_json_ed))
else:
    logger.error("{}: EDDSA deletion failed".format(uuid_json_ed))
    print()
print()

# register ecdsa json
uuid_json_ec = uuid.uuid4()

r = proto.register_key_json(uuid_json_ec, ECDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: ECDSA json registration OK".format(uuid_json_ec))
else:
    logger.error("{}: ECDSA json registration failed".format(uuid_json_ec))
    print()
print()

r = proto.deregister_key(uuid_json_ec, ECDSA_TYPE)
if r.status_code == codes.ok:
    logger.info("{}: ECDSA deletion OK".format(uuid_json_ec))
else:
    logger.error("{}: ECDSA deletion failed".format(uuid_json_ec))
    print()
print()


class TestKeymanager:
    testProto = Proto(env)
    uuid_msgpack_ed = uuid.uuid4()
    uuid_msgpack_ec = uuid.uuid4()
    uuid_json_ed = uuid.uuid4()
    uuid_json_ec = uuid.uuid4()

    def test_register_eddsa_msgpack(self):
        r = self.testProto.register_key_msgpack(self.uuid_msgpack_ed, EDDSA_TYPE)
        assert r.status_code == codes.ok, f"ed25519 msgpack registration failed: [{r.status_code}] {r.content}"

    def test_register_ecdsa_msgpack(self):
        r = self.testProto.register_key_msgpack(self.uuid_msgpack_ec, ECDSA_TYPE)
        assert r.status_code == codes.ok, f"ecdsa msgpack registration failed: [{r.status_code}] {r.content}"

    def test_register_eddsa_json(self):
        r = self.testProto.register_key_json(self.uuid_json_ed, EDDSA_TYPE)
        assert r.status_code == codes.ok, f"ed25519 json registration failed: [{r.status_code}] {r.content}"

    def test_delete_eddsa_json(self):
        r = self.testProto.deregister_key(self.uuid_json_ed, EDDSA_TYPE)
        assert r.status_code == codes.ok, f"ed25519 json deletion failed: [{r.status_code}] {r.content}"

    def test_register_ecdsa_json(self):
        # pdb.set_trace()

        r = self.testProto.register_key_json(self.uuid_json_ec, ECDSA_TYPE)
        assert r.status_code == codes.ok, f"ecdsa json registration failed: [{r.status_code}] {r.content}"

    def test_delete_ecdsa_json(self):
        r = self.testProto.deregister_key(self.uuid_json_ec, ECDSA_TYPE)
        assert r.status_code == codes.ok, f"ecdsa json deletion failed: [{r.status_code}] {r.content}"
