from uuid import UUID

from ed25519 import VerifyingKey

import ubirch
from ubirch.ubirch_protocol import SIGNED

remote_uuid = UUID(hex="6eac4d0b-16e6-4508-8c46-22e7451ea5a1")
remote_vk = VerifyingKey("b12a906051f102881bbb487ee8264aa05d8d0fcc51218f2a47f562ceb9b0d068", encoding='hex')
# a random signed ubirch-protocol message
keystore = ubirch.KeyStore("demo-device.jks", "keystore")
keystore.insert_ed25519_verifying_key(remote_uuid, remote_vk)


class ProtocolImpl(ubirch.Protocol):
    def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> dict:
        return keystore.find_verifying_key(uuid).verify(signature, message)


proto = ProtocolImpl(SIGNED)

message = bytes.fromhex(
    "9512b06eac4d0b16e645088c4622e7451ea5a1ccef01da0040578a5b22ceb3e1"
    "d0d0f8947c098010133b44d3b1d2ab398758ffed11507b607ed37dbbe006f645"
    "f0ed0fdbeb1b48bb50fd71d832340ce024d5a0e21c0ebc8e0e")
print(proto.message_verify(message))
