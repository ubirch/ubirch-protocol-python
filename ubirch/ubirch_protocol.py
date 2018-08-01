from abc import abstractmethod

import msgpack
from Crypto.Hash import SHA512

UBIRCH_PROTOCOL_VERSION = 1
PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)


class UbirchProtocol(object):
    _last_signature: str

    def __init__(self, variant: int = SIGNED) -> None:
        self.__version = variant
        self._last_signature = b'\0' * 64

        if self.__version not in (PLAIN, SIGNED, CHAINED):
            raise Exception("protocol variant unknown: {}".format(self.__version))

    @abstractmethod
    def _sign(self, message: bytes) -> bytes:
        """Sign the request when finished."""
        pass

    def __serialize(self, msg: any) -> bytearray:
        serialized = bytearray(msgpack.packb(msg))
        # TODO fix this issue below
        # fix the 16bit version
        serialized[2] = 0x00
        return serialized

    def message(self, id: bytes, type: int, payload: any) -> bytes:
        """
        Create a new ubirch-protocol message.
        Stores the context, the last signature, to be included in the next message.
        """
        if len(id) > 16:
            raise Exception("id must be 16 bytes or less")

        # TODO fix this issue with the 16bit serialization
        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [0xFF << 8 | self.__version, id.rjust(16, b'\0')]

        if self.__version is CHAINED:
            msg.append(self._last_signature)

        msg.append(type)
        msg.append(payload)

        if self.__version in (SIGNED, CHAINED):
            msg.append(0)
            # sign the message and store the signature
            serialized = self.__serialize(msg)[0:-2]
            sha515digest = SHA512.new(serialized).digest()
            signature = self._sign(sha515digest)
            # replace last element in array with the signature
            msg[-1] = signature
            self._last_signature = signature

        # serialize result and return the message
        return self.__serialize(msg)
