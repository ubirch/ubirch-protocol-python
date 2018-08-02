# ubirch protocol
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

import logging
from abc import abstractmethod
from uuid import UUID

import hashlib
import msgpack

log = logging.getLogger(__name__)

# ubirch-protocol constants
UBIRCH_PROTOCOL_VERSION = 1

PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)

UBIRCH_PROTOCOL_TYPE_BIN = 0x00
UBIRCH_PROTOCOL_TYPE_REG = 0x01
UBIRCH_PROTOCOL_TYPE_HSK = 0x02

class Protocol(object):
    def __init__(self) -> None:
        self._last_signature = self._load_signature()
        if len(self._last_signature) != 64:
            log.warning("last signature size wrong (len={})".format(len(self._last_signature)))
            self._last_signature = b'\0' * 64

    @abstractmethod
    def _sign(self, message: bytes) -> bytes:
        """Sign the request when finished."""
        pass

    @abstractmethod
    def _save_signature(self, signature: bytes) -> None:
        """Save the last signature persistently."""
        log.warning("last signature not saved, implement Protocol._save_signature()")
        pass

    @abstractmethod
    def _load_signature(self) -> bytes:
        """Load the last signature on startup."""
        log.warning("last signature not loaded, implement Protocol._load_signature()")
        return b'\0' * 64

    def __serialize(self, msg: any) -> bytearray:
        serialized = bytearray(msgpack.packb(msg))
        # TODO fix this issue below
        # fix the 16bit version
        serialized[2] = 0x00
        return serialized

    def __sign(self, msg: any) -> (bytes, bytes):
        # sign the message and store the signature
        serialized = self.__serialize(msg)[0:-1]
        sha515digest = hashlib.sha512(serialized).digest()
        signature = self._sign(sha515digest)
        # replace last element in array with the signature
        msg[-1] = signature
        return (signature, self.__serialize(msg))


    def message_signed(self, uuid: UUID, type: int, payload: any) -> bytes:
        """Create a new signed ubirch-protocol message."""
        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            0xFF << 8 | SIGNED,
            uuid.bytes,
            type,
            payload,
            0
        ]

        (self._last_signature, serialized) = self.__sign(msg)

        # serialize result and return the message
        return serialized


    def message_chained(self, uuid: UUID, type: int, payload: any) -> bytes:
        """
        Create a new chained ubirch-protocol message.
        Stores the context, the last signature, to be included in the next message.
        """

        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            0xFF << 8 | CHAINED,
            uuid.bytes,
            self._last_signature,
            type,
            payload,
            0
        ]

        (self._last_signature, serialized) = self.__sign(msg)
        self._save_signature(self._last_signature)

        # serialize result and return the message
        return serialized

