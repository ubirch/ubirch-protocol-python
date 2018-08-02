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

import binascii
from typing import Optional

import msgpack
from Crypto.Hash import SHA512

UBIRCH_PROTOCOL_VERSION = 1
PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)

log = logging.getLogger(__name__)


class Protocol(object):
    def __init__(self, variant: int = SIGNED) -> None:
        self.__version = variant
        self._last_signature = self._load_signature()
        if len(self._last_signature) != 64:
            log.warning("last signature size wrong (len={})".format(len(self._last_signature)))
            self._last_signature = b'\0' * 64

        if self.__version not in (PLAIN, SIGNED, CHAINED):
            raise Exception("protocol variant unknown: {}".format(self.__version))

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

    def message(self, id: bytes, type: int, payload: any) -> bytes:
        """
        Create a new ubirch-protocol message.
        Stores the context, the last signature, to be included in the next message.
        """
        if len(id) > 16:
            raise Exception("id must be 16 bytes or less")

        # TODO fix this issue with the 16bit serialization
        if self.__version > 0xFF:
            log.warning("protocol version (0x{:04x}) may be broken, due to library workaround".format(self.__version))

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
            self._save_signature(signature)

        # serialize result and return the message
        return self.__serialize(msg)
