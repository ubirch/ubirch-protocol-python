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

import hashlib
import logging
from abc import abstractmethod
from uuid import UUID

import msgpack

logger = logging.getLogger(__name__)

# ubirch-protocol constants
UBIRCH_PROTOCOL_VERSION = 1

PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)

UBIRCH_PROTOCOL_TYPE_BIN = 0x00
UBIRCH_PROTOCOL_TYPE_REG = 0x01
UBIRCH_PROTOCOL_TYPE_HSK = 0x02


class Protocol(object):
    _signatures: dict = {}

    def __init__(self, signatures: dict = None) -> None:
        """
        Initialize the protocol.
        :param signatures: previously known signatures
        """
        if signatures is None:
            signatures = {}
        self._signatures = signatures

    def set_saved_signatures(self, signatures: dict) -> None:
        """
        Set known signatures from devices we have talked to.
        :param signatures: the saved signatures as a dictionary (uuid -> bytes)
        """
        self._signatures = signatures

    def get_saved_signatures(self) -> dict:
        """
        Get the saved signatures to store them persistently.
        :return: a dictionary of signatures (uuid -> bytes)
        """
        return self._signatures

    @abstractmethod
    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        """
        Sign the request when finished.
        :param uuid: the uuid of the sender to identify the correct key pair
        :param message: the bytes to sign
        :return: the signature
        """
        raise NotImplementedError("signing not implemented")

    @abstractmethod
    def _verify(self, uuid: UUID, message: bytes, signature: bytes) -> bytes:
        """
        Verify the message. Throws exception if not verifiable.
        :param uuid: the uuid of the sender to identify the correct key pair
        :param message: the message bytes to verify
        :param signature: the signature to use for verification
        :return:
        """
        raise NotImplementedError("verification not implemented")

    def __serialize(self, msg: any) -> bytearray:
        return bytearray(msgpack.packb(msg))

    def __sign(self, uuid: UUID, msg: any) -> (bytes, bytes):
        # sign the message and store the signature
        serialized = self.__serialize(msg)[0:-1]
        sha515digest = hashlib.sha512(serialized).digest()
        signature = self._sign(uuid, sha515digest)
        # replace last element in array with the signature
        msg[-1] = signature
        return (signature, self.__serialize(msg))

    def message_signed(self, uuid: UUID, type: int, payload: any) -> bytes:
        """
        Create a new signed ubirch-protocol message.
        :param uuid: the uuid of the device that sends the message, part of the envelope
        :param type: a hint of the type of message sent (0-255)
        :param payload: the actual message payload
        :return: the encoded and signed message
        """
        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            SIGNED,
            uuid.bytes,
            type,
            payload,
            0
        ]

        (signature, serialized) = self.__sign(uuid, msg)
        self._signatures[uuid] = signature

        # serialize result and return the message
        return serialized

    def message_chained(self, uuid: UUID, type: int, payload: any) -> bytes:
        """
        Create a new chained ubirch-protocol message.
        Stores the context, the last signature, to be included in the next message.
        :param uuid: the uuid of the device that sends the message, part of the envelope
        :param type: a hint of the type of message sent (0-255)
        :param payload: the actual message payload
        :return: the encoded and signed message
        """

        # retrieve last known signature or null bytes
        last_signature: bytes = self._signatures.get(uuid, b'\0' * 64)

        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            CHAINED,
            uuid.bytes,
            last_signature,
            type,
            payload,
            0
        ]

        (signature, serialized) = self.__sign(uuid, msg)
        self._signatures[uuid] = signature

        # serialize result and return the message
        return serialized

    def message_verify(self, message: bytes) -> dict:
        """
        Verify the integrity of the message and decode the contents.
        Throws an exception if the message is not verifiable.
        :param message: the msgpack encoded message
        :return: the decoded message
        """
        if len(message) < 70:
            raise Exception("message format wrong (size < 70 bytes): {}".format(len(message)))
        unpacked = msgpack.unpackb(message)
        uuid = UUID(bytes=unpacked[1])
        if unpacked[0] == SIGNED:
            signature = unpacked[4]
        else:
            signature = unpacked[5]
        self._verify(uuid, message[0:-67], signature)
        return unpacked
