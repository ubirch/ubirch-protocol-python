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
UBIRCH_PROTOCOL_VERSION = 2

PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)

UBIRCH_PROTOCOL_TYPE_BIN = 0x00
UBIRCH_PROTOCOL_TYPE_REG = 0x01
UBIRCH_PROTOCOL_TYPE_HSK = 0x02


class Protocol(object):
    _signatures = {}

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

    def reset_signature(self, uuid: UUID) -> None:
        """
        Reset the last saved signature for this UUID.
        :param uuid: the UUID to reset
        """
        if uuid in self._signatures:
            del self._signatures[uuid]

    def _hash(self, message: bytes) -> bytes:
        """
        Hash the message before signing. Override this method if
        a different hash algorithm is used. Default is SHA512.
        :param message: the message bytes
        :return: the digest in bytes
        """
        return hashlib.sha512(message).digest()

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
    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        """
        Verify the message. Throws exception if not verifiable.
        :param uuid: the uuid of the sender to identify the correct key pair
        :param message: the message bytes to verify
        :param signature: the signature to use for verification
        :return:
        """
        raise NotImplementedError("verification not implemented")

    def _serialize(self, msg: any) -> bytearray:
        return bytearray(msgpack.packb(msg, use_bin_type=True))

    def _prepare_and_sign(self, uuid: UUID, msg: any) -> (bytes, bytes):
        """
        Sign the request when finished. The message is first prepared by serializing and hashing it.
        :param uuid: the uuid of the sender to identify the correct key pair
        :param msg: the bytes to sign
        :return: the signature
        """
        # sign the message and store the signature
        serialized = self._serialize(msg)[0:-1]
        signature = self._sign(uuid, self._hash(serialized))
        # replace last element in array with the signature
        msg[-1] = signature
        return signature, self._serialize(msg)

    def message_signed(self, uuid: UUID, type: int, payload: any, save_signature: bool = False) -> bytes:
        """
        Create a new signed ubirch-protocol message.
        :param uuid: the uuid of the device that sends the message, part of the envelope
        :param type: a hint of the type of message sent (0-255)
        :param payload: the actual message payload
        :param save_signature: save the signature of the created message so the next chained message contains it
        :return: the encoded and signed message
        """
        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            SIGNED,
            uuid.bytes,
            type & 0xffffffff,
            payload,
            0
        ]

        (signature, serialized) = self._prepare_and_sign(uuid, msg)
        if save_signature:
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
        last_signature = self._signatures.get(uuid, b'\0' * 64)

        # we need to ensure we get a 16bit integer serialized (0xFF | version)
        # the 0xFF is replaced by 0x00 in the serialized code
        msg = [
            CHAINED,
            uuid.bytes,
            last_signature,
            type & 0xffffffff,
            payload,
            0
        ]

        (signature, serialized) = self._prepare_and_sign(uuid, msg)
        self._signatures[uuid] = signature

        # serialize result and return the message
        return serialized

    def _prepare_and_verify(self, uuid: UUID, message: bytes, signature: bytes) -> bytes:
        """
        Verify the message. Throws exception if not verifiable. The message is first prepared by hashing it.
        :param uuid: the uuid of the sender to identify the correct key pair
        :param message: the message bytes to verify
        :param signature: the signature to use for verification
        :return:
        """
        return self._verify(uuid, self._hash(message), signature)

    def message_verify(self, message: bytes) -> list:
        """
        Verify the integrity of the message and decode the contents.
        Throws an exception if the message is not verifiable.
        :param message: the msgpack encoded message
        :return: the decoded message
        """
        if len(message) < 70:
            raise Exception("message format wrong (size < 70 bytes): {}".format(len(message)))

        if message[1] >> 4 == 2:  # version 2
            unpacker = msgpack.Unpacker(raw=False)
        elif message[1] >> 4 == 1:  # version 1 (legacy)
            unpacker = msgpack.Unpacker(raw=True)
        elif message[1] == 0xcd and message[3] >> 4 == 1:  # version 1 trackle (legacy)
            unpacker = msgpack.Unpacker(raw=True, strict_map_key=False)
        else:
            raise Exception("invalid input")

        unpacker.feed(message)

        unpacked = []
        # unpack all entries, except the last one, remember the byte index for signature verification
        for n in range(0, unpacker.read_array_header() - 1):
            unpacked.append(unpacker.unpack())
        signatureIndex = unpacker.tell()
        unpacked.append(unpacker.unpack())

        # verify the message using extracted values
        self._prepare_and_verify(UUID(bytes=unpacked[1]), message[0:signatureIndex], unpacked[-1])
        return unpacked
