##
# @file ubirch_protocol.py
# ubirch protocol
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
import logging
from abc import abstractmethod
from uuid import UUID

import msgpack
from ecdsa.keys import BadSignatureError as BadSignatureErrorEcdsa
from ed25519 import BadSignatureError

logger = logging.getLogger(__name__)

# ubirch-protocol constants
UBIRCH_PROTOCOL_VERSION = 2

PLAIN = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x01)
SIGNED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x02)
CHAINED = ((UBIRCH_PROTOCOL_VERSION << 4) | 0x03)

UBIRCH_PROTOCOL_TYPE_BIN = 0x00
UBIRCH_PROTOCOL_TYPE_REG = 0x01
UBIRCH_PROTOCOL_TYPE_HSK = 0x02

# for use with the "get_unpacked_index" function
UNPACKED_UPP_FIELD_VERSION  = 0
UNPACKED_UPP_FIELD_UUID     = 1
UNPACKED_UPP_FIELD_PREV_SIG = 2
UNPACKED_UPP_FIELD_TYPE     = 3
UNPACKED_UPP_FIELD_PAYLOAD  = 4
UNPACKED_UPP_FIELD_SIG      = 5

# lookup tables for fields in unpacked upps (used by the "get_unpacked_index" function)

# message without any signatures
#    0    |   1  |   2  |    3
# --------|------|------|--------
# VERSION | UUID | TYPE | PAYLOAD
UNPACKED_UNSIGNED_UPP_INDEX_TABLE = [-1, -1, -1, -1, -1, -1]
UNPACKED_UNSIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_VERSION] = 0
UNPACKED_UNSIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_UUID]    = 1
UNPACKED_UNSIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_TYPE]    = 2
UNPACKED_UNSIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_PAYLOAD] = 3

# message without the previous signature, contains a message signature
#    0    |   1  |   2  |    3    |     4
# --------|------|------|---------|-----------
# VERSION | UUID | TYPE | PAYLOAD | SIGNATURE
UNPACKED_SIGNED_UPP_INDEX_TABLE = [-1, -1, -1, -1, -1, -1]
UNPACKED_SIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_VERSION] = 0
UNPACKED_SIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_UUID]    = 1
UNPACKED_SIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_TYPE]    = 2
UNPACKED_SIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_PAYLOAD] = 3
UNPACKED_SIGNED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_SIG]     = 4

# message with all signatures
#    0    |   1  |        2       |   3  |    4    |     5
# --------|------|----------------|------|---------|----------
# VERSION | UUID | PREV-SIGNATURE | TYPE | PAYLOAD | SIGNATURE
UNPACKED_CHAINED_UPP_INDEX_TABLE = [-1, -1, -1, -1, -1, -1]
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_VERSION]  = 0
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_UUID]     = 1
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_PREV_SIG] = 2
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_TYPE]     = 3
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_PAYLOAD]  = 4
UNPACKED_CHAINED_UPP_INDEX_TABLE[UNPACKED_UPP_FIELD_SIG]      = 5


class Protocol(object):
    """! Ubirch Protocol: handle signatures and UPP's and create message objects """
    _signatures = {}

    def __init__(self, signatures: dict = None) -> None:
        """!
        Initialize the protocol.
        @param signatures Previously known signatures
        """
        if signatures is None:
            signatures = {}
        self._signatures = signatures

    def set_saved_signatures(self, signatures: dict) -> None:
        """!
        Set known signatures from devices we have talked to.
        @param signatures The saved signatures as a dictionary (uuid -> bytes)
        """
        self._signatures = signatures

    def get_saved_signatures(self) -> dict:
        """!
        Get the saved signatures to store them persistently.
        @return A dictionary of signatures (uuid -> bytes)
        """
        return self._signatures

    def reset_signature(self, uuid: UUID) -> None:
        """!
        Reset the last saved signature for this UUID.
        @param uuid The UUID to reset
        """
        if uuid in self._signatures:
            del self._signatures[uuid]

    def _hash(self, message: bytes) -> bytes:
        """!
        Hash the message before signing. Override this method if
        a different hash algorithm is used. Default is SHA512.
        @param message The message bytes
        @return The digest in bytes
        """
        return hashlib.sha512(message).digest()

    @abstractmethod
    def _sign(self, uuid: UUID, message: bytes) -> bytes:
        """!
        Sign the request when finished.
        IMPORTANT: This function needs to be implemented with the Keystore of choice and its .find_signing_key() and .sign() functions

        This function also takes care of the hashing, before signing, depending on the key type.
        @param uuid The uuid of the sender to identify the correct key pair
        @param message The bytes to sign
        @return NotImplementedError
        """
        raise NotImplementedError("signing not implemented")

    @abstractmethod
    def _verify(self, uuid: UUID, message: bytes, signature: bytes):
        """!
        Verify the message.
        IMPORTANT: This function needs to be implemented with the Keystore of choice and its .find_verifying_key() and .verify() functions

        Throws exception if not verifiable.
        This function also takes care of the hashing, before verifying, depending on the key type.
        @param uuid The uuid of the sender to identify the correct key pair
        @param message The message bytes to verify
        @param signature The signature to use for verification
        @return NotImplementedError
        """
        raise NotImplementedError("verification not implemented")

    def _serialize(self, msg: any) -> bytearray:
        """! @internal
        Serialize to Bytearray
        @param msg The message to serialize
        @return Message packed as msgpack bytearray
        """
        return bytearray(msgpack.packb(msg, use_bin_type=True))

    def _prepare_and_sign(self, uuid: UUID, msg: any) -> (bytes, bytes):
        """! @internal
        Sign the request when finished. The message is first prepared by serializing and hashing it.
        @param uuid The uuid of the sender to identify the correct key pair
        @param msg The bytes to sign
        @return The signature
        """
        # sign the message and store the signature
        serialized = self._serialize(msg)[0:-1]
        signature = self._sign(uuid, serialized)
        # replace last element in array with the signature
        msg[-1] = signature
        return signature, self._serialize(msg)

    def message_signed(self, uuid: UUID, type: int, payload: any, save_signature: bool = False) -> bytes:
        """!
        Create a new signed ubirch-protocol message.
        @param uuid The uuid of the device that sends the message, part of the envelope
        @param type A hint of the type of message sent (0-255)
        @param payload The actual message payload
        @param save_signature Save the signature of the created message so the next chained message contains it
        @return The encoded and signed message
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
        """!
        Create a new chained ubirch-protocol message.
        Stores the context, the last signature, to be included in the next message.
        @param uuid The uuid of the device that sends the message, part of the envelope
        @param type A hint of the type of message sent (0-255)
        @param payload The actual message payload
        @return The encoded and signed message
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

    def unpack_upp(self, msgpackUPP: bytes) -> list:
        """!
        Unpack a UPP (msgpack)
        Throws an exception if the UPP can't be unpacked
        Returns The unpacked upp as a list
        @param msgpackUPP The msgpack encoded message
        @return The unpacked message
        """
        # check for the UPP version
        if msgpackUPP[1] >> 4 == 2:  # version 2
            legacy = False
        elif msgpackUPP[1] >> 4 == 1:  # version 1 (legacy)
            legacy = True
        else:
            raise ValueError("Invalid UPP version byte: 0x%02x" % msgpackUPP[1])

        # unpack the msgpack
        return msgpack.unpackb(msgpackUPP, raw=legacy)

    def get_unpacked_index(self, versionByte: int, targetField: int) -> int:
        """!
        Get the index of a given target field for a UPP with the given version byte
        Throws a ValueError if the version byte (lower four bits) is invalid
        @param versionByte The first byte of an unpacked upp (first element of the list)
        @param targetField One off "UNPACKED_UPP_*"
        @return The index of the field on success
        """
        # check the lower four bits of the version byte
        lowerFour = versionByte & 0x0f

        if lowerFour == 0x01:
            return UNPACKED_UNSIGNED_UPP_INDEX_TABLE[targetField]
        elif lowerFour == 0x02:
            return UNPACKED_SIGNED_UPP_INDEX_TABLE[targetField]
        elif lowerFour == 0x03:
            return UNPACKED_CHAINED_UPP_INDEX_TABLE[targetField]
        else:
            # unknown lower four bits; error
            raise ValueError("Invalid lower four bits of the UPP version byte: %s" % bin(lowerFour))

    def upp_msgpack_split_signature(self, msgpackUPP) -> (bytes, bytes):
        """!
        Separate the signature from the msgpack
        @param msgpackUPP The msgpack encoded upp
        @return A tuple consisting of the message without the signature and the signature
        """
        try:
            if msgpackUPP[1] >> 4 == 2:
                # version 2 upp - 2 byte signature header
                return (msgpackUPP[:-66], msgpackUPP[-64:])
            elif msgpackUPP[1] >> 4 == 1:
                # version 1 upp - 3 byte signature header
                return (msgpackUPP[:-67], msgpackUPP[-64:])
            else:
                raise ValueError("Invalid UPP version byte: %02x" % msgpack[1])
        except IndexError:
            raise ValueError("The UPP-msgpack is too short: %d bytes" % len(msgpackUPP))

    def verfiy_signature(self, uuid: UUID, msgpackUPP: bytes) -> bool:
        """!
        Verify the integrity of the message and decode the contents
        Raises an value error when the message is too short
        @param uuid The uuid of the sender of the message
        @param msgpackUPP The msgpack encoded message
        @return The decoded message
        """
        # separate the message from the signature
        msg, sig = self.upp_msgpack_split_signature(msgpackUPP)

        # verify the message
        try:
            self._verify(uuid, msg, sig)
        except (BadSignatureError, BadSignatureErrorEcdsa):
            return False

        return True
