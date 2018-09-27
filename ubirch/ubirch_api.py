# ubirch API
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

import binascii
import json
import logging
from logging import getLogger
from uuid import UUID

import requests
from requests import Response

logger = getLogger(__name__)

KEY_SERVICE = "key"
AVATAR_SERVICE = "avatar"
CHAIN_SERVICE = "chain"
NOTARY_SERVICE = "notary"


class API(object):
    """ubirch API accessor methods."""

    def __init__(self, auth=None, env=None, debug=False) -> None:
        super().__init__()

        # enable intensive logging
        if debug and logger.level == logging.DEBUG:
            import http.client as http_client
            http_client.HTTPConnection.debuglevel = 1
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        if auth is not None:
            self._auth = {'Authorization': auth}
        else:
            self._auth = {}

        if env is None:
            self._services = {
                KEY_SERVICE: "http://localhost:8095/api/keyService/v1",
                AVATAR_SERVICE: "http://localhost:8080/api/avatarService/v1",
                CHAIN_SERVICE: "http://localhost:8097/api/v1/chainService",
                NOTARY_SERVICE: "https://localhost:8098/api/v1/notaryService"
            }
        else:
            self._services = {
                KEY_SERVICE: "https://key.{}.ubirch.com/api/keyService/v1".format(env),
                AVATAR_SERVICE: "https://api.ubirch.{}.ubirch.com/api/avatarService/v1".format(env),
                CHAIN_SERVICE: "https://api.ubirch.{}.ubirch.com/api/v1/chainService".format(env),
                NOTARY_SERVICE: "http://n.dev.ubirch.com:8080/v1/notaryService".format(env)
            }

    def get_url(self, service: str) -> str or None:
        return self._services.get(service, None)

    def is_identity_registered(self, uuid: UUID) -> bool:
        """
        Check if this identity is registered with the backend.
        :param uuid: the UUID of the identity to check
        :return: true if the identity exists
        """
        logger.debug("is identity registered?: {}".format(uuid))
        r = requests.get(self.get_url(KEY_SERVICE) + "/pubkey/current/hardwareId/" + str(uuid),
                         headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == requests.codes.ok and r.json()

    def register_identity(self, key_registration: bytes) -> Response:
        """
        Register an identity with the backend.
        :param key_registration: the key registration data
        :return: the response from the server
        """
        if key_registration.startswith(b'{'):
            return self._register_identity_json(json.loads(bytes.decode(key_registration)))
        else:
            return self._register_identity_mpack(key_registration)

    def deregister_identity(self, key_deregistration: bytes) -> Response:
        """
        De-register an identity at the backend. Deletes the public key.
        :param key_deregistration: the public key signed
        :return: the response from the server
        """
        if key_deregistration.startswith(b'{'):
            return self._deregister_identity_json(json.loads(bytes.decode(key_deregistration)))
        else:
            return self._deregister_identity_mpack(key_deregistration)

    def _register_identity_json(self, key_registration: dict) -> Response:
        logger.debug("register identity [json]: {}".format(key_registration))
        r = requests.post(self.get_url(KEY_SERVICE) + '/pubkey', json=key_registration,
                          headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _register_identity_mpack(self, key_registration: bytes) -> Response:
        logger.debug("register identity [msgpack]: {}".format(binascii.hexlify(key_registration)))
        headers = {'Content-Type': 'application/octet-stream'}
        headers.update(self._auth)
        r = requests.post(self.get_url(KEY_SERVICE) + '/pubkey/mpack', data=key_registration, headers=headers)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def trust_identity_json(self, signed_trust: dict) -> Response:
        logger.debug("trust an identity [json]: {}".format(signed_trust))
        r = requests.post(self.get_url(KEY_SERVICE) + '/pubkey/trust', json=signed_trust)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def get_trusted_identities_json(self, get_trusted: dict) -> Response:
        logger.debug("get trusted identities [json]: {}".format(get_trusted))
        r = requests.get(self.get_url(KEY_SERVICE) + '/pubkey/trusted', json=get_trusted)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _deregister_identity_json(self, key_deregistration: dict) -> Response:
        logger.debug("de-register identity [json]: {}".format(key_deregistration))
        r = requests.delete(self.get_url(KEY_SERVICE) + '/pubkey', json=key_deregistration,
                            headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r
        pass

    def _deregister_identity_mpack(self, key_deregistration: bytes) -> Response:
        raise NotImplementedError("msgpack identity deregistration not supported yet")

    def device_exists(self, uuid: UUID) -> bool:
        """
        Check if a device exists.
        :param uuid: the UUID of the device
        :return: true of it exists
        """
        logger.debug("device exists?: {}".format(uuid))
        r = requests.get(self.get_url(AVATAR_SERVICE) + '/device/' + str(uuid),
                         headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == requests.codes.ok

    def device_delete(self, uuid: UUID) -> bool:
        """
        Delete a device
        :param uuid: the UUID of the device
        :return: true of the deletion succeeded
        """
        logger.debug("delete device: {}".format(uuid))
        r = requests.delete(self.get_url(AVATAR_SERVICE) + '/device/' + str(uuid), headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == requests.codes.ok

    def device_create(self, device_info: dict) -> Response:
        """
        Create a new device in the server using the device info provided.
        :param device_info: a device descriptor
        :return: the response from the server
        """
        logger.debug("create device: {}".format(device_info))
        r = requests.post(self.get_url(AVATAR_SERVICE) + '/device',
                          json=device_info,
                          headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def send(self, data: bytes) -> Response:
        """
        Send data to the backend. Requires encoding before sending.
        :param data: the msgpack or JSON encoded data to send
        :return: the response from the server
        """
        if data.startswith(b'{'):
            return self._send_json(json.loads(bytes.decode(data)))
        else:
            return self._send_mpack(data)

    def anchor(self, data: bytes) -> Response:
        """
        Anchor some data in the blockchain service.
        :param data: the data to anchor
        :return: the response from the server
        """
        r = requests.post(self.get_url(NOTARY_SERVICE) + '/notarize',
                          json={"data": bytes.decode(binascii.hexlify(data[-64:])), "dataIsHash": True},
                          headers=self._auth)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_json(self, data: dict) -> Response:
        payload = str.encode(json.dumps(data, sort_keys=True, separators=(',', ':')))
        logger.debug(json)
        r = requests.post(self.get_url(AVATAR_SERVICE) + '/device/update',
                          headers={'Content-Type': 'application/json'},
                          data=payload)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_mpack(self, data: bytes) -> Response:
        logger.debug(data)
        r = requests.post(self.get_url(AVATAR_SERVICE) + '/device/update/mpack', data=data)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r
