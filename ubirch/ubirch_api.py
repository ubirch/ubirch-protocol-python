##
# @file ubirch_api.py
# ubirch API
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
import base64
import binascii
import json
import logging
from logging import getLogger
from uuid import UUID

import requests
from requests import Response

logger = getLogger(__name__)

KEY_SERVICE = "key"
NIOMON_SERVICE = "niomon"
VERIFICATION_SERVICE = "verify"
DATA_SERVICE = "data"


class API(object):
    """! Ubirch API accessor methods"""

    def __init__(self, env="demo", debug=False) -> None:
        """!
        Initialize the API
        @param env Can be one of [prod, demo, dev]
        @param debug Print debug output?
        """
        super().__init__()
        self._auth = {}

        # enable intensive logging
        if debug and logger.level == logging.DEBUG:
            import http.client as http_client
            http_client.HTTPConnection.debuglevel = 1
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        self._services = {
            KEY_SERVICE: "https://key.{}.ubirch.com/api/keyService/v1/pubkey".format(env),
            NIOMON_SERVICE: "https://niomon.{}.ubirch.com/".format(env),
            VERIFICATION_SERVICE: "https://verify.{}.ubirch.com/api/upp".format(env),
            DATA_SERVICE: "https://data.{}.ubirch.com/v1".format(env)
        }

    def get_url(self, service: str) -> str or None:
        """!
        @param service Can be one of [prod, demo, dev]
        @return URL of this service
        """
        return self._services.get(service, None)

    def set_authentication(self, uuid: UUID, auth: str or None):
        """!
        @param uuid The UUID of the authentication to add
        @param auth The auth key / password of the ubirch 'thing'
        """
        if auth is not None:
            self._auth[uuid] = auth

    def _update_authentication(self, uuid: UUID, headers: dict) -> dict:
        if uuid in self._auth.keys():
            headers.update({
                'X-Ubirch-Hardware-Id': str(uuid),
                'X-Ubirch-Credential': base64.b64encode(self._auth[uuid].encode()).decode(),
                'X-Ubirch-Auth-Type': 'ubirch'
            })
        return headers

    def is_identity_registered(self, uuid: UUID) -> bool:
        """!
        Check if this identity is registered with the backend.
        @param uuid The UUID of the identity to check
        @return True If the identity exists
        """
        logger.debug("is identity registered?: {}".format(uuid))
        r = requests.get(self.get_url(KEY_SERVICE) + "/current/hardwareId/" + str(uuid))
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == requests.codes.ok and r.json()

    def register_identity(self, key_registration: bytes) -> Response:
        """!
        Register an identity with the backend.
        @param key_registration The key registration data
        @return The response from the server
        """
        if key_registration.startswith(b'{'):
            return self._register_identity_json(json.loads(bytes.decode(key_registration)))
        else:
            return self._register_identity_mpack(key_registration)

    def _register_identity_json(self, key_registration: dict) -> Response:
        logger.debug("register identity [json]: {}".format(key_registration))
        r = requests.post(self.get_url(KEY_SERVICE), json=key_registration)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _register_identity_mpack(self, key_registration: bytes) -> Response:
        logger.debug("register identity [msgpack]: {}".format(binascii.hexlify(key_registration)))
        headers = {'Content-Type': 'application/octet-stream'}
        r = requests.post(self.get_url(KEY_SERVICE) + '/mpack', data=key_registration, headers=headers)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def deregister_identity(self, key_deregistration: bytes) -> Response:
        """!
        De-register an identity at the backend. Deletes the public key.
        @param key_deregistration The public key signed
        @return The response from the server
        """
        if key_deregistration.startswith(b'{'):
            return self._deregister_identity_json(json.loads(bytes.decode(key_deregistration)))
        else:
            return self._deregister_identity_mpack(key_deregistration)

    def _deregister_identity_json(self, key_deregistration: dict) -> Response:
        logger.debug("de-register identity [json]: {}".format(key_deregistration))
        r = requests.delete(self.get_url(KEY_SERVICE), json=key_deregistration)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _deregister_identity_mpack(self, key_deregistration: bytes) -> Response:
        raise NotImplementedError("msgpack identity deregistration not supported yet")

    def trust_identity_json(self, signed_trust: dict) -> Response:
        """!
        Trust a new identity
        @return The response from the server
        """
        logger.debug("trust an identity [json]: {}".format(signed_trust))
        r = requests.post(self.get_url(KEY_SERVICE) + '/trust', json=signed_trust)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def get_trusted_identities_json(self, get_trusted: dict) -> Response:
        """!
        Get the trusted identities as a list in JSON format
        @return The response from the server
        """
        logger.debug("get trusted identities [json]: {}".format(get_trusted))
        r = requests.get(self.get_url(KEY_SERVICE) + '/trusted', json=get_trusted)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def send(self, uuid: UUID, data: bytes) -> Response:
        """!
        Send data to the ubirch authentication service (Niomon). Requires encoding before sending.
        @param uuid The sender's UUID
        @param data The msgpack or JSON encoded data to send
        @return The response from the server
        """
        if data.startswith(b'{'):
            return self._send_json(uuid, json.loads(bytes.decode(data)))
        else:
            return self._send_mpack(uuid, data)

    def _send_json(self, uuid: UUID, data: dict) -> Response:
        payload = str.encode(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(',', ':')))
        logger.debug("sending [json]: {}".format(payload))
        json_header = {
            'Content-Type': 'application/json'
        }
        r = requests.post(self.get_url(NIOMON_SERVICE),
                          headers=self._update_authentication(uuid, json_header),
                          data=payload)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_mpack(self, uuid: UUID, data: bytes) -> Response:
        logger.debug("sending [msgpack]: {}".format(binascii.hexlify(data)))
        r = requests.post(self.get_url(NIOMON_SERVICE),
                          headers=self._update_authentication(uuid, {}),
                          data=data)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def verify(self, data: bytes, quick=False) -> Response:
        """!
        Verify a given hash with the ubirch backend. Returns all available verification
        data.
        @param data The hash of the message to verify
        @param quick Only run quick check to verify that the hash has been stored in backend
        @return If the verification was successful and the data related to it
        """
        logger.debug("verifying hash: {}".format(base64.b64encode(data).decode()))
        url = self.get_url(VERIFICATION_SERVICE)
        if not quick:
            url = self.get_url(VERIFICATION_SERVICE) + '/verify'
        r = requests.post(url,
                          headers={'Accept': 'application/json', 'Content-Type': 'text/plain'},
                          data=base64.b64encode(data).decode().rstrip('\n'))
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def send_data(self, uuid: UUID, data: bytes) -> Response:
        """!
        Send data to the ubirch data service. Requires encoding before sending.
        @param uuid The sender's UUID
        @param data The msgpack or JSON encoded data to send
        @return The response from the server
        """
        if data.startswith(b'{'):
            return self._send_data_json(uuid, data)
        else:
            return self._send_data_mpack(uuid, data)

    def _send_data_json(self, uuid: UUID, data: bytes):
        logger.debug("sending data [json]: {}".format(data))
        json_header = {'Content-Type': 'application/json'}
        r = requests.post(self.get_url(DATA_SERVICE) + '/json',
                          headers=self._update_authentication(uuid, json_header),
                          data=data)
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_data_mpack(self, uuid: UUID, data: bytes) -> Response:
        logger.debug("sending data [msgpack]: {}".format(binascii.hexlify(data)))
        r = requests.post(self.get_url(DATA_SERVICE) + '/msgPack',
                          headers=self._update_authentication(uuid, {}),
                          data=binascii.hexlify(data))
        logger.debug("{}: {}".format(r.status_code, r.content))
        return r
