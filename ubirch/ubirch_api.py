# ubirch API
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
import http.client as http_client

log = getLogger(__name__)


class API(object):
    """ubirch API accessor methods."""

    def __init__(self, auth=None, env=None, debug=False) -> None:
        super().__init__()

        # enable intensive logging
        if debug and log.level == logging.DEBUG:
            http_client.HTTPConnection.debuglevel = 1
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        if auth is not None:
            self._auth = {'Authorization': auth}
        else:
            self._auth = {}

        if env is None:
            self.KEY_SERVICE = "http://localhost:8095/api/keyService/v1".format(env)
            self.AVATAR_SERVICE = "http://localhost:8080/api/avatarService/v1".format(env)
            self.CHAIN_SERVICE = "http://localhost:8097/api/v1/chainService".format(env)
            self.NOTARY_SERVICE = "https://localhost:8098/api/v1/notaryService".format(env)
        else:
            self.KEY_SERVICE = "https://key.{}.ubirch.com/api/keyService/v1".format(env)
            self.AVATAR_SERVICE = "https://api.ubirch.{}.ubirch.com/api/avatarService/v1".format(env)
            self.CHAIN_SERVICE = "https://api.ubirch.{}.ubirch.com/api/v1/chainService".format(env)
            self.NOTARY_SERVICE = "http://n.dev.ubirch.com:8080/v1/notaryService".format(env)

    def is_identity_registered(self, uuid: UUID) -> bool:
        """Check if this identity is registered with the backend."""
        log.info("is identity registered?: {}".format(uuid))
        r = requests.get(self.KEY_SERVICE + "/pubkey/current/hardwareId/" + str(uuid),
                         headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == 200 and r.json()

    def register_identity(self, key_registration: bytes) -> Response:
        if key_registration.startswith(b'{'):
            log.debug(key_registration)
            return self._register_identity_json(json.loads(bytes.decode(key_registration)))
        else:
            return self._register_identity_mpack(key_registration)

    def _register_identity_json(self, key_registration: dict) -> Response:
        log.info("register device identity [json]: {}".format(key_registration))
        r = requests.post(self.KEY_SERVICE + '/pubkey', json=key_registration,
                          headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _register_identity_mpack(self, key_registration: bytes) -> Response:
        log.info("register device identity [msgpack]: {}".format(binascii.hexlify(key_registration)))
        r = requests.post(self.KEY_SERVICE + '/pubkey/mpack', data=key_registration,
                          headers={'Content-Type': 'application/octet-stream', **self._auth})
        log.debug("{}: {}".format(r.status_code, r.content))
        return r

    def device_exists(self, uuid: UUID) -> bool:
        log.info("device exists?: {}".format(uuid))
        r = requests.get(self.AVATAR_SERVICE + '/device/' + str(uuid),
                         headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == 200

    def device_delete(self, uuid: UUID) -> bool:
        log.info("delete device: {}".format(uuid))
        r = requests.delete(self.AVATAR_SERVICE + '/device/' + str(uuid), headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r.status_code == 200

    def device_create(self, device_info: dict) -> Response:
        log.info("create device: {}".format(device_info))
        r = requests.post(self.AVATAR_SERVICE + '/device',
                          json=device_info,
                          headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r

    def send(self, data: bytes) -> Response:
        if data.startswith(b'{'):
            return self._send_json(json.loads(bytes.decode(data)))
        else:
            return self._send_mpack(data)

    def anchor(self, data: bytes) -> Response:
        if data.startswith(b'{'):
            raise Exception("unsupported data type: json")

        r = requests.post(self.NOTARY_SERVICE + '/notarize',
                          json={"data": bytes.decode(binascii.hexlify(data[-64:])), "dataIsHash": True},
                          headers=self._auth)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_json(self, data: dict) -> Response:
        payload = str.encode(json.dumps(data, sort_keys=True, separators=(',', ':')))
        log.debug(json)
        r = requests.post(self.AVATAR_SERVICE + '/device/update',
                          headers={'Content-Type': 'application/json'},
                          data=payload)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r

    def _send_mpack(self, data: bytes) -> Response:
        log.debug(data)
        r = requests.post(self.AVATAR_SERVICE + '/device/update/mpack', data=data)
        log.debug("{}: {}".format(r.status_code, r.content))
        return r
